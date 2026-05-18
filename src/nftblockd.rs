use clap::Parser;
use log::{error, info, warn};
use nftblockd::error::AppError;
use nftblockd::grpc::ctl::nftblockd::status_service_server::StatusServiceServer;
use nftblockd::grpc::server::{Command, ServiceStatusStruct};
use nftblockd::nftables::config::NftConfig;
use nftblockd::set::blocklist::BlockList;
use nftblockd::utils::stats::Stats;
use nftblockd::utils::status::NftblockdStatus;
use rand::RngExt;
use std::env;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tonic::codegen::tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Group of URLs provided for IPv4 and IPv6 blocklist fetching.
/// These URLs can be passed via CLI arguments or environment variables.
#[derive(Debug, clap::Args)]
#[group(multiple = true)]
pub struct UrlGroup {
    /// Endpoint for retrieving the IPv4 blocklist
    #[clap(short = '4', long, value_name = "IPv4_URL", env = "NFTBLOCKD_IPV4_URL")]
    url4: Option<String>,

    /// Endpoint for retrieving the IPv6 blocklist
    #[clap(short = '6', long, value_name = "IPv6_URL", env = "NFTBLOCKD_IPV6_URL")]
    url6: Option<String>,
}

/// CLI interface for the `nftblockd` binary.
/// Handles argument parsing for runtime behavior configuration.
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(flatten)]
    url: UrlGroup,

    /// Interval (in seconds) to periodically update the blocklists.
    #[clap(
        short,
        long,
        value_name = "INTERVAL",
        default_value = "30",
        env = "NFTBLOCKD_INTERVAL"
    )]
    interval: u64,

    /// Optional `.env` file path for loading environment variables.
    #[clap(short, long, value_name = "ENV_FILE")]
    env_file: Option<String>,

    /// Deletes the existing `nftables` blocklist table and then exits.
    /// This is used for cleanup.
    #[arg(short = 'd', long = "delete", action = clap::ArgAction::SetTrue)]
    delete: bool,
}

struct SocketGuard {
    path: String,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Entry point of the `nftblockd` binary.
/// Parses CLI arguments, initializes logging, loads the configuration (from `.env` and CLI),
/// and periodically updates the blocklists based on the configured interval.
#[tokio::main]
async fn main() -> Result<(), AppError> {
    // Parse CLI arguments.
    let mut cli = Cli::parse();

    // Load environment variables from the specified `.env` file (if provided), then re-parse CLI.
    if let Some(env_file) = cli.env_file {
        dotenvy::from_filename(env_file).expect("failed to load .env file");
        cli = Cli::parse();
    }

    let env = EnvFilter::try_from_env("NFTBLOCKD_LOG_LEVEL").unwrap_or(EnvFilter::new("info"));
    let timer = tracing_subscriber::fmt::time::LocalTime::rfc_3339();
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(env)
        .init();

    let blocklist_split_string = env::var("NFTBLOCKD_BLOCKLIST_SPLIT_STRING")
        .ok()
        .filter(|s| !s.is_empty());

    let mut config = NftConfig::new(blocklist_split_string.as_deref())?;
    if cli.delete {
        flush_table(&config);
        return Ok(());
    }

    // Check that at least one URL (IPv4 or IPv6) is specified; otherwise, exit early.
    if cli.url.url4.is_none() && cli.url.url6.is_none() {
        warn!("no blocklist url provided");
    }

    let mut channel = tokio::sync::mpsc::channel::<Command>(100);

    let status = Arc::new(ServiceStatusStruct {
        status: Arc::new(RwLock::new(NftblockdStatus::default())),
        stats: Arc::new(RwLock::new(Stats::default())),
        command_channel: channel.0.clone(),
    });

    let status_clone = status.clone();

    let socket = bind_socket("/run/nftblockd.sock").await?;
    let _guard = SocketGuard {
        path: "/run/nftblockd.sock".into(),
    };
    tokio::spawn(async move {
        if let Err(e) = Server::builder()
            .add_service(StatusServiceServer::from_arc(status_clone))
            .serve_with_incoming(socket)
            .await
        {
            error!("Error creating server: {e}");
        }
    });

    info!("initialized");

    let mut cancellation_token = CancellationToken::new();
    config = spawn_blocklist_loop(
        &cli,
        status.clone(),
        cancellation_token.clone(),
        blocklist_split_string.as_deref(),
    )?;

    loop {
        tokio::select! {
            cmd = channel.1.recv() => {
            match cmd {
                Some(Command::Flush { respond_to }) => {
                    cancellation_token.cancel();
                    flush_table(&config);
                    respond_to.send(Ok(())).map_err(|_| AppError::NftblockdError("failed to send response to a gRPC client".to_string()))?;
                }
                Some(Command::Reload { respond_to }) => {
                    cancellation_token.cancel();
                    cancellation_token = CancellationToken::new();
                    match spawn_blocklist_loop(&cli, status.clone(), cancellation_token.clone(), blocklist_split_string.as_deref()) {
                        Ok(_) => respond_to.send(Ok(())).map_err(|_| AppError::NftblockdError("failed to send response to a gRPC client".to_string()))?,
                        Err(e) => respond_to.send(Err(e)).map_err(|_| AppError::NftblockdError("failed to send response to a gRPC client".to_string()))?,
                    }
                }
            _ => {}}
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received shutdown signal");
                return Ok(());
            },
        }
    }
}

fn spawn_blocklist_loop<'a>(
    cli: &Cli,
    status: Arc<ServiceStatusStruct>,
    cancellation_token: CancellationToken,
    blocklist_split_string: Option<&str>,
) -> Result<NftConfig<'a>, AppError> {
    let retry_interval = env::var("NFTBLOCKD_RETRY_INTERVAL")
        .unwrap_or("2".to_string())
        .parse::<u64>()?;

    let retry_count = env::var("NFTBLOCKD_RETRY_COUNT")
        .unwrap_or("10".to_string())
        .parse::<u64>()?;
    let blocklist = BlockList::new(
        cli.url.url4.clone(),
        cli.url.url6.clone(),
        blocklist_split_string,
    )?;
    let refresh_interval = cli.interval;
    let config = NftConfig::new(blocklist_split_string)?;
    let config_local = config.clone();
    tokio::spawn(async move {
        blocklist_loop(
            status,
            blocklist,
            config_local,
            refresh_interval,
            retry_count,
            retry_interval,
            cancellation_token,
        )
        .await;
    });
    Ok(config)
}

async fn blocklist_loop(
    status: Arc<ServiceStatusStruct>,
    blocklist: BlockList,
    config: NftConfig<'_>,
    refresh_interval: u64,
    retry_count: u64,
    retry_interval: u64,
    cancellation_token: CancellationToken,
) {
    let mut counter = 1;
    loop {
        info!("starting updating nftables blocklist");
        match blocklist.update(&config, status.clone()).await {
            Ok(()) => {
                info!("finished updating nftables blocklist");
                *status.status.write().await = NftblockdStatus::Ok;
                counter = 1;
            }
            Err(e) => {
                error!("{e}");
                if !matches!(*status.status.read().await, NftblockdStatus::Failed(_)) {
                    *status.status.write().await = NftblockdStatus::PreFail(e.clone());
                }

                let ms = retry_interval * 1000;
                let sleep_interval = rand::rng().random_range(ms / 2..ms * 2);
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_millis(sleep_interval)) => {}
                    () = cancellation_token.cancelled() => {
                        info!("stopping blocklist retry loop");
                        return;
                    }
                }
                warn!(
                    "paused for {sleep_interval} ms; retrying; attempt {counter} out of {retry_count}"
                );
                if counter >= retry_count {
                    let err = AppError::NftblockdError(format!(
                        "failed to update nftables blocklist after {retry_count} retries; reason: {e}; FLUSHING TABLE!"
                    ));
                    error!("{err}");
                    *status.status.write().await = NftblockdStatus::Failed(err);
                    counter = 1;
                    flush_table(&config);
                }
                counter += 1;
                continue;
            }
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(refresh_interval)) => {}
            () = cancellation_token.cancelled() => {
                info!("stopping blocklist loop");
                return;
            }
        }
    }
}

async fn bind_socket(path: &str) -> Result<UnixListenerStream, AppError> {
    if Path::new(path).exists() {
        if UnixStream::connect(path).await.is_ok() {
            return Err(AppError::NftblockdError(
                "nftblockd is already running".into(),
            ));
        }
        info!("Removing stale socket: {path}");
        std::fs::remove_file(path)?;
    }

    let uds = UnixListener::bind(path)?;

    Ok(UnixListenerStream::new(uds))
}

fn flush_table(config: &NftConfig<'_>) {
    let _ = config.delete_table_and_apply().map_err(|e| {
        warn!(
            "the `{}` table (probably) already deleted: {}",
            config.table_name, e
        );
    });
}
