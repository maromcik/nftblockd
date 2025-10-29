use clap::Parser;
use log::{error, info, warn};
use nftblockd::nftables::config::NftConfig;
use nftblockd::set::blocklist::BlockList;
use rand::Rng;
use std::env;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

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

/// Entry point of the `nftblockd` binary.
/// Parses CLI arguments, initializes logging, loads the configuration (from `.env` and CLI),
/// and periodically updates the blocklists based on the configured interval.
fn main() {
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

    let request_headers = env::var("NFTBLOCKD_REQUEST_HEADERS")
        .ok()
        .filter(|s| !s.is_empty());

    let request_timeout = env::var("NFTBLOCKD_REQUEST_TIMEOUT")
        .unwrap_or("10".to_string())
        .parse::<u64>()
        .unwrap_or_else(|e| {
            error!("{e}");
            exit(1);
        });

    let retry_interval = env::var("NFTBLOCKD_RETRY_INTERVAL")
        .unwrap_or("1".to_string())
        .parse::<u64>()
        .unwrap_or_else(|e| {
            error!("{e}");
            exit(1);
        });

    let retry_count = env::var("NFTBLOCKD_RETRY_COUNT")
        .unwrap_or("5".to_string())
        .parse::<u64>()
        .unwrap_or_else(|e| {
            error!("{e}");
            exit(1);
        });

    // Initialize the `nftables` configuration.
    let config = NftConfig::new(blocklist_split_string.as_deref()).unwrap_or_else(|e| {
        error!("{e}");
        exit(1);
    });

    // If the delete flag is set, clean up the blocklist table and exit.
    if cli.delete {
        let _ = config.delete_table_and_apply().map_err(|e| {
            warn!(
                "the `{}` table (probably) already deleted: {}",
                config.table_name, e
            );
        });
        return;
    }

    // Check that at least one URL (IPv4 or IPv6) is specified; otherwise, exit early.
    if cli.url.url4.is_none() && cli.url.url6.is_none() {
        warn!("no url provided");
        return;
    }

    let blocklist = BlockList::new(
        request_headers,
        request_timeout,
        cli.url.url4,
        cli.url.url6,
        blocklist_split_string.as_deref(),
    )
    .unwrap_or_else(|e| {
        error!("{e}");
        exit(1);
    });

    info!("initialized");
    // Main update loop: Periodically fetch, validate, and apply blocklists.
    let mut counter = 1;
    loop {
        info!("starting updating nftables blocklist");
        match blocklist.update(&config) {
            Ok(()) => {
                info!("finished updating nftables blocklist");
                counter = 1;
            }
            Err(e) => {
                error!("{e}");
                let ms = retry_interval * 1000;
                let sleep_interval = rand::rng().random_range(ms / 2..ms * 2);
                sleep(Duration::from_millis(sleep_interval));
                warn!(
                    "paused for {sleep_interval} ms; retrying; attempt {counter} out of {retry_count}"
                );
                if counter >= retry_count {
                    error!("failed to update nftables blocklist after {retry_count} retries");
                    exit(3);
                }
                counter += 1;
                continue;
            }
        }

        sleep(Duration::from_secs(cli.interval));
    }
}
