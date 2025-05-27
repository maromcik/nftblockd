use clap::Parser;
use env_logger::Env;
use log::{error, info, warn};
use nftblockd::blocklist::{update_ipv4, update_ipv6};
use nftblockd::error::AppError;
use nftblockd::nftables::NftConfig;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;

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

/// Updates the IPv4 and/or IPv6 blocklists based on CLI configuration.
/// Validates and applies the fetched blocklists to the `nftables` configuration.
///
/// # Parameters
/// - `cli`: The parsed command-line arguments.
/// - `config`: The active `NftConfig` instance containing `nftables` table information.
///
/// # Errors
/// Returns an `AppError` if fetching, validating, or applying the blocklists fails.
fn update(cli: &Cli, config: &NftConfig) -> Result<(), AppError> {
    let ipv4 = if let Some(url) = cli.url.url4.as_ref() {
        update_ipv4(url.as_str())?
    } else {
        None
    };
    let ipv6 = if let Some(url) = cli.url.url6.as_ref() {
        update_ipv6(url.as_str())?
    } else {
        None
    };

    config.apply_nft(ipv4, ipv6)?;
    info!("the `{}` table successfully loaded", config.table_name);
    Ok(())
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

    // Initialize the logger with a default log level of "info" (can be overridden via `NFTBLOCKD_LOG_LEVEL`).
    let env = Env::new().filter_or("NFTBLOCKD_LOG_LEVEL", "info");
    env_logger::init_from_env(env);

    // Initialize the `nftables` configuration.
    let config = match NftConfig::new() {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            exit(1)
        }
    };

    // If the delete flag is set, clean up the blocklist table and exit.
    if cli.delete {
        let _ = config.delete_table_and_apply().map_err(|e| {
            warn!(
                "the `{}` table (probably) already deleted: {}",
                config.table_name, e
            )
        });
        return;
    }

    // Check that at least one URL (IPv4 or IPv6) is specified; otherwise, exit early.
    if cli.url.url4.is_none() && cli.url.url6.is_none() {
        warn!("no url provided");
        return;
    }

    // Main update loop: Periodically fetch, validate, and apply blocklists.
    loop {
        match update(&cli, &config) {
            Ok(_) => info!("finished"),
            Err(e) => {
                error!("{}", e);
                exit(2);
            }
        }

        sleep(Duration::from_secs(cli.interval));
    }
}
