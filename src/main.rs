use clap::Parser;
use env_logger::Env;
use log::{error, info, warn};
use nftables_blocklist_updater::blocklist::{update_ipv4, update_ipv6};
use nftables_blocklist_updater::error::AppError;
use nftables_blocklist_updater::nftables::NftConfig;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;

#[derive(Debug, clap::Args)]
#[group(multiple = true)]
pub struct UrlGroup {
    /// Endpoint for getting the ipv4 blocklist
    #[clap(
        short = '4',
        long,
        value_name = "IPv4_URL",
        env = "NFTABLES_BLOCKLIST_IPV4_URL"
    )]
    url4: Option<String>,

    /// Endpoint for getting the ipv6 blocklist
    #[clap(
        short = '6',
        long,
        value_name = "IPv6_URL",
        env = "NFTABLES_BLOCKLIST_IPV6_URL"
    )]
    url6: Option<String>,
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(flatten)]
    url: UrlGroup,

    /// Interval in seconds to update the blocklist
    #[clap(
        short,
        long,
        value_name = "INTERVAL",
        default_value = "30",
        env = "NFTABLES_BLOCKLIST_INTERVAL"
    )]
    interval: u64,

    #[clap(short, long, value_name = "ENV_FILE")]
    env_file: Option<String>,

    /// If true, deletes the existing blocklist table and exits.
    #[arg(short = 'd', long = "delete", action = clap::ArgAction::SetTrue)]
    delete: bool,
}

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

fn main() {
    let mut cli = Cli::parse();
    if let Some(env_file) = cli.env_file {
        dotenvy::from_filename(env_file).expect("failed to load .env file");
        cli = Cli::parse();
    }

    let env = Env::new().filter_or("NFTABLES_BLOCKLIST_LOG_LEVEL", "info");
    env_logger::init_from_env(env);

    let config = match NftConfig::new() {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            return;
        }
    };

    if cli.delete {
        let _ = config.delete_table_and_apply().map_err(|e| {
            warn!(
                "the `{}` table (probably) already deleted: {}",
                config.table_name, e
            )
        });
        return;
    }

    if cli.url.url4.is_none() && cli.url.url6.is_none() {
        warn!("no url provided");
        return;
    }

    loop {
        match update(&cli, &config) {
            Ok(_) => info!("finished"),
            Err(e) => {
                error!("{}", e);
                exit(1);
            }
        }

        sleep(Duration::from_secs(cli.interval));
    }
}
