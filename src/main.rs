mod anti_lockout;
mod blocklist;
mod error;
mod iptrie;
mod network;
mod nft;
mod subnet;

use crate::anti_lockout::AntiLockoutSet;
use crate::blocklist::{update_ipv4, update_ipv6};
use crate::error::AppError;
use crate::nft::{NftConfig, SetElements};
use clap::Parser;
use env_logger::Env;
use log::{error, info, warn};
use std::env;
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

    Ok(())
}

fn main() {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();
    let env = Env::new().filter("NFTABLES_BLOCKLIST_LOG_LEVEL");
    env_logger::init_from_env(env);
    let (anti_lockout_ipv4, anti_lockout_ipv6) = match parse_anti_lockout_env() {
        Ok(sets) => sets,
        Err(e) => {
            error!("{}", e);
            exit(1);
        }
    };
    let config = NftConfig {
        table_name: &env::var("NFTABLES_BLOCKLIST_TABLE_NAME").unwrap_or("blocklist".into()),
        prerouting_chain: &env::var("NFTABLES_BLOCKLIST_PREROUTING_CHAIN_NAME")
            .unwrap_or("prerouting".into()),
        postrouting_chain: &env::var("NFTABLES_BLOCKLIST_POSTROUTING_CHAIN_NAME")
            .unwrap_or("postrouting".into()),
        blocklist_set_name: &env::var("NFTABLES_BLOCKLIST_BLOCKLIST_SET_NAME")
            .unwrap_or("blocklist_set".into()),
        anti_lockout_set_name: &env::var("NFTABLES_BLOCKLIST_ANTI_LOCKOUT_SET_NAME")
            .unwrap_or("anti_lockout_set".into()),
        anti_lockout_ipv4,
        anti_lockout_ipv6,
    };

    if cli.delete {
        let _ = config
            .delete_table_and_apply()
            .map_err(|e| warn!("probably already deleted: {}", e));
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

fn parse_anti_lockout_env<'a>()
-> Result<(Option<SetElements<'a>>, Option<SetElements<'a>>), AppError> {
    let anti_lockout_ipv4_string = env::var("NFTABLES_BLOCKLIST_ANTI_LOCKOUT_IPV4").ok();
    let anti_lockout_ipv4 = anti_lockout_ipv4_string
        .map(|s| AntiLockoutSet::IPv4(s).build_anti_lockout())
        .transpose()?;

    let anti_lockout_ipv6_string = env::var("NFTABLES_BLOCKLIST_ANTI_LOCKOUT_IPV6").ok();
    let anti_lockout_ipv6 = anti_lockout_ipv6_string
        .map(|s| AntiLockoutSet::IPv6(s).build_anti_lockout())
        .transpose()?;

    Ok((anti_lockout_ipv4, anti_lockout_ipv6))
}
