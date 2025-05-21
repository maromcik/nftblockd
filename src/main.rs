mod blocklist;
mod error;
mod nft;
mod trie;


use crate::blocklist::{Blocklist, fetch_blocklist};
use crate::error::{AppError, AppErrorKind};
use clap::Parser;
use env_logger::Env;
use log::{debug, error, info, warn};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use crate::nft::{NftConfig, SetElements};

#[derive(Debug, clap::Args)]
#[group(required = true, multiple = true)]
pub struct CommandGroup {
    /// Endpoint for getting the ipv4 blocklist
    #[clap(short = '4', long, value_name = "IPv4_URL", env = "BLOCKLIST_IPV4_URL")]
    url4: Option<String>,

    /// Endpoint for getting the ipv6 blocklist
    #[clap(short = '6', long, value_name = "IPv6_URL", env = "BLOCKLIST_IPV6_URL")]
    url6: Option<String>,
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {

    #[clap(flatten)]
    url: CommandGroup,


    /// Interval in seconds to update the blocklist
    #[clap(
        short,
        long,
        value_name = "INTERVAL",
        default_value = "30",
        env = "BLOCKLIST_INTERVAL"
    )]
    interval: u64,

    /// Output directory for the blocklist files
    #[clap(
        short,
        long,
        value_name = "PATH_TO_DIR",
        default_value = "/etc/nftables/blocklist",
        env = "BLOCKLIST_DIR"
    )]
    dir: String,

    /// Filenames for the blocklist set files, will be suffixed wth ipv4/ipv6
    #[clap(
        short,
        long,
        value_name = "SET_FILENAME",
        default_value = "blocklist_set",
        env = "BLOCKLIST_FILENAME"
    )]
    filename: String,
    
    /// Nftables reload command
    #[clap(
        short = 'c',
        long,
        value_name = "COMMAND",
        default_value = "nft -f /etc/nftables/blocklist/blocklist.nft",
        env = "BLOCKLIST_COMMAND"
    )]
    command: String,
}

fn update_ipv4<'a>(url: &str) -> Result<Option<SetElements<'a>>, AppError> {
    if let Some(blocklist_ipv4) = fetch_blocklist(url)? {
        let elems = Blocklist::IPv4(blocklist_ipv4)
            .validate_blocklist()?
            .deduplicate()?
            .to_nft_expression()
            .get_elements();
        Ok(Some(elems))
    } else {
        warn!("empty IPv4 blocklist fetched from: {}", url);
        Ok(None)
    }
}

fn update_ipv6<'a>(url: &str) -> Result<Option<SetElements<'a>>, AppError> {
    if let Some(blocklist_ipv6) = fetch_blocklist(url)? {
        let elems = Blocklist::IPv6(blocklist_ipv6)
            .validate_blocklist()?
            .deduplicate()?
            .to_nft_expression()
            .get_elements();
        Ok(Some(elems))
    } else {
        warn!("empty IPv6 blocklist fetched from: {}", url);
        Ok(None)
    }
}

fn update(cli: &Cli, config:  &NftConfig) -> Result<(), AppError> {
    let ipv4 = if let Some(url) = cli.url.url4.as_ref() {
        update_ipv4(url.as_str())?
    } else { None };
    let ipv6 = if let Some(url) = cli.url.url6.as_ref() {
        update_ipv6(url.as_str())?
    } else { None };
    config.apply_nft(ipv4, ipv6)?;
    Ok(())
}

pub fn load_nft(command: &str) -> Result<(), AppError> {
    let commands: Vec<&str> = command.split_whitespace().collect();
    let Some(program) = commands.first() else {
        return Err(AppError::new(
            AppErrorKind::InvalidCommandError,
            "no command provided!",
        ));
    };
    let output = Command::new(program)
        .args(commands.iter().skip(1))
        .output()?;
    debug!("running command: {}", command);
    debug!("stdout: {}", String::from_utf8_lossy(&output.stdout).trim());
    debug!("stderr: {}", String::from_utf8_lossy(&output.stderr).trim());
    if !output.status.success() {
        return Err(AppError::new(
            AppErrorKind::NftablesError,
            format!(
                "nftables reload failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
            .as_str(),
        ));
    }
    info!("nftables successfully reloaded");
    Ok(())
}

fn main() {
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    // let subnets = vec![
    //     "192.168.1.0/24",
    //     "192.168.0.0/16",
    //     "10.1.0.0/16",
    //     "10.0.0.0/8",
    //     "172.16.5.0/24",
    //     "172.16.0.0/16",
    //     "8.8.8.0/24",
    // ].iter().map(|s| Ipv4Network::from_str(s).unwrap()).collect::<Vec<_>>();
    //
    // let deduped = deduplicate_ipv4(subnets);
    //
    // for subnet in deduped {
    //     println!("{}", subnet);
    // }

    let config = NftConfig {
        table_name: "blocklist",
        prerouting_chain: "prerouting",
        postrouting_chain: "postrouting",
        blocklist_set_name: "blocklist_set",
        anti_lockout_set_name: "anti_lockout_set",
    };
    
    let cli = Cli::parse();
    loop {
        match update(&cli, &config) {
            Ok(_) => info!("finished"),
            Err(e) => {
                error!("{}", e);
                break;
            }
        }

        sleep(Duration::from_secs(cli.interval));
    }
}

