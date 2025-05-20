mod blocklist;
mod error;

use crate::blocklist::{Blocklist, fetch_blocklist};
use crate::error::{AppError, AppErrorKind};
use clap::Parser;
use env_logger::Env;
use log::{debug, error, info, warn};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
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

    /// Endpoint for getting the ipv4 blocklist
    #[clap(short = '4', long, value_name = "IPv4_URL", env = "BLOCKLIST_IPV4_URL")]
    url4: String,

    /// Endpoint for getting the ipv6 blocklist
    #[clap(short = '6', long, value_name = "IPv6_URL", env = "BLOCKLIST_IPV6_URL")]
    url6: String,

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

fn update(cli: &Cli) -> Result<(), AppError> {
    if let Some(blocklist_ipv4) = fetch_blocklist(&cli.url4)? {
        Blocklist::IPv4(blocklist_ipv4)
            .validate_blocklist()?
            .store_blocklist(&cli.dir, &cli.filename)?;
    } else {
        warn!("empty IPv4 blocklist fetched from: {}", cli.url4);
    }
    if let Some(blocklist_ipv6) = fetch_blocklist(&cli.url6)? {
        Blocklist::IPv6(blocklist_ipv6)
            .validate_blocklist()?
            .store_blocklist(&cli.dir, &cli.filename)?;
    } else {
        warn!("empty IPv6 blocklist fetched from: {}", cli.url6);
    }
    load_nft(&cli.command)?;
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
    let cli = Cli::parse();
    loop {
        match update(&cli) {
            Ok(_) => info!("finished"),
            Err(e) => {
                error!("{}", e);
                break;
            }
        }

        sleep(Duration::from_secs(cli.interval));
    }
}
