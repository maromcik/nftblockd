mod error;

use crate::error::{AppError, AppErrorKind};
use clap::Parser;
use env_logger::Env;
use ipnet::{Ipv4Net, Ipv6Net};
use log::{debug, error, info, warn};
use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Interval in seconds to update the blocklist
    #[clap(short, long, value_name = "INTERVAL", default_value = "30")]
    interval: u64,

    /// Output directory for the blocklist files
    #[clap(
        short,
        long,
        value_name = "PATH_TO_DIR",
        default_value = "/etc/nftables/blocklist"
    )]
    dir: String,

    /// Filenames for the blocklist set files, will be suffixed wth ipv4/ipv6
    #[clap(
        short,
        long,
        value_name = "SET_FILENAME",
        default_value = "blocklist_set"
    )]
    filename: String,

    /// Endpoint for getting the ipv4 blocklist
    #[clap(short = '4', long, value_name = "IPv4_URL")]
    url4: String,

    /// Endpoint for getting the ipv6 blocklist
    #[clap(short = '6', long, value_name = "IPv6_URL")]
    url6: String,

    /// Nftables reload command
    #[clap(
        short = 'c',
        long,
        value_name = "COMMAND",
        default_value = "nft -f /etc/nftables/blocklist/blocklist.nft"
    )]
    command: String,
}

pub fn fetch_blocklist(endpoint: &str) -> Result<Vec<String>, AppError> {
    let body = ureq::get(endpoint)
        .header("Example-Header", "header value")
        .call()?
        .body_mut()
        .read_to_string()?;
    if body.is_empty() {
        return Err(AppError::new(
            AppErrorKind::EmptyBlocklistError,
            format!("URL: {}", endpoint).as_str(),
        ));
    }
    let blocklist = body
        .trim()
        .split("\n")
        .map(|s| s.trim().to_string())
        .collect::<Vec<String>>();
    info!("blocklist fetched from: {}", endpoint);
    Ok(blocklist)
}

pub enum Blocklist {
    IPv4(Vec<String>),
    IPv6(Vec<String>),
}

impl Blocklist {
    pub fn validate_blocklist(self) -> Result<ValidatedBlocklist, AppError> {
        let validate_ipv4 = |ip: &str| -> bool {
            match (ip.parse::<Ipv4Addr>(), ip.parse::<Ipv4Net>()) {
                (Err(ip_err), Err(_)) => {
                    warn!("error parsing IPv4: {}; {}", ip, ip_err);
                    false
                }
                (_, _) => {
                    debug!("valid IPv4: {}", ip);
                    true
                }
            }
        };
        let validate_ipv6 = |ip: &str| -> bool {
            match (ip.parse::<Ipv6Addr>(), ip.parse::<Ipv6Net>()) {
                (Err(ip_err), Err(_)) => {
                    warn!("error parsing IPv6: {}; {}", ip, ip_err);
                    false
                }
                (_, _) => {
                    debug!("valid IPv6: {}", ip);
                    true
                }
            }
        };
        Ok(match self {
            Self::IPv4(parsed_ips) => {
                let blocklist = parsed_ips
                    .into_iter()
                    .filter(|ip| validate_ipv4(ip))
                    .collect::<Vec<String>>();
                if blocklist.is_empty() {
                    return Err(AppError::new(
                        AppErrorKind::NoAddressesParsedError,
                        "the blocklist is empty after parsing",
                    ));
                }
                ValidatedBlocklist::IPv4(blocklist)
            }
            Self::IPv6(parsed_ips) => {
                let blocklist = parsed_ips
                    .into_iter()
                    .filter(|ip| validate_ipv6(ip))
                    .collect::<Vec<String>>();
                if blocklist.is_empty() {
                    return Err(AppError::new(
                        AppErrorKind::NoAddressesParsedError,
                        "the blocklist is empty after parsing",
                    ));
                }
                ValidatedBlocklist::IPv6(blocklist)
            }
        })
    }
}

pub enum ValidatedBlocklist {
    IPv4(Vec<String>),
    IPv6(Vec<String>),
}

impl Display for ValidatedBlocklist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IPv4(ips) => write!(f, "elements = {{\n{}\n}}\n", ips.join(",\n")),
            Self::IPv6(ips) => write!(f, "elements = {{\n{}\n}}\n", ips.join(",\n")),
        }
    }
}

impl ValidatedBlocklist {
    pub fn format_path(&self, dir: &str, filename: &str) -> String {
        match self {
            Self::IPv4(_) => format!("{}/{}_ipv4.nft", dir, filename),
            Self::IPv6(_) => format!("{}/{}_ipv6.nft", dir, filename),
        }
    }
    pub fn store_blocklist(&self, dir: &str, filename: &str) -> Result<(), AppError> {
        let path = self.format_path(dir, filename);
        let mut file = File::create(&path)?;
        file.write_all(self.to_string().as_bytes())?;
        info!("blocklist saved to: {}", &path);
        Ok(())
    }
}

fn update(cli: &Cli) -> Result<(), AppError> {
    let blocklist_ipv4 = Blocklist::IPv4(fetch_blocklist(&cli.url4)?).validate_blocklist()?;
    let blocklist_ipv6 = Blocklist::IPv6(fetch_blocklist(&cli.url6)?).validate_blocklist()?;
    blocklist_ipv4.store_blocklist(&cli.dir, &cli.filename)?;
    blocklist_ipv6.store_blocklist(&cli.dir, &cli.filename)?;
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
