use crate::error::{AppError, AppErrorKind};
use ipnet::{Ipv4Net, Ipv6Net};
use log::{debug, info, warn};
use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

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
            if let (Err(ip_err), Err(_)) = (ip.parse::<Ipv4Addr>(), ip.parse::<Ipv4Net>()) {
                warn!("error parsing IPv4: {}; {}", ip, ip_err);
                false
            } else {
                debug!("valid IPv4: {}", ip);
                true
            }
        };
        let validate_ipv6 = |ip: &str| -> bool {
            if let (Err(ip_err), Err(_)) = (ip.parse::<Ipv6Addr>(), ip.parse::<Ipv6Net>()) {
                warn!("error parsing IPv6: {}; {}", ip, ip_err);
                false
            } else {
                debug!("valid IPv6: {}", ip);
                true
            }
        };
        let blocklist = match self {
            Self::IPv4(parsed_ips) => ValidatedBlocklist::IPv4(
                parsed_ips
                    .into_iter()
                    .filter(|ip| validate_ipv4(ip))
                    .collect::<Vec<String>>(),
            ),
            Self::IPv6(parsed_ips) => ValidatedBlocklist::IPv6(
                parsed_ips
                    .into_iter()
                    .filter(|ip| validate_ipv6(ip))
                    .collect::<Vec<String>>(),
            ),
        };
        if blocklist.is_empty() {
            return Err(AppError::new(
                AppErrorKind::NoAddressesParsedError,
                "the blocklist is empty after parsing",
            ));
        };
        Ok(blocklist)
    }
}

pub enum ValidatedBlocklist {
    IPv4(Vec<String>),
    IPv6(Vec<String>),
}

impl ValidatedBlocklist {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::IPv4(ips) => ips.is_empty(),
            Self::IPv6(ips) => ips.is_empty(),
        }
    }
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
