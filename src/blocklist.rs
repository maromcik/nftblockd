use std::borrow::Cow;
use crate::error::{AppError, AppErrorKind};
use ipnetwork::{Ipv4Network, Ipv6Network};
use log::{debug, info, warn};
use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use clap::builder::Str;
use iptrie::{IpLCTrieSet, Ipv4LCTrieSet, Ipv4Prefix, Ipv4RTrieSet, Ipv6Prefix, Ipv6RTrieSet};
use iptrie::set::LCTrieSet;
use nftables::{expr, helper};
use nftables::expr::Expression;
use crate::nft::NftConfig;

pub fn fetch_blocklist(endpoint: &str) -> Result<Option<Vec<String>>, AppError> {
    let body = ureq::get(endpoint)
        .header("Example-Header", "header value")
        .call()?
        .body_mut()
        .read_to_string()?;
    if body.is_empty() {
        return Ok(None);
    }
    let blocklist = body
        .trim()
        .split("\n")
        .map(|s| s.trim().to_string())
        .collect::<Vec<String>>();
    info!("blocklist fetched from: {}", endpoint);
    Ok(Some(blocklist))
}

pub enum Blocklist {
    IPv4(Vec<String>),
    IPv6(Vec<String>),
}


impl Blocklist {
    pub fn validate_blocklist(self) -> Result<ValidatedBlocklist, AppError> {
        let validate_ipv4 = |ip: &str| -> Option<Ipv4Network> {
            match ip.parse::<Ipv4Network>() {
                Ok(addr) => {
                    debug!("valid IPv4: {}", ip);
                    Some(addr)
                }
                Err(err) => {
                    warn!("error parsing IPv4: {}; {}", ip, err);
                    None
                }
            }
        };
        let validate_ipv6 = |ip: &str| -> Option<Ipv6Network> {
            match ip.parse::<Ipv6Network>() {
                Ok(addr) => {
                    debug!("valid IPv6: {}", ip);
                    Some(addr)
                }
                Err(err) => {
                    warn!("error parsing IPv6: {}; {}", ip, err);
                    None
                }
            }
        };
        let blocklist = match self {
            Self::IPv4(parsed_ips) => ValidatedBlocklist::IPv4(
                parsed_ips
                    .into_iter()
                    .filter_map(|ip| validate_ipv4(ip.as_str()))
                    .collect::<Vec<Ipv4Network>>(),
            ),
            Self::IPv6(parsed_ips) => ValidatedBlocklist::IPv6(
                parsed_ips
                    .into_iter()
                    .filter_map(|ip| validate_ipv6(ip.as_str()))
                    .collect::<Vec<Ipv6Network>>(),
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
    IPv4(Vec<Ipv4Network>),
    IPv6(Vec<Ipv6Network>),
}

impl ValidatedBlocklist {

    pub fn deduplicate<'a>(self) -> Result<DeduplicatedBlockList<'a>, AppError>{
        match self {
            ValidatedBlocklist::IPv4(mut ips) => {
                let base_ip = "0.0.0.0/0".parse::<Ipv4Prefix>()?;
                ips.sort_by_key(|ip| ip.prefix());
                let mut trie = Ipv4RTrieSet::new();
                for ip in ips {
                    let ip = Ipv4Prefix::new(ip.network(), ip.prefix())?;
                    let res = trie.lookup(&ip);
                    if res == &base_ip {
                        trie.insert(ip);
                    }
                }
                let nft_expressions = trie.iter().map(|ip| expr::Expression::String(Cow::from(ip.to_string()))).collect::<Vec<expr::Expression>>();
                Ok(DeduplicatedBlockList::IPv4(nft_expressions))
            }
            ValidatedBlocklist::IPv6(mut ips) => {
                let base_ip = "::/0".parse::<Ipv6Prefix>()?;
                ips.sort_by_key(|ip| ip.prefix());
                let mut trie = Ipv6RTrieSet::new();
                for ip in ips {
                    let ip = Ipv6Prefix::new(ip.network(), ip.prefix())?;
                    let res = trie.lookup(&ip);
                    if res == &base_ip {
                        trie.insert(ip);
                    }
                }
                let nft_expressions = trie.iter().map(|ip| expr::Expression::String(Cow::from(ip.to_string()))).collect::<Vec<expr::Expression>>();
                Ok(DeduplicatedBlockList::IPv6(nft_expressions))
            }
        }
    }
    pub fn is_empty(&self) -> bool {
        match self {
            Self::IPv4(ips) => ips.is_empty(),
            Self::IPv6(ips) => ips.is_empty(),
        }
    }
    // pub fn format_path(&self, dir: &str, filename: &str) -> String {
    //     match self {
    //         Self::IPv4(_) => format!("{}/{}_ipv4.nft", dir, filename),
    //         Self::IPv6(_) => format!("{}/{}_ipv6.nft", dir, filename),
    //     }
    // }
    // pub fn store_blocklist(&self, dir: &str, filename: &str) -> Result<(), AppError> {
    //     let path = self.format_path(dir, filename);
    //     let mut file = File::create(&path)?;
    //     file.write_all(self.to_string().as_bytes())?;
    //     info!("blocklist saved to: {}", &path);
    //     Ok(())
    // }
    //
    // pub fn to_strings(&self) -> Vec<String> {
    //     match self {
    //         Self::IPv4(ips) => ips.iter().map(|ip| ip.to_string()).collect::<Vec<String>>(),
    //         Self::IPv6(ips) => ips.iter().map(|ip| ip.to_string()).collect::<Vec<String>>(),
    //     }
    // }

}

#[derive(Default)]
pub enum DeduplicatedBlockList<'a> {
    
    IPv4(Vec<Expression<'a>>),
    IPv6(Vec<Expression<'a>>),
    #[default]
    None
}


impl<'a> DeduplicatedBlockList<'a> {
    
    pub fn get_elements(self) -> std::vec::Vec<nftables::expr::Expression<'a>> {
        match self {
            DeduplicatedBlockList::IPv4(mut exp) => {exp.remove(0); exp}
            DeduplicatedBlockList::IPv6(mut exp) => {exp.remove(0); exp}
            DeduplicatedBlockList::None => {vec![]}
        }
    }
}


// impl Display for ValidatedBlocklist {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         let converted = self.to_strings();
//         match self {
//             Self::IPv4(ips) => write!(f, "elements = {{\n{}\n}}\n", converted.join(",\n")),
//             Self::IPv6(ips) => write!(f, "elements = {{\n{}\n}}\n", converted.join(",\n")),
//         }
//     }
// }

