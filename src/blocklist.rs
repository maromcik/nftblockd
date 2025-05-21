use std::borrow::Cow;
use crate::error::{AppError, AppErrorKind};
use ipnetwork::{Ipv4Network, Ipv6Network};
use log::{debug, info, warn};
use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use clap::builder::Str;
use iptrie::{IpLCTrieSet, IpPrefix, Ipv4LCTrieSet, Ipv4Prefix, Ipv4RTrieSet, Ipv6Prefix, Ipv6RTrieSet};
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

    fn deduplicate_ipv4(ips: &mut Vec<Ipv4Network>, base_ip: &Ipv4Prefix) -> Result<Ipv4RTrieSet, AppError> {
        ips.sort_by_key(|ip| ip.prefix());
        let mut trie = Ipv4RTrieSet::new();
        for ip in ips {
            let ip = Ipv4Prefix::new(ip.network(), ip.prefix())?;
            let res = trie.lookup(&ip);
            if res == base_ip {
                trie.insert(ip);
            }
        }
        Ok(trie)
    }
    
    fn deduplicate_ipv6(ips: &mut Vec<Ipv6Network>, base_ip: &Ipv6Prefix) -> Result<Ipv6RTrieSet, AppError> {
        ips.sort_by_key(|ip| ip.prefix());
        let mut trie = Ipv6RTrieSet::new();
        for ip in ips {
            let ip = Ipv6Prefix::new(ip.network(), ip.prefix())?;
            let res = trie.lookup(&ip);
            if res == base_ip {
                trie.insert(ip);
            }
        }
        Ok(trie)
    }
    
    pub fn deduplicate<'a>(self) -> Result<DeduplicatedBlockList<'a>, AppError>{
        match self {
            ValidatedBlocklist::IPv4(mut ips) => {
                let base_ip = "0.0.0.0/0".parse::<Ipv4Prefix>()?;
                let trie = Self::deduplicate_ipv4(&mut ips, &base_ip)?;
                let nft_expressions = trie
                    .iter()
                    .filter(|ip| *ip != &base_ip)
                    .map(|ip| Expression::String(Cow::from(ip.to_string())))
                    .collect::<Vec<Expression>>();
                Ok(DeduplicatedBlockList::IPv4(nft_expressions))
            }
            ValidatedBlocklist::IPv6(mut ips) => {
                let base_ip = "::/0".parse::<Ipv6Prefix>()?;
                let trie = Self::deduplicate_ipv6(&mut ips, &base_ip)?;
                let nft_expressions = trie
                    .iter()
                    .filter(|ip| **ip != base_ip)
                    .map(|ip| Expression::String(Cow::from(ip.to_string())))
                    .collect::<Vec<Expression>>();
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
}

pub enum DeduplicatedBlockList<'a> {
    
    IPv4(Vec<Expression<'a>>),
    IPv6(Vec<Expression<'a>>),
}

impl<'a> DeduplicatedBlockList<'a> {
    
    pub fn get_elements(self) -> Vec<Expression<'a>> {
        match self {
            DeduplicatedBlockList::IPv4(exp) => exp,
            DeduplicatedBlockList::IPv6(exp) => exp,
        }
    }
}

