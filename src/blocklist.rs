use std::borrow::Cow;
use crate::error::{AppError, AppErrorKind};
use ipnetwork::{Ipv4Network, Ipv6Network};
use log::{debug, info, warn};

use nftables::{helper};
use nftables::expr::{Expression, NamedExpression, Prefix};

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
    pub fn sort_by_prefix(&mut self)
    {
        match self {
            ValidatedBlocklist::IPv4(ips) => ips.sort_by_key(|ip| ip.prefix()),
            ValidatedBlocklist::IPv6(ips) => ips.sort_by_key(|ip| ip.prefix()),
        }
    }


    pub fn deduplicate<'a>(self) -> Result<DeduplicatedBlockList<'a>, AppError>{
        match self {
            ValidatedBlocklist::IPv4(mut ips) => {

                ips.sort_by_key(|ip| ip.prefix());
                let mut root = crate::trie::TrieNode::new();
                let mut result = Vec::new();
                for ip in ips {
                    if root.insert(ip) {
                        result.push(ip);
                    }
                }
                
                let nft_expressions = result
                    .iter()
                    .map(|ip| Expression::Named(NamedExpression::Prefix(Prefix {
                        addr: Box::new(Expression::String(Cow::from(ip.network().to_string()))),
                        len: ip.prefix() as u32,
                    })))
                    .collect::<Vec<Expression>>();
                Ok(DeduplicatedBlockList::IPv4(nft_expressions))
            }
            ValidatedBlocklist::IPv6(mut ips) => {
                // let base_ip = "::/0".parse::<Ipv6Network>()?;
                ips.sort_by_key(|ip| ip.prefix());
                let mut root = crate::trie::TrieNode::new();
                let mut result = Vec::new();
                for ip in ips {
                    if root.insert(ip) {
                        result.push(ip);
                    }
                }

                let nft_expressions = result
                    .iter()
                    .map(|ip| Expression::Named(NamedExpression::Prefix(Prefix {
                        addr: Box::new(Expression::String(Cow::from(ip.network().to_string()))),
                        len: ip.prefix() as u32,
                    })))
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

