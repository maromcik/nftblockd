use std::borrow::Cow;
use crate::error::{AppError, AppErrorKind};
use ipnetwork::{Ipv4Network, Ipv6Network};
use log::{debug, info, warn};
use nftables::expr::{Expression, NamedExpression, Prefix};
use crate::trie::{deduplicate, TrieNetwork};

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
        fn validate<T: std::str::FromStr>(ips: Vec<String>) -> Vec<T>
        where
            <T as std::str::FromStr>::Err: std::fmt::Display,
        {
            ips.into_iter()
                .filter_map(|ip| match ip.parse::<T>() {
                    Ok(parsed) => {
                        debug!("valid ip: {}", ip);
                        Some(parsed)
                    }
                    Err(e) => {
                        warn!("invalid ip: {}; {}", ip, e);
                        None
                    }
                })
                .collect()
        }

        let blocklist = match self {
            Self::IPv4(parsed_ips) => ValidatedBlocklist::IPv4(
                validate(parsed_ips)
            ),
            Self::IPv6(parsed_ips) => ValidatedBlocklist::IPv6(
                validate(parsed_ips)
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
    

    pub fn deduplicate<'a>(self) -> Result<DeduplicatedBlockList, AppError>{
        match self {
            ValidatedBlocklist::IPv4(ips) => {
                Ok(DeduplicatedBlockList::IPv4(deduplicate(ips)))
            }
            ValidatedBlocklist::IPv6(ips) => {
                Ok(DeduplicatedBlockList::IPv6(deduplicate(ips)))
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

pub enum DeduplicatedBlockList {
    
    IPv4(Vec<Ipv4Network>),
    IPv6(Vec<Ipv6Network>),
}

impl DeduplicatedBlockList {
    pub fn to_nft_expression<'a>(self) ->NftExpressionBlocklist<'a> {
        match self {
            DeduplicatedBlockList::IPv4(ips) =>NftExpressionBlocklist::IPv4( Self::get_nft_expressions(ips)),
            DeduplicatedBlockList::IPv6(ips) => NftExpressionBlocklist::IPv6(Self::get_nft_expressions(ips)),
        }
    }
    
    pub fn get_nft_expressions<'a, T>(ips: Vec<T>) -> Vec<Expression<'a>>
    where T: TrieNetwork {
        ips.iter()
            .map(|ip| Expression::Named(NamedExpression::Prefix(Prefix {
                addr: Box::new(Expression::String(Cow::from(ip.network_string()))),
                len: ip.network_prefix() as u32,
            })))
            .collect::<Vec<Expression>>()
    }
}

pub enum NftExpressionBlocklist<'a> {
    IPv4(Vec<Expression<'a>>),
    IPv6(Vec<Expression<'a>>),
}

impl<'a> NftExpressionBlocklist<'a> {
    
    pub fn get_elements(self) -> Vec<Expression<'a>> {
        match self {
            Self::IPv4(exp) => exp,
            Self::IPv6(exp) => exp,
        }
    }
}
