use crate::error::{AppError, AppErrorKind};
use crate::network::{validate_subnets};
use crate::iptrie::deduplicate;
use ipnetwork::{Ipv4Network, Ipv6Network};
use log::{info};
use nftables::expr::{Expression};
use crate::nft::get_nft_expressions;

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
        let blocklist = match self {
            Self::IPv4(parsed_ips) => ValidatedBlocklist::IPv4(validate_subnets(parsed_ips)),
            Self::IPv6(parsed_ips) => ValidatedBlocklist::IPv6(validate_subnets(parsed_ips)),
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
    pub fn deduplicate(self) -> Result<DeduplicatedBlockList, AppError> {
        match self {
            ValidatedBlocklist::IPv4(ips) => Ok(DeduplicatedBlockList::IPv4(deduplicate(ips))),
            ValidatedBlocklist::IPv6(ips) => Ok(DeduplicatedBlockList::IPv6(deduplicate(ips))),
        }
    }
    fn is_empty(&self) -> bool {
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
    pub fn to_nft_expression<'a>(self) -> NftExpressionBlocklist<'a> {
        match self {
            DeduplicatedBlockList::IPv4(ips) => {
                NftExpressionBlocklist::IPv4(get_nft_expressions(ips))
            }
            DeduplicatedBlockList::IPv6(ips) => {
                NftExpressionBlocklist::IPv6(get_nft_expressions(ips))
            }
        }
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
