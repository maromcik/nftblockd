use crate::error::{AppError, AppErrorKind};
use crate::iptrie::deduplicate;
use crate::network::BlockListNetwork;
use crate::nftables::get_nft_expressions;
use log::{debug, warn};
use nftables::expr::Expression;
use std::fmt::Display;
use std::str::FromStr;

pub enum SubnetList {
    IPv4(Vec<String>),
    IPv6(Vec<String>),
}

impl SubnetList {
    pub fn validate_blocklist<V>(
        self,
    ) -> Result<ValidatedSubnetList<impl Iterator<Item = V> + Clone, V>, AppError>
    where
        V: BlockListNetwork + FromStr,
        <V as FromStr>::Err: Display,
    {
        let blocklist = match self {
            Self::IPv4(parsed_ips) => ValidatedSubnetList::IPv4(validate_subnets::<V>(parsed_ips)),
            Self::IPv6(parsed_ips) => ValidatedSubnetList::IPv6(validate_subnets::<V>(parsed_ips)),
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

pub enum ValidatedSubnetList<T, V>
where
    T: Iterator<Item = V> + Clone,
    V: BlockListNetwork,
{
    IPv4(T),
    IPv6(T),
}

impl<T, V> ValidatedSubnetList<T, V>
where
    T: Iterator<Item = V> + Clone,
    V: BlockListNetwork,
{
    pub fn deduplicate(self) -> Result<DeduplicatedSubnetList<V>, AppError> {
        match self {
            ValidatedSubnetList::IPv4(ips) => {
                Ok(DeduplicatedSubnetList::IPv4(deduplicate::<V>(ips)))
            }
            ValidatedSubnetList::IPv6(ips) => {
                Ok(DeduplicatedSubnetList::IPv6(deduplicate::<V>(ips)))
            }
        }
    }
    fn is_empty(&self) -> bool {
        match self {
            Self::IPv4(ips) => ips.clone().peekable().peek().is_none(),
            Self::IPv6(ips) => ips.clone().peekable().peek().is_none(),
        }
    }
}

pub enum DeduplicatedSubnetList<V>
where
    V: BlockListNetwork,
{
    IPv4(Vec<V>),
    IPv6(Vec<V>),
}

impl<V> DeduplicatedSubnetList<V>
where
    V: BlockListNetwork,
{
    pub fn transform_to_nft_expressions<'a>(self) -> NftExpressionSubnetList<'a> {
        match self {
            DeduplicatedSubnetList::IPv4(ips) => {
                NftExpressionSubnetList::IPv4(get_nft_expressions(ips))
            }
            DeduplicatedSubnetList::IPv6(ips) => {
                NftExpressionSubnetList::IPv6(get_nft_expressions(ips))
            }
        }
    }
}

pub enum NftExpressionSubnetList<'a> {
    IPv4(Vec<Expression<'a>>),
    IPv6(Vec<Expression<'a>>),
}

impl<'a> NftExpressionSubnetList<'a> {
    pub fn get_elements(self) -> Vec<Expression<'a>> {
        match self {
            Self::IPv4(exp) => exp,
            Self::IPv6(exp) => exp,
        }
    }
}

pub fn parse_from_string(s: &str) -> Vec<String> {
    s.split_whitespace().map(|s| s.to_string()).collect()
}

pub fn validate_subnets<T>(ips: Vec<String>) -> impl Iterator<Item = T> + Clone
where
    T: BlockListNetwork + FromStr,
    <T as FromStr>::Err: Display,
{
    ips.into_iter().filter_map(|ip| match ip.parse::<T>() {
        Ok(parsed) => {
            if parsed.is_network() {
                debug!("valid ip: {}", ip);
                Some(parsed)
            } else {
                warn!("invalid ip: {}; not a network", ip);
                None
            }
        }
        Err(e) => {
            warn!("ip could not be parsed: {}; {}", ip, e);
            None
        }
    })
}
