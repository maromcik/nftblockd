use ipnetwork::{Ipv4Network, Ipv6Network};
use nftables::expr::Expression;
use crate::error::{AppError, AppErrorKind};
use crate::iptrie::deduplicate;
use crate::network::validate_subnets;
use crate::nft::get_nft_expressions;

pub enum SubnetList {
    IPv4(Vec<String>),
    IPv6(Vec<String>),
}

impl SubnetList {
    pub fn validate_blocklist(self) -> Result<ValidatedSubnetList, AppError> {
        let blocklist = match self {
            Self::IPv4(parsed_ips) => ValidatedSubnetList::IPv4(validate_subnets(parsed_ips)),
            Self::IPv6(parsed_ips) => ValidatedSubnetList::IPv6(validate_subnets(parsed_ips)),
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

pub enum ValidatedSubnetList {
    IPv4(Vec<Ipv4Network>),
    IPv6(Vec<Ipv6Network>),
}

impl ValidatedSubnetList {
    pub fn deduplicate(self) -> Result<DeduplicatedSubnetList, AppError> {
        match self {
            ValidatedSubnetList::IPv4(ips) => Ok(DeduplicatedSubnetList::IPv4(deduplicate(ips))),
            ValidatedSubnetList::IPv6(ips) => Ok(DeduplicatedSubnetList::IPv6(deduplicate(ips))),
        }
    }
    fn is_empty(&self) -> bool {
        match self {
            Self::IPv4(ips) => ips.is_empty(),
            Self::IPv6(ips) => ips.is_empty(),
        }
    }
}

pub enum DeduplicatedSubnetList {
    IPv4(Vec<Ipv4Network>),
    IPv6(Vec<Ipv6Network>),
}

impl DeduplicatedSubnetList {
    pub fn to_nft_expression<'a>(self) -> NftExpressionSubnetList<'a> {
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
