use crate::error::{AppError, AppErrorKind};
use crate::iptrie::deduplicate;
use crate::network::ListNetwork;
use crate::nftables::get_nft_expressions;
use ipnetwork::{Ipv4Network, Ipv6Network};
use log::warn;
use nftables::expr::Expression;
use std::fmt::Display;
use std::str::FromStr;

/// Represents a collection of subnets, either IPv4 or IPv6.
pub enum SubnetList {
    /// Collection of IPv4 subnets as `Vec<String>`.
    IPv4(Vec<String>),
    /// Collection of IPv6 subnets as `Vec<String>`.
    IPv6(Vec<String>),
}

impl SubnetList {
    /// Validates the subnets within the list and converts them into a validated format.
    ///
    /// # Type Parameters
    /// - `V`: The network type implementing the `BlockListNetwork` trait (e.g., `Ipv4Network` or `Ipv6Network`).
    ///
    /// # Returns
    /// A `ValidatedSubnetList` containing valid IPv4 or IPv6 subnets.
    ///
    /// # Errors
    /// Returns an `AppError` if no valid addresses are available after validation.
    pub fn validate_blocklist(self, strict: bool) -> Result<ValidatedSubnetList, AppError> {
        let blocklist = match self {
            // Parse and validate the IPv4 blocklist.
            Self::IPv4(parsed_ips) => {
                ValidatedSubnetList::IPv4(validate_subnets::<Ipv4Network>(&parsed_ips, strict)?)
            }
            // Parse and validate the IPv6 blocklist.
            Self::IPv6(parsed_ips) => {
                ValidatedSubnetList::IPv6(validate_subnets::<Ipv6Network>(&parsed_ips, strict)?)
            }
        };

        Ok(blocklist)
    }

    #[must_use]
    pub fn get_strings(self) -> Vec<String> {
        match self {
            Self::IPv4(ips) | Self::IPv6(ips) => ips,
        }
    }
}

/// Represents a validated list of IPv4 or IPv6 subnets that can be deduplicated.
pub enum ValidatedSubnetList {
    IPv4(Option<Vec<Ipv4Network>>), // IPv4 list after validation.
    IPv6(Option<Vec<Ipv6Network>>), // IPv6 list after validation.
}

impl ValidatedSubnetList {
    /// Deduplicates the validated subnets using a prefix trie, removing redundant subnets.
    ///
    /// # Returns
    /// A `DeduplicatedSubnetList` containing only the largest covering subnets.
    ///
    /// # Errors
    /// Returns an `AppError` if an internal failure occurs during deduplication.
    pub fn deduplicate(self) -> Result<DeduplicatedSubnetList, AppError> {
        match self {
            // Deduplicate IPv4 subnets.
            ValidatedSubnetList::IPv4(ips) => Ok(DeduplicatedSubnetList::IPv4(deduplicate(ips))),
            // Deduplicate IPv6 subnets.
            ValidatedSubnetList::IPv6(ips) => Ok(DeduplicatedSubnetList::IPv6(deduplicate(ips))),
        }
    }
}

/// Represents a deduplicated list of IPv4 or IPv6 subnets.
pub enum DeduplicatedSubnetList {
    /// Deduplicated IPv4 subnets contained in a `Vec`.
    IPv4(Option<Vec<Ipv4Network>>),
    /// Deduplicated IPv6 subnets contained in a `Vec`.
    IPv6(Option<Vec<Ipv6Network>>),
}

impl DeduplicatedSubnetList {
    /// Transforms the deduplicated subnets into a list of `nftables` expressions.
    /// These expressions can be used directly in the `nftables` ruleset.
    ///
    /// # Returns
    /// An `NftExpressionSubnetList` containing expressions for IPv4 or IPv6 subnets.
    #[must_use]
    pub fn transform_to_nft_expressions<'a>(self) -> NftExpressionSubnetList<'a> {
        match self {
            // Transform IPv4 subnets into `nftables` expressions.
            DeduplicatedSubnetList::IPv4(ips) => {
                NftExpressionSubnetList::IPv4(get_nft_expressions(ips))
            }
            // Transform IPv6 subnets into `nftables` expressions.
            DeduplicatedSubnetList::IPv6(ips) => {
                NftExpressionSubnetList::IPv6(get_nft_expressions(ips))
            }
        }
    }
}

/// Contains `nftables` expressions for IPv4 or IPv6 subnets.
/// These expressions are used when applying firewall rules to `nftables`.
pub enum NftExpressionSubnetList<'a> {
    /// IPv4 `nftables` expressions.
    IPv4(Option<Vec<Expression<'a>>>),
    /// IPv6 `nftables` expressions.
    IPv6(Option<Vec<Expression<'a>>>),
}

impl<'a> NftExpressionSubnetList<'a> {
    /// Extracts all elements (expressions) from the subnet list.
    ///
    /// # Returns
    /// A `Vec` containing `Expression` instances, either for IPv4 or IPv6.
    #[must_use]
    pub fn get_elements(self) -> Option<Vec<Expression<'a>>> {
        match self {
            Self::IPv4(exp) | Self::IPv6(exp) => exp,
        }
    }
}

/// Parses a single space-separated string into a vector of subnet strings.
///
/// # Parameters
/// - `s`: A string containing space-separated subnet representations.
///
/// # Returns
/// A vector of subnet strings.
#[must_use]
pub fn parse_from_string<S: AsRef<str>>(
    data: Option<S>,
    split_string: Option<&str>,
) -> Option<Vec<String>> {
    match data {
        Some(s) if !s.as_ref().is_empty() => match split_string {
            None => Some(
                s.as_ref()
                    .split_whitespace()
                    .map(|s| s.trim().to_string())
                    .collect(),
            ),
            Some(split_str) => Some(
                s.as_ref()
                    .split(split_str)
                    .map(|s| s.trim().to_string())
                    .collect(),
            ),
        },
        _ => None,
    }
}

/// Validates a list of subnets and filters them into valid structures.
///
/// # Type Parameters
/// - `T`: A type that implements the `BlockListNetwork` trait (e.g., `Ipv4Network` or `Ipv6Network`).
///
/// # Parameters
/// - `ips`: A `Vec` of raw subnet strings to validate.
/// - `strict`: Whether to return an error if an invalid subnet is encountered.
///
/// # Returns
/// Aa vector of valid subnets represented as type `T`.
/// # Errors
/// Will return `AppError` when subnets are invalid
pub fn validate_subnets<T>(ips: &[String], strict: bool) -> Result<Option<Vec<T>>, AppError>
where
    T: ListNetwork + FromStr + Display + std::fmt::Debug,
    <T as FromStr>::Err: Display,
    AppError: From<<T as FromStr>::Err>,
{
    let mut parsed = Vec::new();
    for ip in ips {
        match ip.parse::<T>() {
            Ok(parsed_ip) => {
                if parsed_ip.is_network() {
                    parsed.push(parsed_ip);
                } else if strict {
                    return Err(AppError::new(
                        AppErrorKind::ParseError,
                        format!("invalid ip: {parsed_ip}; not a network").as_str(),
                    ));
                } else {
                    warn!("invalid ip: {ip}; not a network");
                }
            }
            Err(e) => {
                if strict {
                    return Err(AppError::from(e));
                }
                warn!("ip could not be parsed: {ip}; {e}");
            }
        }
    }

    Ok(if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    })
}

// pub fn validate_subnets<T>(ips: Vec<String>) -> Vec<T>
// where
//     T: BlocklistNetwork + FromStr,
//     <T as FromStr>::Err: Display,
// {
//     ips.into_iter()
//         .filter_map(|ip| match ip.parse::<T>() {
//             Ok(parsed) => {
//                 if parsed.is_network() {
//                     debug!("valid ip: {}", ip);
//                     Some(parsed)
//                 } else {
//                     warn!("invalid ip: {}; not a network", ip);
//                     None
//                 }
//             }
//             Err(e) => {
//                 warn!("ip could not be parsed: {}; {}", ip, e);
//                 None
//             }
//         })
//         .collect()
// }
