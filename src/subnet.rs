use crate::error::{AppError, AppErrorKind};
use crate::iptrie::deduplicate;
use crate::network::BlockListNetwork;
use crate::nftables::get_nft_expressions;
use log::{debug, warn};
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
    pub fn validate_blocklist<V>(
        self,
    ) -> Result<ValidatedSubnetList<impl Iterator<Item = V> + Clone, V>, AppError>
    where
        V: BlockListNetwork + FromStr,
        <V as FromStr>::Err: Display,
    {
        let blocklist = match self {
            // Parse and validate the IPv4 blocklist.
            Self::IPv4(parsed_ips) => ValidatedSubnetList::IPv4(validate_subnets::<V>(parsed_ips)),
            // Parse and validate the IPv6 blocklist.
            Self::IPv6(parsed_ips) => ValidatedSubnetList::IPv6(validate_subnets::<V>(parsed_ips)),
        };

        // If the blocklist is empty after parsing, return an error.
        if blocklist.is_empty() {
            return Err(AppError::new(
                AppErrorKind::NoAddressesParsedError,
                "the blocklist is empty after parsing",
            ));
        };
        Ok(blocklist)
    }
}

/// Represents a validated list of IPv4 or IPv6 subnets that can be deduplicated.
pub enum ValidatedSubnetList<T, V>
where
    T: Iterator<Item = V> + Clone,
    V: BlockListNetwork,
{
    IPv4(T), // IPv4 list after validation.
    IPv6(T), // IPv6 list after validation.
}

impl<T, V> ValidatedSubnetList<T, V>
where
    T: Iterator<Item = V> + Clone,
    V: BlockListNetwork,
{
    /// Deduplicates the validated subnets using a prefix trie, removing redundant subnets.
    ///
    /// # Returns
    /// A `DeduplicatedSubnetList` containing only the largest covering subnets.
    ///
    /// # Errors
    /// Returns an `AppError` if an internal failure occurs during deduplication.
    pub fn deduplicate(self) -> Result<DeduplicatedSubnetList<V>, AppError> {
        match self {
            // Deduplicate IPv4 subnets.
            ValidatedSubnetList::IPv4(ips) => {
                Ok(DeduplicatedSubnetList::IPv4(deduplicate::<V>(ips)))
            }
            // Deduplicate IPv6 subnets.
            ValidatedSubnetList::IPv6(ips) => {
                Ok(DeduplicatedSubnetList::IPv6(deduplicate::<V>(ips)))
            }
        }
    }

    /// Checks whether the validated subnet list is empty.
    ///
    /// # Returns
    /// `true` if the list contains no valid subnets; otherwise, `false`.
    fn is_empty(&self) -> bool {
        match self {
            Self::IPv4(ips) => ips.clone().peekable().peek().is_none(),
            Self::IPv6(ips) => ips.clone().peekable().peek().is_none(),
        }
    }
}

/// Represents a deduplicated list of IPv4 or IPv6 subnets.
pub enum DeduplicatedSubnetList<V>
where
    V: BlockListNetwork,
{
    /// Deduplicated IPv4 subnets contained in a `Vec`.
    IPv4(Vec<V>),
    /// Deduplicated IPv6 subnets contained in a `Vec`.
    IPv6(Vec<V>),
}

impl<V> DeduplicatedSubnetList<V>
where
    V: BlockListNetwork,
{
    /// Transforms the deduplicated subnets into a list of `nftables` expressions.
    /// These expressions can be used directly in the `nftables` ruleset.
    ///
    /// # Returns
    /// An `NftExpressionSubnetList` containing expressions for IPv4 or IPv6 subnets.
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
    IPv4(Vec<Expression<'a>>),
    /// IPv6 `nftables` expressions.
    IPv6(Vec<Expression<'a>>),
}

impl<'a> NftExpressionSubnetList<'a> {
    /// Extracts all elements (expressions) from the subnet list.
    ///
    /// # Returns
    /// A `Vec` containing `Expression` instances, either for IPv4 or IPv6.
    pub fn get_elements(self) -> Vec<Expression<'a>> {
        match self {
            // Extract IPv4 expressions.
            Self::IPv4(exp) => exp,
            // Extract IPv6 expressions.
            Self::IPv6(exp) => exp,
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
pub fn parse_from_string(s: &str) -> Vec<String> {
    s.split_whitespace().map(|s| s.to_string()).collect()
}

/// Validates a list of subnets and filters them into valid structures.
///
/// # Type Parameters
/// - `T`: A type that implements the `BlockListNetwork` trait (e.g., `Ipv4Network` or `Ipv6Network`).
///
/// # Parameters
/// - `ips`: A `Vec` of raw subnet strings to validate.
///
/// # Returns
/// An iterator over valid subnets represented as type `T`.
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
