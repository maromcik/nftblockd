use crate::error::AppError;
use crate::nftables::SetElements;
use crate::subnet::{SubnetList, parse_from_string};

/// Represents a set of anti-lockout rules.
/// These rules define IPs or subnets that are protected from being blocked inadvertently.
pub enum AntiLockoutSet {
    /// Anti-lockout rules for IPv4 addresses or subnets.
    IPv4(Option<String>),
    /// Anti-lockout rules for IPv6 addresses or subnets.
    IPv6(Option<String>),
}

impl AntiLockoutSet {
    /// Constructs a set of anti-lockout `nftables` elements based on the defined rules.
    ///
    /// # Workflow:
    /// 1. Parses the given string of subnets.
    /// 2. Validates the parsed subnets to ensure correctness.
    /// 3. Deduplicates the subnets to remove overlaps or unnecessary entries.
    /// 4. Converts the resulting subnets into `nftables`-compatible expressions.
    ///
    /// # Type Parameters:
    /// - `'a`: Indicates that the returned `SetElements`' lifetime is tied to the input subnets.
    ///
    /// # Returns:
    /// A `Vec` of `nftables` expressions (`SetElements`) representing the anti-lockout subnets.
    ///
    /// # Errors:
    /// Returns an `AppError` in the following scenarios:
    /// - No valid subnets were parsed.
    /// - Validation or deduplication failed.
    ///
    /// # Example:
    /// ```rust
    /// use nftblockd::anti_lockout::AntiLockoutSet;
    /// let subnets = "192.168.0.1 10.0.0.0/8".to_string();
    /// let anti_lockout = AntiLockoutSet::IPv4(Some(subnets)).build_anti_lockout();
    /// assert!(anti_lockout.is_ok());
    /// ```
    pub fn build_anti_lockout<'a>(self) -> Result<Option<SetElements<'a>>, AppError> {
        match self {
            AntiLockoutSet::IPv4(endpoint) => {
                let Some(ips) = parse_from_string(endpoint.as_deref(), None) else {
                    return Ok(None);
                };
                Ok(SubnetList::IPv4(ips)
                    .validate_blocklist(true)?
                    .deduplicate()?
                    .transform_to_nft_expressions()
                    .get_elements())
            }
            AntiLockoutSet::IPv6(endpoint) => {
                let Some(ips) = parse_from_string(endpoint.as_deref(), None) else {
                    return Ok(None);
                };
                Ok(SubnetList::IPv6(ips)
                    .validate_blocklist(true)?
                    .deduplicate()?
                    .transform_to_nft_expressions()
                    .get_elements())
            }
        }
    }
}
