use crate::error::AppError;
use crate::nftables::SetElements;
use crate::subnet::SubnetList;
use ipnetwork::{Ipv4Network, Ipv6Network};
use log::{info, warn};

/// Fetches a blocklist from the given endpoint.
///
/// # Parameters
/// - `endpoint`: The URL from which to fetch the blocklist.
///
/// # Returns
/// - `Ok(Some(Vec<String>))` containing the list of subnets fetched from the endpoint if successful.
/// - `Ok(None)` if the response body is empty.
/// - `Err(AppError)` if the request fails or the response cannot be read.
///
/// # Errors
/// Returns an `AppError` in the following cases:
/// - The HTTP request to the endpoint fails.
/// - The response body cannot be read successfully.
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

/// Updates the IPv4 blocklist by fetching, validating, and transforming subnets into `nftables` elements.
///
/// # Parameters
/// - `url`: The endpoint URL from which to fetch the IPv4 blocklist.
///
/// # Returns
/// - `Ok(Some(SetElements<'a>))` containing the transformed IPv4 subnets as `nftables` expressions.
/// - `Ok(None)` if the fetched blocklist is empty.
/// - `Err(AppError)` if any step in the process fails.
///
/// # Errors
/// - Returns an error if the blocklist fetch fails, if subnets are invalid, or during transformation.
pub fn update_ipv4<'a>(url: &str) -> Result<Option<SetElements<'a>>, AppError> {
    if let Some(blocklist_ipv4) = fetch_blocklist(url)? {
        let elems = SubnetList::IPv4(blocklist_ipv4)
            .validate_blocklist::<Ipv4Network>()?
            .deduplicate()?
            .transform_to_nft_expressions()
            .get_elements();
        Ok(Some(elems))
    } else {
        warn!("empty IPv4 blocklist fetched from: {}", url);
        Ok(None)
    }
}

/// Updates the IPv6 blocklist by fetching, validating, and transforming subnets into `nftables` elements.
///
/// # Parameters
/// - `url`: The endpoint URL from which to fetch the IPv6 blocklist.
///
/// # Returns
/// - `Ok(Some(SetElements<'a>))` containing the transformed IPv6 subnets as `nftables` expressions.
/// - `Ok(None)` if the fetched blocklist is empty.
/// - `Err(AppError)` if any step in the process fails.
///
/// # Errors
/// - Returns an error if the blocklist fetch fails, if subnets are invalid, or during transformation.
pub fn update_ipv6<'a>(url: &str) -> Result<Option<SetElements<'a>>, AppError> {
    if let Some(blocklist_ipv6) = fetch_blocklist(url)? {
        let elems = SubnetList::IPv6(blocklist_ipv6)
            .validate_blocklist::<Ipv6Network>()?
            .deduplicate()?
            .transform_to_nft_expressions()
            .get_elements();
        Ok(Some(elems))
    } else {
        warn!("empty IPv6 blocklist fetched from: {}", url);
        Ok(None)
    }
}
