use crate::error::AppError;
use crate::nftables::SetElements;
use crate::subnet::SubnetList;
use ipnetwork::{Ipv4Network, Ipv6Network};
use log::{info, warn};

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
