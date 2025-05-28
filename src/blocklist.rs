use crate::error::{AppError, AppErrorKind};
use crate::nftables::{NftConfig, SetElements};
use crate::subnet::{SubnetList, parse_from_string};
use log::{info, warn};
use std::collections::HashMap;

pub struct BlockList {
    pub headers: Option<HashMap<String, String>>,
    pub ipv4_endpoint: Option<String>,
    pub ipv6_endpoint: Option<String>,
    pub split_string: Option<String>,
}

// headers with json in env

impl BlockList {
    pub fn new(
        headers: Option<String>,
        ipv4_endpoint: Option<String>,
        ipv6_endpoint: Option<String>,
        split_string: Option<&str>,
    ) -> Result<BlockList, AppError> {
        let headers: Option<HashMap<String, String>> = headers
            .map(|h| serde_json::from_str(h.as_str()))
            .transpose()?;
        Ok(Self {
            headers,
            ipv4_endpoint,
            ipv6_endpoint,
            split_string: split_string.map(|s| s.to_string()),
        })
    }

    fn fetch_blocklist(&self, endpoint: &str) -> Result<Option<Vec<String>>, AppError> {
        let mut request = ureq::get(endpoint);

        if let Some(headers) = &self.headers {
            for header in headers {
                request = request.header(header.0, header.1);
            }
        }
        
        let call = request.call();
        let body = call
            .map_err(|e| {
                AppError::new(
                    AppErrorKind::RequestError,
                    format!("failed to fetch from {}: {}", endpoint, e).as_str(),
                )
            })?
            .body_mut()
            .read_to_string()?;

        let blocklist = parse_from_string(Some(body.trim()), self.split_string.as_deref());

        info!("blocklist fetched from: {}", endpoint);
        Ok(blocklist)
    }

    fn update_ipv4<'a>(&self) -> Result<Option<SetElements<'a>>, AppError> {
        let Some(url) = self.ipv4_endpoint.as_deref() else {
            return Ok(None);
        };
        if let Some(blocklist_ipv4) = self.fetch_blocklist(url)? {
            let elems = SubnetList::IPv4(blocklist_ipv4)
                .validate_blocklist(false)?
                .deduplicate()?
                .transform_to_nft_expressions()
                .get_elements();
            Ok(elems)
        } else {
            warn!("empty IPv4 blocklist fetched from: {}", url);
            Ok(None)
        }
    }

    fn update_ipv6<'a>(&self) -> Result<Option<SetElements<'a>>, AppError> {
        let Some(url) = self.ipv6_endpoint.as_deref() else {
            return Ok(None);
        };
        if let Some(blocklist_ipv6) = self.fetch_blocklist(url)? {
            let elems = SubnetList::IPv6(blocklist_ipv6)
                .validate_blocklist(false)?
                .deduplicate()?
                .transform_to_nft_expressions()
                .get_elements();
            Ok(elems)
        } else {
            warn!("empty IPv6 blocklist fetched from: {}", url);
            Ok(None)
        }
    }

    pub fn update(&self, config: &NftConfig) -> Result<(), AppError> {
        let ipv4 = self.update_ipv4()?;
        let ipv6 = self.update_ipv6()?;

        config.apply_nft(ipv4, ipv6)?;
        info!("the `{}` table successfully loaded", config.table_name);
        Ok(())
    }
}
