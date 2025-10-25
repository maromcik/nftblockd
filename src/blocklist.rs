use crate::error::{AppError, AppErrorKind};
use crate::nftables::{NftConfig, SetElements};
use crate::subnet::{SubnetList, parse_from_string};
use log::{info, warn};
use std::collections::HashMap;
use std::time::Duration;

pub struct BlockList {
    pub headers: Option<HashMap<String, String>>,
    pub timeout: Duration,
    pub ipv4_endpoint: Option<String>,
    pub ipv6_endpoint: Option<String>,
    pub split_string: Option<String>,
}

// headers with json in env

impl BlockList {
    /// Creates a new `BlockList` instance.
    ///
    /// This function initializes a `BlockList` object with the provided parameters.
    /// It parses the `headers` string into a `HashMap` of key-value pairs if provided,
    /// and converts other optional parameters into their expected types.
    ///
    /// # Arguments
    ///
    /// * `headers` - An optional JSON string that contains HTTP headers in key-value format.
    /// * `ipv4_endpoint` - An optional string representing the IPv4 blocklist URL.
    /// * `ipv6_endpoint` - An optional string representing the IPv6 blocklist URL.
    /// * `split_string` - An optional delimiter used to split the blocklist contents.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the newly created `BlockList` object, or an `AppError` if parsing the headers fails.
    ///
    /// # Errors
    /// Will return `AppError` when parsing headers fails
    pub fn new(
        headers: Option<String>,
        timeout: u64,
        ipv4_endpoint: Option<String>,
        ipv6_endpoint: Option<String>,
        split_string: Option<&str>,
    ) -> Result<BlockList, AppError> {
        let headers: Option<HashMap<String, String>> = headers
            .map(|h| serde_json::from_str(h.as_str()))
            .transpose()?;
        Ok(Self {
            headers,
            timeout: Duration::from_secs(timeout),
            ipv4_endpoint,
            ipv6_endpoint,
            split_string: split_string.map(std::string::ToString::to_string),
        })
    }

    /// Fetches and parses a blocklist from the specified endpoint.
    ///
    /// This function sends an HTTP GET request to the given endpoint. If headers
    /// are specified in the `BlockList` object, they are applied to the request.
    /// The response body is read and processed using the delimiter specified by `split_string`
    /// before being returned.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - A string reference to the endpoint URL from which to fetch the blocklist.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing an optional `Vec<String>` with blocklist entries, or an `AppError`
    /// if the request or parsing fails.
    /// # Errors
    /// Will return `AppError` when fetching blocklist fails
    fn fetch_blocklist(&self, endpoint: &str) -> Result<Option<Vec<String>>, AppError> {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .build();

        let agent = ureq::Agent::new_with_config(config);

        let mut request = agent.get(endpoint);

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
                    format!("failed to fetch from {endpoint}: {e}").as_str(),
                )
            })?
            .body_mut()
            .read_to_string()?;

        let blocklist = parse_from_string(Some(body.trim()).as_ref(), self.split_string.as_deref());

        info!("blocklist fetched from: {endpoint}");
        Ok(blocklist)
    }

    /// Updates the IPv4 blocklist and transforms it into nftables expressions.
    ///
    /// This function fetches the IPv4 blocklist using the `ipv4_endpoint`. If a blocklist is
    /// successfully retrieved, it is validated, deduplicated, and transformed into nftables-compatible
    /// expressions.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing an optional `SetElements` object with the expressions,
    /// or an `AppError` if any step during the process fails.
    /// # Errors
    /// Will return `AppError` when parsing subnets fails
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
            warn!("empty IPv4 blocklist fetched from: {url}");
            Ok(None)
        }
    }

    /// Updates the IPv6 blocklist and transforms it into nftables expressions.
    ///
    /// This function fetches the IPv6 blocklist using the `ipv6_endpoint`. If a blocklist is
    /// successfully retrieved, it is validated, deduplicated, and transformed into nftables-compatible
    /// expressions.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing an optional `SetElements` object with the expressions,
    /// or an `AppError` if any step during the process fails.
    /// # Errors
    /// Will return `AppError` when parsing subnets fails
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
            warn!("empty IPv6 blocklist fetched from: {url}");
            Ok(None)
        }
    }

    /// Applies the updated blocklists to the nftables configuration.
    ///
    /// This public function updates both the IPv4 and IPv6 blocklists (if their respective endpoints are provided)
    /// and applies the resulting nftables expressions to the given `NftConfig`. Logs relevant information
    /// such as the successful application of the blocklist table.
    ///
    /// # Arguments
    ///
    /// * `config` - A reference to the `NftConfig` object where the blocklist updates will be applied.
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success (`Ok(())`) or an `AppError` if any part of the process fails.
    /// # Errors
    /// Will return `AppError` when updating nftables fails
    pub fn update(&self, config: &NftConfig) -> Result<(), AppError> {
        let ipv4 = self.update_ipv4()?;
        let ipv6 = self.update_ipv6()?;

        config.apply_nft(&ipv4, &ipv6)?;
        info!("the `{}` table successfully loaded", config.table_name);
        Ok(())
    }
}
