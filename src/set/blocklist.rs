use crate::error::AppError;
use crate::grpc::server::ServiceStatusStruct;
use crate::nftables::builder::SetElements;
use crate::nftables::config::NftConfig;
use crate::nftables::flush_table;
use crate::utils::status::NftblockdStatus;
use crate::utils::subnet::{SubnetList, parse_from_string};
use log::{error, info, warn};
use rand::RngExt;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
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
        ipv4_endpoint: Option<String>,
        ipv6_endpoint: Option<String>,
        split_string: Option<&str>,
    ) -> Result<BlockList, AppError> {
        let headers = env::var("NFTBLOCKD_REQUEST_HEADERS")
            .ok()
            .filter(|s| !s.is_empty());
        let timeout = env::var("NFTBLOCKD_REQUEST_TIMEOUT")
            .unwrap_or("10".to_string())
            .parse::<u64>()?;
        let headers: Option<HashMap<String, String>> = headers
            .map(|h| serde_json::from_str(h.as_str()))
            .transpose()?;
        Ok(Self {
            headers,
            timeout: Duration::from_secs(timeout),
            ipv4_endpoint,
            ipv6_endpoint,
            split_string: split_string.map(ToString::to_string),
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
    async fn fetch_blocklist(&self, endpoint: &str) -> Result<Option<Vec<String>>, AppError> {
        let client = reqwest::Client::builder().timeout(self.timeout).build()?;

        let mut req = client.get(endpoint);

        if let Some(headers) = &self.headers {
            for (k, v) in headers {
                req = req.header(k, v);
            }
        }

        let body = req.send().await?.text().await?;

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
    async fn update_ipv4<'a>(&self) -> Result<Option<SetElements<'a>>, AppError> {
        let Some(url) = self.ipv4_endpoint.as_deref() else {
            return Ok(None);
        };
        if let Some(blocklist_ipv4) = self.fetch_blocklist(url).await? {
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
    async fn update_ipv6<'a>(&self) -> Result<Option<SetElements<'a>>, AppError> {
        let Some(url) = self.ipv6_endpoint.as_deref() else {
            return Ok(None);
        };
        if let Some(blocklist_ipv6) = self.fetch_blocklist(url).await? {
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
    pub async fn update(
        &self,
        config: &NftConfig<'_>,
        status: Arc<ServiceStatusStruct>,
    ) -> Result<(), AppError> {
        info!("Generating stats");
        config.generate_stats(status.stats.clone()).await?;

        if matches!(*status.status.read().await, NftblockdStatus::Ok) {
            *status.status.write().await = NftblockdStatus::Pending;
        }

        info!("Pulling and parsing blocklist");
        let ipv4 = self.update_ipv4().await?;
        let ipv6 = self.update_ipv6().await?;

        info!("Applying nftables ruleset");
        config.apply_nft(&ipv4, &ipv6)?;
        info!("the `{}` table successfully loaded", config.table_name);
        Ok(())
    }
}

pub async fn blocklist_loop(
    status: Arc<ServiceStatusStruct>,
    blocklist: BlockList,
    config: NftConfig<'_>,
    refresh_interval: u64,
    retry_count: u64,
    retry_interval: u64,
    cancellation_token: CancellationToken,
) {
    let mut counter = 1;
    loop {
        info!("starting updating nftables blocklist");
        match blocklist.update(&config, status.clone()).await {
            Ok(()) => {
                info!("finished updating nftables blocklist");
                *status.status.write().await = NftblockdStatus::Ok;
                counter = 1;
            }
            Err(e) => {
                error!("{e}");
                if !matches!(*status.status.read().await, NftblockdStatus::Failed(_)) {
                    *status.status.write().await = NftblockdStatus::PreFail(e.clone());
                }

                let ms = retry_interval * 1000;
                let sleep_interval = rand::rng().random_range(ms / 2..ms * 2);
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_millis(sleep_interval)) => {}
                    () = cancellation_token.cancelled() => {
                        info!("stopping blocklist retry loop");
                        return;
                    }
                }
                warn!(
                    "paused for {sleep_interval} ms; retrying; attempt {counter} out of {retry_count}"
                );
                if counter >= retry_count {
                    let err = AppError::NftblockdError(format!(
                        "failed to update nftables blocklist after {retry_count} retries; reason: {e}; FLUSHING TABLE!"
                    ));
                    error!("{err}");
                    *status.status.write().await = NftblockdStatus::Failed(err);
                    counter = 1;
                    flush_table(&config);
                }
                counter += 1;
                continue;
            }
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(refresh_interval)) => {}
            () = cancellation_token.cancelled() => {
                info!("stopping blocklist loop");
                return;
            }
        }
    }
}
