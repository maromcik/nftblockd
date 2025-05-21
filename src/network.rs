use std::fmt::Display;
use std::str::{FromStr};
use crate::iptrie::BitIp;
use ipnetwork::{Ipv4Network, Ipv6Network};
use log::{debug, warn};

pub trait BlocklistNetwork {
    fn network_addr(&self) -> BitIp;
    fn network_prefix(&self) -> u8;
    fn max_prefix(&self) -> u8;
    fn network_string(&self) -> String;
    fn is_network(&self) -> bool;
}

impl BlocklistNetwork for Ipv4Network {
    fn network_addr(&self) -> BitIp {
        BitIp::Ipv4(self.network().to_bits())
    }
    fn network_prefix(&self) -> u8 {
        self.prefix()
    }
    fn max_prefix(&self) -> u8 {
        32
    }
    fn network_string(&self) -> String {
        self.network().to_string()
    }
    fn is_network(&self) -> bool {
        self.network() == self.ip()
    }
}

impl BlocklistNetwork for Ipv6Network {
    fn network_addr(&self) -> BitIp {
        BitIp::Ipv6(self.network().to_bits())
    }
    fn network_prefix(&self) -> u8 {
        self.prefix()
    }
    fn max_prefix(&self) -> u8 {
        128
    }
    fn network_string(&self) -> String {
        self.network().to_string()
    }

    fn is_network(&self) -> bool {
        self.network() == self.ip()
    }
}

pub fn parse_from_string(s: &str) -> Vec<String> {
    s.split_whitespace()
        .map(|s| s.to_string())
        .collect()
}


pub fn validate_subnets<T>(ips: Vec<String>) -> Vec<T>
where
    T: BlocklistNetwork + FromStr,
    <T as FromStr>::Err: Display,
{
    ips.into_iter()
        .filter_map(|ip| match ip.parse::<T>() {
            Ok(parsed) =>
                if parsed.is_network() {
                    debug!("valid ip: {}", ip);
                    Some(parsed)
                } else {
                    warn!("invalid ip: {}; not a network", ip);
                    None
                }
            Err(e) => {
                warn!("ip could not be parsed: {}; {}", ip, e);
                None
            }
        })
        .collect()
}