use std::fmt::Display;

use crate::grpc::ctl::nftblockd::{
    ChainDropStats, DropStats, IpFamilyDropStats, Stats, StatusSummary,
};

pub mod nftblockd {
    tonic::include_proto!("nftblockd");
}

impl Display for StatusSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "status_code={} status={} message={}",
            self.status_code, self.status, self.message
        )
    }
}

impl Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "===COMBINED===\n{}\n\n{}",
            self.combined.unwrap_or_default(),
            self.drop_stats.unwrap_or_default()
        )
    }
}

impl Display for DropStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "packets={} bytes={}", self.packets, self.bytes)
    }
}

impl Display for ChainDropStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "===PREROUTING===\n{}\n\n===POSTROUTING===\n{}",
            self.prerouting.unwrap_or_default(),
            self.postrouting.unwrap_or_default()
        )
    }
}

impl Display for IpFamilyDropStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "---IPv4---\n{}\n\n---IPv6---\n{}",
            self.ipv4.unwrap_or_default(),
            self.ipv6.unwrap_or_default()
        )
    }
}
