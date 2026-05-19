use std::ops::AddAssign;

use nftables::{
    expr::{Expression, NamedExpression, Payload, PayloadField},
    schema::Rule,
    stmt::Statement,
};
use serde::{Deserialize, Serialize};

use crate::{
    grpc::ctl::nftblockd::{
        ChainDropStats as GrpcChainDropStats, DropStats as GrpcDropStats,
        IpFamilyDropStats as GrpcIpFamilyDropStats, Stats as GrpcStats,
    },
    nftables::builder::RuleProto,
};

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub drop_stats: ChainDropStats,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DropStats {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Default, Clone)]
pub struct IpFamilyDropStats {
    pub combined: DropStats,
    pub ipv4: DropStats,
    pub ipv6: DropStats,
}

#[derive(Debug, Default, Clone)]
pub struct ChainDropStats {
    pub combined: DropStats,
    pub prerouting: IpFamilyDropStats,
    pub postrouting: IpFamilyDropStats,
}

impl Stats {
    pub fn add(&mut self, rhs: Self) {
        *self += rhs;
    }
}

impl AddAssign for DropStats {
    fn add_assign(&mut self, rhs: Self) {
        self.packets += rhs.packets;
        self.bytes += rhs.bytes;
    }
}

impl AddAssign for IpFamilyDropStats {
    fn add_assign(&mut self, rhs: Self) {
        self.combined += rhs.combined;
        self.ipv4 += rhs.ipv4;
        self.ipv6 += rhs.ipv6;
    }
}

impl AddAssign for ChainDropStats {
    fn add_assign(&mut self, rhs: Self) {
        self.combined += rhs.combined;
        self.prerouting += rhs.prerouting;
        self.postrouting += rhs.postrouting;
    }
}

impl AddAssign for Stats {
    fn add_assign(&mut self, rhs: Self) {
        self.drop_stats += rhs.drop_stats;
    }
}

impl From<RuleInfo> for Stats {
    fn from(rule_info: RuleInfo) -> Self {
        let mut stats = Stats::default();
        match rule_info.chain.as_str() {
            "prerouting" => {
                stats.drop_stats.prerouting.combined.bytes += rule_info.bytes as u64;
                stats.drop_stats.prerouting.combined.packets += rule_info.packets as u64;
                match rule_info.protocol {
                    RuleProto::Ip => {
                        stats.drop_stats.prerouting.ipv4.bytes += rule_info.bytes as u64;
                        stats.drop_stats.prerouting.ipv4.packets += rule_info.packets as u64;
                    }
                    RuleProto::Ip6 => {
                        stats.drop_stats.prerouting.ipv6.bytes += rule_info.bytes as u64;
                        stats.drop_stats.prerouting.ipv6.packets += rule_info.packets as u64;
                    }
                    RuleProto::Other => {}
                }
            }
            "postrouting" => {
                stats.drop_stats.postrouting.combined.bytes += rule_info.bytes as u64;
                stats.drop_stats.postrouting.combined.packets += rule_info.packets as u64;
                match rule_info.protocol {
                    RuleProto::Ip => {
                        stats.drop_stats.postrouting.ipv4.bytes += rule_info.bytes as u64;
                        stats.drop_stats.postrouting.ipv4.packets += rule_info.packets as u64;
                    }
                    RuleProto::Ip6 => {
                        stats.drop_stats.postrouting.ipv6.bytes += rule_info.bytes as u64;
                        stats.drop_stats.postrouting.ipv6.packets += rule_info.packets as u64;
                    }
                    RuleProto::Other => {}
                }
            }
            _ => {}
        }
        stats.drop_stats.combined.bytes += rule_info.bytes as u64;
        stats.drop_stats.combined.packets += rule_info.packets as u64;
        stats
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuleInfo {
    pub table: String,
    pub chain: String,
    pub protocol: RuleProto,
    pub set_name: String,
    pub packets: usize,
    pub bytes: usize,
}

#[allow(clippy::single_match)]
impl From<&Rule<'_>> for RuleInfo {
    fn from(rule: &Rule<'_>) -> Self {
        let mut rule_info = RuleInfo {
            table: rule.table.to_string(),
            chain: rule.chain.to_string(),
            protocol: RuleProto::default(),
            set_name: String::new(),
            packets: 0,
            bytes: 0,
        };

        for expr in rule.expr.iter() {
            match expr {
                Statement::Match(m) => {
                    match &m.right {
                        Expression::String(st) => {
                            rule_info.set_name = st.to_string();
                        }
                        _ => {}
                    }
                    match &m.left {
                        Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                            PayloadField {
                                protocol,
                                field: _field,
                            },
                        ))) => {
                            rule_info.protocol = match protocol.to_string().as_str() {
                                "ip" => RuleProto::Ip,
                                "ip6" => RuleProto::Ip6,
                                _ => RuleProto::Other,
                            };
                        }
                        _ => {}
                    }
                }
                Statement::Counter(nftables::stmt::Counter::Anonymous(Some(counter))) => {
                    if let Some(x) = counter.bytes {
                        rule_info.bytes = x;
                    }
                    if let Some(x) = counter.packets {
                        rule_info.packets = x;
                    }
                }
                _ => {}
            }
        }
        rule_info
    }
}

impl From<DropStats> for GrpcDropStats {
    fn from(value: DropStats) -> Self {
        GrpcDropStats {
            packets: value.packets,
            bytes: value.bytes,
        }
    }
}
impl From<IpFamilyDropStats> for GrpcIpFamilyDropStats {
    fn from(value: IpFamilyDropStats) -> Self {
        GrpcIpFamilyDropStats {
            combined: Some(value.combined.into()),
            ipv4: Some(value.ipv4.into()),
            ipv6: Some(value.ipv6.into()),
        }
    }
}

impl From<ChainDropStats> for GrpcChainDropStats {
    fn from(value: ChainDropStats) -> Self {
        GrpcChainDropStats {
            combined: Some(value.combined.into()),
            prerouting: Some(value.prerouting.into()),
            postrouting: Some(value.postrouting.into()),
        }
    }
}

impl From<Stats> for GrpcStats {
    fn from(value: Stats) -> Self {
        GrpcStats {
            drop_stats: Some(value.drop_stats.into()),
        }
    }
}
