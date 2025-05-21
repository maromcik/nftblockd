use crate::network::{parse_from_string, validate_subnets};
use crate::nft::{SetElements, get_nft_expressions};
use ipnetwork::{Ipv4Network, Ipv6Network};

pub enum AntiLockoutSet {
    IPv4(String),
    IPv6(String),
}
impl AntiLockoutSet {
    pub fn build_anti_lockout<'a>(self) -> SetElements<'a> {
        match self {
            AntiLockoutSet::IPv4(s) => {
                let ips = parse_from_string(s.as_str());
                let validated: Vec<Ipv4Network> = validate_subnets(ips);
                get_nft_expressions(validated)
            }
            AntiLockoutSet::IPv6(s) => {
                let ips = parse_from_string(s.as_str());
                let validated: Vec<Ipv6Network> = validate_subnets(ips);
                get_nft_expressions(validated)
            }
        }
    }
}
