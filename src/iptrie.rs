use crate::network::BlocklistNetwork;

pub enum BitIp {
    Ipv4(u32),
    Ipv6(u128),
}

impl BitIp {
    fn r_shift(&self, n: u8) -> Self {
        match self {
            BitIp::Ipv4(ip) => BitIp::Ipv4(*ip >> n),
            BitIp::Ipv6(ip) => BitIp::Ipv6(*ip >> n),
        }
    }

    fn b_and(self, rhs: u8) -> u8 {
        match self {
            BitIp::Ipv4(ip) => (ip & rhs as u32) as u8,
            BitIp::Ipv6(ip) => (ip & rhs as u128) as u8,
        }
    }
}
#[derive(Default)]
struct TrieNode {
    children: [Option<Box<TrieNode>>; 2],
    is_subnet: bool,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: Default::default(),
            is_subnet: false,
        }
    }

    fn insert<T>(&mut self, ip: &T) -> bool
    where
        T: BlocklistNetwork,
    {
        let mut node = self;

        for i in 0..ip.network_prefix() {
            if node.is_subnet {
                // This subnet is already covered by a broader one
                return false;
            }

            let n = ip.max_prefix() - 1 - i;
            let bit = ip.network_addr().r_shift(n).b_and(1);
            node = node.children[bit as usize].get_or_insert_with(|| Box::new(TrieNode::new()));
        }

        if node.is_subnet {
            // Exact subnet already exists — this is a duplicate.
            return false;
        }

        // Mark this node as a subnet and prune deeper subnets
        node.is_subnet = true;
        node.children = Default::default(); // Drop more specific subnets
        true
    }
}

pub fn deduplicate<T>(mut ips: Vec<T>) -> Vec<T>
where
    T: BlocklistNetwork,
{
    ips.sort_by_key(|ip| ip.network_prefix());
    let mut root = TrieNode::new();
    let mut result = Vec::new();
    for ip in ips {
        if root.insert(&ip) {
            result.push(ip);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnetwork::{Ipv4Network, Ipv6Network};
    use std::str::FromStr;

    fn parse_subnets<T>(subnets: Vec<&str>) -> Vec<T>
    where
        T: FromStr,
        <T as FromStr>::Err: std::fmt::Debug,
    {
        subnets
            .into_iter()
            .map(|s| s.parse::<T>().unwrap())
            .collect::<Vec<T>>()
    }

    #[test]
    fn test_deduplicate_ipv4_subnets() {
        let subnets = vec![
            "192.168.1.0/24",
            "192.168.0.0/16",
            "10.1.0.0/16",
            "10.0.0.0/8",
            "172.16.5.0/24",
            "172.16.0.0/16",
            "8.8.8.0/24",
        ];

        let deduped: Vec<Ipv4Network> = deduplicate(parse_subnets(subnets));

        // Expected subnets after deduplication:
        let expected = vec![
            Ipv4Network::from_str("10.0.0.0/8").unwrap(),
            Ipv4Network::from_str("192.168.0.0/16").unwrap(),
            Ipv4Network::from_str("172.16.0.0/16").unwrap(),
            Ipv4Network::from_str("8.8.8.0/24").unwrap(),
        ];
        assert_eq!(
            deduped, expected,
            "The deduplicated subnets did not match the expected list."
        );
    }

    #[test]
    fn test_deduplicate_ipv6_subnets() {
        let subnets = vec![
            "2001:db8::/64",
            "2001:db8::/32",
            "2001:db8:0:1::/64",
            "fe80::/10",
            "fe80::1/128",
        ];

        let deduped: Vec<Ipv6Network> = deduplicate(parse_subnets(subnets));

        // Expected subnets after deduplication:
        let expected = vec![
            Ipv6Network::from_str("fe80::/10").unwrap(),
            Ipv6Network::from_str("2001:db8::/32").unwrap(),
        ];

        assert_eq!(
            deduped, expected,
            "The deduplicated subnets did not match the expected list."
        );
    }
}
