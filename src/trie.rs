use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

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

    fn insert(&mut self, ip: u32, prefix_len: u8) -> bool {
        let mut node = self;

        for i in 0..prefix_len {
            if node.is_subnet {
                // This subnet is already covered by a broader one
                return false;
            }

            let bit = (ip >> (31 - i)) & 1;
            node = node.children[bit as usize].get_or_insert_with(|| Box::new(TrieNode::new()));
        }

        // Mark this node as a subnet and prune deeper subnets
        node.is_subnet = true;
        node.children = Default::default(); // Drop more specific subnets
        true
    }
}

fn ipv4_str_to_u32(ip_str: &str) -> u32 {
    let ip = Ipv4Addr::from_str(ip_str).unwrap();
    u32::from(ip)
}

fn apply_mask(ip: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        return 0;
    }
    ip & (!0u32 << (32 - prefix_len))
}

pub(crate) fn deduplicate_subnets(subnets: Vec<&str>) -> Vec<String> {
    let mut parsed: Vec<(u32, u8)> = subnets
        .into_iter()
        .map(|s| {
            let parts: Vec<&str> = s.split('/').collect();
            let ip = ipv4_str_to_u32(parts[0]);
            let prefix_len = parts[1].parse::<u8>().unwrap();
            (apply_mask(ip, prefix_len), prefix_len)
        })
        .collect();

    // Sort by increasing prefix length (broadest subnets first)
    parsed.sort_by_key(|&(_, prefix_len)| prefix_len);

    let mut root = TrieNode::new();
    let mut result = Vec::new();

    for (network, prefix_len) in parsed {
        if root.insert(network, prefix_len) {
            let ip = Ipv4Addr::from(network).to_string();
            result.push(format!("{}/{}", ip, prefix_len));
        }
    }

    result
}
