use crate::network::BlockListNetwork;
use itertools::Itertools;

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
/// Generic Prefix Trie node
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

    /// Prefix trie insertion method
    fn insert<T>(&mut self, ip: &T) -> bool
    where
        T: BlockListNetwork,
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

/// Deduplicates a vector of structs that implement the BlockListNetwork trait
/// by sorting the vector and then inserting elements into a prefix trie.
/// Time complexity is O(h*n*logn), where h is the height of the trie
/// and n*logn is there because of the sorting.
/// The height of the trie in our case is at most 32 for IPv4 and 128 for IPv6
pub fn deduplicate<T>(ips: impl Iterator<Item = T>) -> Vec<T>
where
    T: BlockListNetwork,
{
    let ips = ips.sorted_by_key(|ip| ip.network_prefix());
    let mut root = TrieNode::new();
    let mut result = Vec::new();
    for ip in ips {
        if root.insert(&ip) {
            result.push(ip);
        }
    }
    result
}
