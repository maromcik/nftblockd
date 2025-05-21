use crate::blocklist::ValidatedBlocklist;
use ipnetwork::{Ipv4Network, Ipv6Network};

pub enum BitIp {
    Ipv4(u32),
    Ipv6(u128),
}

impl BitIp {
    pub fn r_shift(&self, n: u8) -> Self {
        match self {
            BitIp::Ipv4(ip) => BitIp::Ipv4(*ip >> n),
            BitIp::Ipv6(ip) => BitIp::Ipv6(*ip >> n),
        }
    }

    pub fn b_and(self, rhs: u8) -> u8 {
        match self {
            BitIp::Ipv4(ip) => (ip & rhs as u32) as u8,
            BitIp::Ipv6(ip) => (ip & rhs as u128) as u8,
        }
    }
}

pub trait TrieNetwork {
    fn network_addr(&self) -> BitIp;
    fn network_prefix(&self) -> u8;
    fn prefix_len(&self) -> u8;
}

impl TrieNetwork for Ipv4Network {
    fn network_addr(&self) -> BitIp {
        BitIp::Ipv4(self.network().to_bits())
    }

    fn network_prefix(&self) -> u8 {
        self.prefix()
    }

    fn prefix_len(&self) -> u8 {
        32
    }
}

impl TrieNetwork for Ipv6Network {
    fn network_addr(&self) -> BitIp {
        BitIp::Ipv6(self.network().to_bits())
    }

    fn network_prefix(&self) -> u8 {
        self.prefix()
    }

    fn prefix_len(&self) -> u8 {
        128
    }
}

#[derive(Default)]
pub(crate) struct TrieNode {
    pub children: [Option<Box<TrieNode>>; 2],
    pub is_subnet: bool,
}

impl TrieNode {
    pub(crate) fn new() -> Self {
        Self {
            children: Default::default(),
            is_subnet: false,
        }
    }

    pub(crate) fn insert<T>(&mut self, ip: T) -> bool
    where
        T: TrieNetwork,
    {
        let mut node = self;

        for i in 0..ip.network_prefix() {
            if node.is_subnet {
                // This subnet is already covered by a broader one
                return false;
            }

            let n = ip.prefix_len() - 1 - i;
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

// fn apply_mask(ip: u32, prefix_len: u8) -> u32 {
//     if prefix_len == 0 {
//         return 0;
//     }
//     ip & (!0u32 << (32 - prefix_len))
// }
//
//
