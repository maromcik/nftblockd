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

