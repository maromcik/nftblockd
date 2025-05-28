use crate::iptrie::BitIp;
use ipnetwork::{Ipv4Network, Ipv6Network};
use std::fmt::Debug;

/// Trait that defines a generic abstraction for representing network-related operations on IPv4 and IPv6 subnets.
/// This trait is implemented for `Ipv4Network` and `Ipv6Network`.
pub trait ListNetwork: Clone + Debug {
    /// Retrieves the numeric representation (as `BitIp`) of the network address.
    ///
    /// # Returns
    /// A `BitIp` containing the numeric representation of the network address.
    fn network_addr(&self) -> BitIp;

    /// Retrieves the network prefix length, which is the number of bits used for the network part of the address.
    ///
    /// # Returns
    /// An unsigned 8-bit integer (`u8`) representing the prefix length.
    fn network_prefix(&self) -> u8;

    /// Provides the maximum allowable prefix length for the network type.
    ///
    /// # Returns
    /// - `32` for IPv4 networks.
    /// - `128` for IPv6 networks.
    fn max_prefix(&self) -> u8;

    /// Converts the network address to its string representation (e.g., `192.168.0.0/24`).
    ///
    /// # Returns
    /// A `String` containing the CIDR representation of the network.
    fn network_string(&self) -> String;

    /// Checks whether the current network is properly aligned to the prefix boundary.
    ///
    /// # Returns
    /// `true` if the network address is aligned; otherwise, `false`.
    fn is_network(&self) -> bool;
}

/// Implementation of the `BlockListNetwork` trait for IPv4 networks (`Ipv4Network`).
impl ListNetwork for Ipv4Network {
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

/// Implementation of the `BlockListNetwork` trait for IPv6 networks (`Ipv6Network`).
impl ListNetwork for Ipv6Network {
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
