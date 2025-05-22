use nftables_blocklist_updater::iptrie::deduplicate;
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

#[test]
fn test_deduplicate_zero_prefix_ipv4() {
    let subnets = vec![
        "0.0.0.0/0",
        "10.0.0.0/8",
        "192.168.1.1/32",
        "172.16.0.0/12",
    ];

    let deduped: Vec<Ipv4Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv4Network::from_str("0.0.0.0/0").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Expected 0.0.0.0/0 to absorb all other IPv4 networks."
    );
}

#[test]
fn test_deduplicate_broadcast_address() {
    let subnets = vec![
        "255.255.255.255/32",
        "255.255.255.255/32",
    ];

    let deduped: Vec<Ipv4Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv4Network::from_str("255.255.255.255/32").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Broadcast address deduplication failed."
    );
}

#[test]
fn test_deduplicate_single_ip_subnets_ipv4() {
    let subnets = vec![
        "10.1.2.3/32",
        "10.1.2.3/32",
        "10.1.2.3/32",
    ];

    let deduped: Vec<Ipv4Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv4Network::from_str("10.1.2.3/32").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Expected deduplication of repeated /32 addresses."
    );
}

#[test]
fn test_deduplicate_single_ip_subnets_ipv6() {
    let subnets = vec![
        "2001:db8::1/128",
        "2001:db8::1/128",
    ];

    let deduped: Vec<Ipv6Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv6Network::from_str("2001:db8::1/128").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Expected deduplication of repeated /128 IPv6 addresses."
    );
}

#[test]
fn test_deduplicate_ipv6_zero_prefix() {
    let subnets = vec![
        "2001:db8::/32",
        "2001:db8:abcd::/48",
        "2001:db8::1/128",
        "::/0",
    ];

    let deduped: Vec<Ipv6Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv6Network::from_str("::/0").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Expected ::/0 to absorb all other IPv6 subnets."
    );
}

#[test]
fn test_deduplicate_disjoint_ipv4_subnets() {
    let subnets = vec![
        "1.1.1.0/24",
        "2.2.2.0/24",
        "3.3.3.0/24",
    ];

    let deduped: Vec<Ipv4Network> = deduplicate(parse_subnets(subnets));

    let expected = parse_subnets(vec![
        "1.1.1.0/24",
        "2.2.2.0/24",
        "3.3.3.0/24",
    ]);

    assert_eq!(
        deduped, expected,
        "Disjoint subnets should remain unchanged after deduplication."
    );
}
#[test]
fn test_deduplicate_ipv6_deeply_nested_subnets() {
    let subnets = vec![
        "2001:db8::/32",
        "2001:db8:0:1::/48",
        "2001:db8:0:1:1::/64",
        "2001:db8:0:1:1:1::/80",
        "2001:db8:0:1:1:1:1::/96",
    ];

    let deduped: Vec<Ipv6Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv6Network::from_str("2001:db8::/32").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Nested IPv6 subnets should be absorbed by their supernet."
    );
}

#[test]
fn test_deduplicate_ipv6_mixed_overlap_and_disjoint() {
    let subnets = vec![
        "2001:db8:abcd::/48",
        "2001:db8::/32",
        "2001:dead:beef::/48",
        "2001:dead::/32",
        "2001:db8:abcd:1::/64",
    ];

    let deduped: Vec<Ipv6Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv6Network::from_str("2001:db8::/32").unwrap(),
        Ipv6Network::from_str("2001:dead::/32").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Redundant subnets under broader /32s should be removed."
    );
}

#[test]
fn test_deduplicate_ipv6_extreme_prefixes() {
    let subnets = vec![
        "2001:db8::0/128",
        "2001:db8::1/128",
        "2001:db8::/127",
    ];

    let deduped: Vec<Ipv6Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv6Network::from_str("2001:db8::/127").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Two /128s covered by a /127 should be deduplicated."
    );
}

#[test]
fn test_deduplicate_ipv6_supernet_with_siblings() {
    let subnets = vec![
        "2001:db8:1::/48",
        "2001:db8:2::/48",
        "2001:db8::/32",
    ];

    let deduped: Vec<Ipv6Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv6Network::from_str("2001:db8::/32").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Sibling /48s under same /32 should be removed when supernet is present."
    );
}

#[test]
fn test_deduplicate_ipv6_link_local_and_loopback() {
    let subnets = vec![
        "::1/128",          // Loopback
        "fe80::/10",        // Link-local
        "fe80::1/128",
        "fe80::abcd/64",
    ];

    let deduped: Vec<Ipv6Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv6Network::from_str("fe80::/10").unwrap(),
        Ipv6Network::from_str("::1/128").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "fe80::/10 should absorb all link-local addresses; ::1 should be preserved."
    );
}

#[test]
fn test_deduplicate_ipv6_multicast_and_global() {
    let subnets = vec![
        "ff00::/8",             // Multicast
        "2001:db8::/32",        // Documentation (global unicast)
        "ff02::1/128",          // All nodes
        "ff02::2/128",          // All routers
    ];

    let deduped: Vec<Ipv6Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv6Network::from_str("ff00::/8").unwrap(),
        Ipv6Network::from_str("2001:db8::/32").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Multicast subnets should be absorbed by ff00::/8."
    );
}

#[test]
fn test_deduplicate_ipv4_deeply_nested_subnets() {
    let subnets = vec![
        "10.0.0.0/8",
        "10.0.1.0/24",
        "10.0.1.128/25",
        "10.0.1.64/26",
        "10.0.1.65/32",
    ];

    let deduped: Vec<Ipv4Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv4Network::from_str("10.0.0.0/8").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Nested IPv4 subnets should be absorbed by their /8 supernet."
    );
}

#[test]
fn test_deduplicate_ipv4_multiple_siblings_under_supernet() {
    let subnets = vec![
        "192.168.1.0/24",
        "192.168.2.0/24",
        "192.168.0.0/16",
    ];

    let deduped: Vec<Ipv4Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv4Network::from_str("192.168.0.0/16").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "All /24s under /16 should be eliminated if /16 is present."
    );
}

#[test]
fn test_deduplicate_ipv4_extreme_prefixes() {
    let subnets = vec![
        "192.0.2.0/32",
        "192.0.2.1/32",
        "192.0.2.0/31",
    ];

    let deduped: Vec<Ipv4Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv4Network::from_str("192.0.2.0/31").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Individual /32s should be absorbed by a broader /31 range."
    );
}

#[test]
fn test_deduplicate_ipv4_broadcast_and_special_cases() {
    let subnets = vec![
        "255.255.255.255/32", // broadcast
        "0.0.0.0/0",          // default route
        "192.0.2.0/24",       // test-net-1
    ];

    let deduped: Vec<Ipv4Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv4Network::from_str("0.0.0.0/0").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Any subnet is covered by 0.0.0.0/0 and should be removed if it exists."
    );
}

#[test]
fn test_deduplicate_ipv4_loopback_and_reserved_blocks() {
    let subnets = vec![
        "127.0.0.1/32",     // loopback
        "127.0.0.0/8",      // entire loopback block
        "169.254.0.0/16",   // link-local
        "169.254.1.1/32",
    ];

    let deduped: Vec<Ipv4Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv4Network::from_str("127.0.0.0/8").unwrap(),
        Ipv4Network::from_str("169.254.0.0/16").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "More specific subnets under loopback and link-local should be removed if parent exists."
    );
}

#[test]
fn test_deduplicate_ipv4_mixed_overlap_and_disjoint() {
    let subnets = vec![
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.1.0/24",
        "192.168.0.0/16",
        "8.8.8.0/24",
    ];

    let deduped: Vec<Ipv4Network> = deduplicate(parse_subnets(subnets));

    let expected = vec![
        Ipv4Network::from_str("10.0.0.0/8").unwrap(),
        Ipv4Network::from_str("172.16.0.0/12").unwrap(),
        Ipv4Network::from_str("192.168.0.0/16").unwrap(),
        Ipv4Network::from_str("8.8.8.0/24").unwrap(),
    ];

    assert_eq!(
        deduped, expected,
        "Only the broadest covering subnets should remain after deduplication."
    );
}
