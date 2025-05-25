use nftables::expr::{Expression, NamedExpression, Prefix};
use nftblockd::anti_lockout::AntiLockoutSet;
use nftblockd::error::{AppError, AppErrorKind};
use std::borrow::Cow;

#[test]
fn test_valid_anti_lockout_set() {
    let subnets = "192.168.1.0/24 192.168.0.0/16".to_string();

    let actual = AntiLockoutSet::IPv4(subnets).build_anti_lockout().unwrap();

    // Expected subnets after deduplication:
    let expected = vec![Expression::Named(NamedExpression::Prefix(Prefix {
        addr: Box::new(Expression::String(Cow::from("192.168.0.0"))),
        len: 16,
    }))];
    assert_eq!(
        actual, expected,
        "The deduplicated subnets did not match the expected list."
    );
}

#[test]
fn test_anti_lockout_set_not_network() {
    let subnets = "192.168.1.0 192.168.0.2/16".to_string();

    let actual = AntiLockoutSet::IPv4(subnets)
        .build_anti_lockout()
        .unwrap_err();

    // Expected subnets after deduplication:
    let expected = AppError::new(
        AppErrorKind::ParseError,
        "invalid ip: 192.168.0.2/16; not a network",
    );
    assert_eq!(
        actual, expected,
        "The deduplicated subnets did not match the expected list."
    );
}

#[test]
fn test_empty_anti_lockout_set() {
    let subnets = "".to_string();

    let err = AntiLockoutSet::IPv4(subnets)
        .build_anti_lockout()
        .unwrap_err();

    // Expected subnets after deduplication:
    let expected = AppError::new(
        AppErrorKind::NoAddressesParsedError,
        "the blocklist is empty after parsing",
    );
    assert_eq!(
        err, expected,
        "The deduplicated subnets did not match the expected list."
    );
}

#[test]
fn test_empty_anti_lockout_set_after_parsing() {
    let subnets = "192.168.1.3/24 300.300.300.300/32".to_string();

    let err = AntiLockoutSet::IPv4(subnets)
        .build_anti_lockout()
        .unwrap_err();

    // Expected subnets after deduplication:
    let expected = AppError::new(
        AppErrorKind::ParseError,
        "invalid ip: 192.168.1.3/24; not a network",
    );
    assert_eq!(
        err, expected,
        "The deduplicated subnets did not match the expected list."
    );
}

#[test]
fn test_valid_mixed_ipv4_set_deduplicated() {
    let subnets = "10.0.0.0/8 10.0.0.1/32 10.1.0.0/16".to_string();

    let actual = AntiLockoutSet::IPv4(subnets).build_anti_lockout().unwrap();

    let expected = vec![Expression::Named(NamedExpression::Prefix(Prefix {
        addr: Box::new(Expression::String(Cow::from("10.0.0.0"))),
        len: 8,
    }))];

    assert_eq!(actual, expected, "Nested subnets should be deduplicated.");
}

#[test]
fn test_ipv4_with_invalid_ip() {
    let subnets = "192.168.1.0/24 300.300.300.300/32".to_string();

    let actual = AntiLockoutSet::IPv4(subnets)
        .build_anti_lockout()
        .unwrap_err();

    let expected = AppError::new(
        AppErrorKind::ParseError,
        "invalid address: invalid IPv4 address syntax",
    );

    assert_eq!(actual, expected, "Nested subnets should be deduplicated.");
}

#[test]
fn test_ipv4_with_invalid_cidr() {
    let subnets = "192.168.1.0/24 10.0.0.0/33".to_string(); // /33 invalid for IPv4

    let actual = AntiLockoutSet::IPv4(subnets)
        .build_anti_lockout()
        .unwrap_err();

    let expected = AppError::new(AppErrorKind::ParseError, "invalid prefix");

    assert_eq!(actual, expected, "Nested subnets should be deduplicated.");
}

#[test]
fn test_ipv4_with_malformed_input() {
    let subnets = "foobar 10.0.0.0/8 baz/24".to_string();

    let actual = AntiLockoutSet::IPv4(subnets)
        .build_anti_lockout()
        .unwrap_err();

    let expected = AppError::new(
        AppErrorKind::ParseError,
        "invalid address: invalid IPv4 address syntax",
    );

    assert_eq!(actual, expected, "Nested subnets should be deduplicated.");
}

#[test]
fn test_ipv4_with_only_invalid_entries() {
    let subnets = "xyz 256.256.256.256/24 /32 blah".to_string();

    let actual = AntiLockoutSet::IPv4(subnets)
        .build_anti_lockout()
        .unwrap_err();

    let expected = AppError::new(
        AppErrorKind::ParseError,
        "invalid address: invalid IPv4 address syntax",
    );

    assert_eq!(
        actual, expected,
        "Only invalid entries should return a parsing error."
    );
}

#[test]
fn test_ipv4_with_valid_entries() {
    let subnets = "10.0.0.0/8 192.168.0.0/16 100.90.0.1".to_string();

    let actual = AntiLockoutSet::IPv4(subnets).build_anti_lockout().unwrap();

    let expected = vec![
        Expression::Named(NamedExpression::Prefix(Prefix {
            addr: Box::new(Expression::String(Cow::from("10.0.0.0"))),
            len: 8,
        })),
        Expression::Named(NamedExpression::Prefix(Prefix {
            addr: Box::new(Expression::String(Cow::from("192.168.0.0"))),
            len: 16,
        })),
        Expression::Named(NamedExpression::Prefix(Prefix {
            addr: Box::new(Expression::String(Cow::from("100.90.0.1"))),
            len: 32,
        })),
    ];

    assert_eq!(actual, expected, "Only valid subnet should be included.");
}

#[test]
fn test_ipv4_only_loopback_and_zero() {
    let subnets = "127.0.0.1/32 0.0.0.0/0".to_string();

    let actual = AntiLockoutSet::IPv4(subnets).build_anti_lockout().unwrap();

    let expected = vec![Expression::Named(NamedExpression::Prefix(Prefix {
        addr: Box::new(Expression::String(Cow::from("0.0.0.0"))),
        len: 0,
    }))];

    assert_eq!(
        actual, expected,
        "Loopback should be eliminated if 0.0.0.0/0 exists."
    );
}

#[test]
fn test_valid_ipv6_anti_lockout_set() {
    let subnets = "2001:db8::/32 2001:db8:1::/48".to_string();

    let actual = AntiLockoutSet::IPv6(subnets).build_anti_lockout().unwrap();

    let expected = vec![Expression::Named(NamedExpression::Prefix(Prefix {
        addr: Box::new(Expression::String(Cow::from("2001:db8::"))),
        len: 32,
    }))];

    assert_eq!(actual, expected, "IPv6 subnets should be deduplicated.");
}

#[test]
fn test_ipv6_anti_lockout_set_not_network() {
    let subnets = "2001:db8::/32 2001:db8::1/48".to_string();

    let actual = AntiLockoutSet::IPv6(subnets)
        .build_anti_lockout()
        .unwrap_err();

    let expected = AppError::new(
        AppErrorKind::ParseError,
        "invalid ip: 2001:db8::1/48; not a network",
    );

    assert_eq!(
        actual, expected,
        "Should keep only the valid network-aligned prefix."
    );
}

#[test]
fn test_empty_ipv6_anti_lockout_set() {
    let subnets = "".to_string();

    let err = AntiLockoutSet::IPv6(subnets)
        .build_anti_lockout()
        .unwrap_err();

    let expected = AppError::new(
        AppErrorKind::NoAddressesParsedError,
        "the blocklist is empty after parsing",
    );

    assert_eq!(err, expected, "Empty input should trigger a parsing error.");
}

#[test]
fn test_ipv6_with_invalid_address() {
    let subnets = "2001:db8::/32 not_an_ip".to_string();

    let actual = AntiLockoutSet::IPv6(subnets)
        .build_anti_lockout()
        .unwrap_err();

    let expected = AppError::new(
        AppErrorKind::ParseError,
        "invalid address: invalid IPv6 address syntax",
    );

    assert_eq!(actual, expected, "Invalid addresses should be ignored.");
}

#[test]
fn test_ipv6_with_valid_cidr() {
    let subnets = "2001:db8::/128 2001:db8:abcd::/48".to_string();

    let actual = AntiLockoutSet::IPv6(subnets).build_anti_lockout().unwrap();

    let expected = vec![
        Expression::Named(NamedExpression::Prefix(Prefix {
            addr: Box::new(Expression::String(Cow::from("2001:db8:abcd::"))),
            len: 48,
        })),
        Expression::Named(NamedExpression::Prefix(Prefix {
            addr: Box::new(Expression::String(Cow::from("2001:db8::"))),
            len: 128,
        })),
    ];

    assert_eq!(actual, expected, "Invalid CIDR (>128) should be ignored.");
}

#[test]
fn test_ipv6_with_malformed_input() {
    let subnets = "foobar 2001:db8::/32 ::1/129".to_string();

    let actual = AntiLockoutSet::IPv6(subnets).build_anti_lockout().unwrap_err();

    let expected = AppError::new(
        AppErrorKind::ParseError,
        "invalid address: invalid IPv6 address syntax",
    );

    assert_eq!(
        actual, expected,
        "Only valid IPv6 CIDRs should be retained."
    );
}

#[test]
fn test_ipv6_with_only_invalid_entries() {
    let subnets = "xyz ::g/64 2001:db8::/999".to_string();

    let err = AntiLockoutSet::IPv6(subnets)
        .build_anti_lockout()
        .unwrap_err();

    let expected = AppError::new(
        AppErrorKind::ParseError,
        "invalid address: invalid IPv6 address syntax",
    );

    assert_eq!(err, expected, "All invalid entries should lead to error.");
}

#[test]
fn test_ipv6_with_partial_invalid_entries() {
    let subnets = "2001:4860:4860::/64 ::1/129".to_string();

    let actual = AntiLockoutSet::IPv6(subnets).build_anti_lockout().unwrap_err();

    let expected = AppError::new(
        AppErrorKind::ParseError,
        "invalid prefix",
    );

    assert_eq!(
        actual, expected,
        "Only valid IPv6 addresses should be returned."
    );
}

#[test]
fn test_ipv6_loopback_and_full_block() {
    let subnets = "::1 ::/0".to_string();

    let actual = AntiLockoutSet::IPv6(subnets).build_anti_lockout().unwrap();

    let expected = vec![Expression::Named(NamedExpression::Prefix(Prefix {
        addr: Box::new(Expression::String(Cow::from("::"))),
        len: 0,
    }))];

    assert_eq!(
        actual, expected,
        "Loopback should be excluded if ::/0 is present."
    );
}
