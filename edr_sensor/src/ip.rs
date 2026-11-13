//! Python 3.10 `ipaddress` `.is_global` semantics (the builder ran on 3.10).
//! std's `IpAddr::is_global` is unstable and uses a different table.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4_in(ip: Ipv4Addr, net: [u8; 4], prefix: u32) -> bool {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    (u32::from(ip) & mask) == (u32::from(Ipv4Addr::from(net)) & mask)
}

fn v6_in(ip: Ipv6Addr, net: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

fn v4_private(ip: Ipv4Addr) -> bool {
    const NETS: &[([u8; 4], u32)] = &[
        ([0, 0, 0, 0], 8), ([10, 0, 0, 0], 8), ([127, 0, 0, 0], 8), ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12), ([192, 0, 0, 0], 29), ([192, 0, 0, 170], 31), ([192, 0, 2, 0], 24),
        ([192, 168, 0, 0], 16), ([198, 18, 0, 0], 15), ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24), ([240, 0, 0, 0], 4), ([255, 255, 255, 255], 32),
    ];
    NETS.iter().any(|&(n, p)| v4_in(ip, n, p))
}

fn v6_private(ip: Ipv6Addr) -> bool {
    const NETS: &[(&str, u32)] = &[
        ("::1", 128), ("::", 128), ("::ffff:0:0", 96), ("100::", 64), ("2001::", 23),
        ("2001:2::", 48), ("2001:db8::", 32), ("2001:10::", 28), ("fc00::", 7), ("fe80::", 10),
    ];
    NETS.iter().any(|&(n, p)| v6_in(ip, n.parse().unwrap(), p))
}

/// `Some(is_global)`, or `None` when the string is not an IP address.
pub fn is_global(s: &str) -> Option<bool> {
    // Python accepts an IPv6 scope id ("fe80::1%eth0"); it does not change the result.
    let addr = match s.split_once('%') {
        Some((a, _)) if a.contains(':') => a,
        _ => s,
    };
    match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => Some(!v4_in(v4, [100, 64, 0, 0], 10) && !v4_private(v4)),
        IpAddr::V6(v6) => Some(!v6_private(v6)),
    }
}

#[cfg(test)]
mod tests {
    use super::is_global;

    #[test]
    fn matches_python_310() {
        assert_eq!(is_global("8.8.8.8"), Some(true));
        assert_eq!(is_global("10.1.2.3"), Some(false));
        assert_eq!(is_global("192.168.0.5"), Some(false));
        assert_eq!(is_global("100.64.1.1"), Some(false));
        assert_eq!(is_global("224.0.0.251"), Some(true)); // multicast is "global" in 3.10
        assert_eq!(is_global("fe80::1%12"), Some(false));
        assert_eq!(is_global("2606:4700::1111"), Some(true));
        assert_eq!(is_global("0"), None);
        assert_eq!(is_global(""), None);
    }
}
