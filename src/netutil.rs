// src/netutil.rs
// Shared IP/CIDR helpers used by configuration and the firewall.

use std::net::IpAddr;

use ipnet::IpNet;

/// Parse a strict IP address (no hostnames, no ports).
pub fn parse_ip(value: &str) -> Option<IpAddr> {
    value.trim().parse().ok()
}

/// True for loopback, RFC1918, link-local and other non-routable addresses.
/// These must never be banned or treated as remote attackers.
pub fn is_internal_ip(value: &str) -> bool {
    if value.eq_ignore_ascii_case("localhost") {
        return true;
    }

    match parse_ip(value) {
        Some(IpAddr::V4(ip)) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
        }
        Some(IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
        None => false,
    }
}

/// Parse either `10.0.0.0/8` or a bare `10.0.0.1` (treated as a /32 or /128).
pub fn parse_net(value: &str) -> Option<IpNet> {
    let value = value.trim();
    if let Ok(net) = value.parse::<IpNet>() {
        return Some(net);
    }
    parse_ip(value).map(IpNet::from)
}

/// True when `value` is a valid IP contained in at least one of `nets`.
pub fn ip_in_any_net(value: &str, nets: &[IpNet]) -> bool {
    match parse_ip(value) {
        Some(addr) => nets.iter().any(|net| net.contains(&addr)),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_ranges_are_detected() {
        assert!(is_internal_ip("127.0.0.1"));
        assert!(is_internal_ip("10.1.2.3"));
        assert!(is_internal_ip("172.16.0.1"));
        assert!(is_internal_ip("192.168.1.10"));
        assert!(is_internal_ip("169.254.1.1"));
        assert!(is_internal_ip("::1"));
        assert!(!is_internal_ip("203.0.113.10"));
    }

    #[test]
    fn cidr_and_bare_ip_match() {
        let nets = vec![
            parse_net("192.168.1.0/24").unwrap(),
            parse_net("203.0.113.7").unwrap(),
        ];
        assert!(ip_in_any_net("192.168.1.55", &nets));
        assert!(ip_in_any_net("203.0.113.7", &nets));
        assert!(!ip_in_any_net("203.0.113.8", &nets));
        assert!(!ip_in_any_net("not-an-ip", &nets));
    }
}
