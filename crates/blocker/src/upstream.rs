//! The DNS servers Windows is currently using, so the resolver forwards to
//! the same place (a home router, a company or school DNS server) instead of
//! a hardcoded public resolver.

use std::net::{IpAddr, SocketAddr};

/// DNS servers of every connected network adapter, in adapter order, without
/// duplicates. Loopback servers are skipped: once Windows points at this
/// resolver, they would be the resolver itself.
pub fn system_upstreams() -> Vec<SocketAddr> {
    let mut found: Vec<SocketAddr> = Vec::new();
    let Ok(adapters) = ipconfig::get_adapters() else { return found };
    for adapter in adapters {
        if adapter.oper_status() != ipconfig::OperStatus::IfOperStatusUp {
            continue;
        }
        for ip in adapter.dns_servers() {
            let addr = SocketAddr::new(*ip, 53);
            if usable(*ip) && !found.contains(&addr) {
                found.push(addr);
            }
        }
    }
    found
}

fn usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified(),
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            // Link-local needs a scope ID we do not carry; fec0::/10 is the
            // deprecated placeholder Windows lists on adapters without IPv6 DNS.
            !v6.is_loopback() && !v6.is_unspecified() && (first & 0xffc0) != 0xfe80 && (first & 0xffc0) != 0xfec0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::usable;

    #[test]
    fn filters_unusable_servers() {
        assert!(usable("10.193.47.235".parse().unwrap()));
        assert!(usable("2606:4700:4700::1111".parse().unwrap()));
        assert!(!usable("127.0.0.1".parse().unwrap()));
        assert!(!usable("::1".parse().unwrap()));
        assert!(!usable("fe80::1".parse().unwrap()));
        assert!(!usable("fec0:0:0:ffff::1".parse().unwrap()));
    }
}
