//! Pointing Windows at the blocking resolver, and back.
//!
//! Each connected adapter's DNS setting is recorded before it is changed, so
//! it can be put back exactly: the servers someone typed in, or "automatic"
//! (from the router). The original server stays second in the list, so if
//! the resolver ever stops answering, Windows falls back to it and the
//! internet keeps working. Blocked names are answered (with 0.0.0.0), so they
//! never fall through to the second server.
//!
//! The Windows side is behind [`DnsSystem`] so this logic is tested without
//! touching the real network settings.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const RESOLVER_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
pub const RESOLVER_V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

/// One network adapter's DNS setup as Windows has it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterDns {
    /// Stable ID (`{GUID}`).
    pub id: String,
    /// Interface index, for `netsh`.
    pub index: u32,
    /// "Wi-Fi", "Ethernet".
    pub name: String,
    /// Servers typed in by hand; empty means "automatic".
    pub v4_static: Vec<IpAddr>,
    pub v6_static: Vec<IpAddr>,
    /// Servers the network handed out (used when the setting is automatic).
    pub v4_auto: Vec<IpAddr>,
    pub v6_auto: Vec<IpAddr>,
}

impl AdapterDns {
    fn v4_effective(&self) -> &[IpAddr] {
        if self.v4_static.is_empty() { &self.v4_auto } else { &self.v4_static }
    }
    fn v6_effective(&self) -> &[IpAddr] {
        if self.v6_static.is_empty() { &self.v6_auto } else { &self.v6_static }
    }
}

/// What an adapter looked like before Guardian Angel changed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterSnapshot {
    pub id: String,
    pub index: u32,
    pub name: String,
    pub v4_static: Vec<IpAddr>,
    pub v6_static: Vec<IpAddr>,
    /// The IPv6 setting was changed too (the adapter used IPv6 DNS).
    pub v6_changed: bool,
    /// The fallback servers put second, to notice when the network changes.
    #[serde(default)]
    pub v4_fallback: Option<IpAddr>,
    #[serde(default)]
    pub v6_fallback: Option<IpAddr>,
}

pub trait DnsSystem {
    /// Connected adapters that can reach a network.
    fn adapters(&self) -> Vec<AdapterDns>;
    /// Sets an adapter's DNS servers for one IP version; an empty list means
    /// "automatic".
    fn set(&self, index: u32, ipv6: bool, servers: &[IpAddr]) -> Result<(), String>;
}

/// Can be used as an upstream or backup server. IPv6 link-local addresses
/// (`fe80::`, what many routers hand out) need an interface scope that a
/// plain server list cannot carry.
fn usable(ip: &IpAddr) -> bool {
    let link_local = match ip {
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80 || (v6.segments()[0] & 0xffc0) == 0xfec0,
        IpAddr::V4(_) => false,
    };
    !ip.is_loopback() && !ip.is_unspecified() && !link_local
}

/// An adapter already pointing at the resolver (left over after a crash
/// lost the snapshot) was set up by us; its original setting is taken to be
/// "automatic", never our own address.
fn original(static_servers: &[IpAddr], resolver: IpAddr) -> Vec<IpAddr> {
    if static_servers.first() == Some(&resolver) {
        Vec::new()
    } else {
        static_servers.to_vec()
    }
}

fn first_usable(list: &[IpAddr]) -> Option<IpAddr> {
    list.iter().copied().find(usable)
}

/// Points every connected adapter not yet in `pointed` at the resolver and
/// records it there. `ipv6` says whether the resolver also listens on `::1`.
/// If an adapter cannot be changed, the ones changed in this call are put
/// back and the error is returned.
pub fn point_at_resolver(sys: &dyn DnsSystem, ipv6: bool, pointed: &mut Vec<AdapterSnapshot>) -> Result<(), String> {
    let mut done: Vec<AdapterSnapshot> = Vec::new();
    for adapter in sys.adapters() {
        if pointed.iter().any(|p| p.id == adapter.id) {
            continue;
        }
        let v4_fallback = first_usable(adapter.v4_effective());
        let v6_fallback = first_usable(adapter.v6_effective());
        // Any IPv6 DNS server (even one we cannot use as a backup) would let
        // lookups bypass blocking, so IPv6 is pointed at the resolver too.
        let v6_changed = ipv6 && !adapter.v6_effective().is_empty();
        let snap = AdapterSnapshot {
            id: adapter.id.clone(),
            index: adapter.index,
            name: adapter.name.clone(),
            v4_static: original(&adapter.v4_static, RESOLVER_V4),
            v6_static: original(&adapter.v6_static, RESOLVER_V6),
            v6_changed,
            v4_fallback,
            v6_fallback,
        };
        let v4: Vec<IpAddr> = std::iter::once(RESOLVER_V4).chain(v4_fallback).collect();
        let mut result = sys.set(adapter.index, false, &v4);
        if result.is_ok() && v6_changed {
            let v6: Vec<IpAddr> = std::iter::once(RESOLVER_V6).chain(v6_fallback).collect();
            result = sys.set(adapter.index, true, &v6);
            if result.is_err() {
                let _ = sys.set(adapter.index, false, &snap.v4_static);
            }
        }
        if let Err(e) = result {
            restore(sys, &done);
            return Err(format!("Could not change the DNS setting of {}: {e}", adapter.name));
        }
        done.push(snap);
    }
    pointed.extend(done);
    Ok(())
}

/// Puts adapters back as they were. Returns the ones that could not be
/// restored (still connected but the change failed) so they can be retried.
pub fn restore(sys: &dyn DnsSystem, snaps: &[AdapterSnapshot]) -> Vec<AdapterSnapshot> {
    let present: Vec<AdapterDns> = sys.adapters();
    let mut failed = Vec::new();
    for snap in snaps {
        // An adapter that is gone (unplugged dongle) is restored by index
        // anyway; Windows keeps its settings for when it returns.
        let index = present.iter().find(|a| a.id == snap.id).map_or(snap.index, |a| a.index);
        let mut ok = sys.set(index, false, &snap.v4_static).is_ok();
        if snap.v6_changed {
            ok &= sys.set(index, true, &snap.v6_static).is_ok();
        }
        if !ok && present.iter().any(|a| a.id == snap.id) {
            failed.push(snap.clone());
        }
    }
    failed
}

/// Where the resolver should forward: each pointed adapter's original
/// servers, or for automatic ones what the current network hands out (so
/// moving to another Wi-Fi keeps working). IPv4 first.
pub fn upstreams(sys: &dyn DnsSystem, pointed: &[AdapterSnapshot]) -> Vec<SocketAddr> {
    let adapters = sys.adapters();
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for snap in pointed {
        let current = adapters.iter().find(|a| a.id == snap.id);
        let auto4 = current.map(|a| a.v4_auto.clone()).unwrap_or_default();
        let auto6 = current.map(|a| a.v6_auto.clone()).unwrap_or_default();
        v4.extend(if snap.v4_static.is_empty() { auto4 } else { snap.v4_static.clone() });
        v6.extend(if snap.v6_static.is_empty() { auto6 } else { snap.v6_static.clone() });
    }
    let mut out: Vec<SocketAddr> = Vec::new();
    for ip in v4.into_iter().chain(v6).filter(usable) {
        let addr = SocketAddr::new(ip, 53);
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// Adapters whose network now hands out other DNS servers than the
/// fallback recorded for them (the PC joined another network). Re-pointing
/// them keeps the fallback useful.
pub fn stale_fallbacks(sys: &dyn DnsSystem, pointed: &[AdapterSnapshot]) -> Vec<String> {
    let adapters = sys.adapters();
    pointed
        .iter()
        .filter(|snap| {
            adapters.iter().any(|a| {
                a.id == snap.id
                    && snap.v4_static.is_empty()
                    && first_usable(&a.v4_auto).is_some()
                    && first_usable(&a.v4_auto) != snap.v4_fallback
            })
        })
        .map(|snap| snap.id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Fake Windows: adapters and the DNS servers set on each (index, ipv6).
    #[derive(Default)]
    struct Fake {
        adapters: RefCell<Vec<AdapterDns>>,
        set: RefCell<HashMap<(u32, bool), Vec<IpAddr>>>,
        fail_index: Option<u32>,
    }

    impl DnsSystem for Fake {
        fn adapters(&self) -> Vec<AdapterDns> {
            self.adapters.borrow().clone()
        }
        fn set(&self, index: u32, ipv6: bool, servers: &[IpAddr]) -> Result<(), String> {
            if self.fail_index == Some(index) {
                return Err("access denied".into());
            }
            self.set.borrow_mut().insert((index, ipv6), servers.to_vec());
            Ok(())
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn wifi() -> AdapterDns {
        AdapterDns {
            id: "{wifi}".into(),
            index: 7,
            name: "Wi-Fi".into(),
            v4_static: vec![],
            v6_static: vec![],
            v4_auto: vec![ip("192.168.1.1")],
            v6_auto: vec![ip("2001:db8::1")],
        }
    }

    fn ethernet() -> AdapterDns {
        AdapterDns {
            id: "{eth}".into(),
            index: 3,
            name: "Ethernet".into(),
            v4_static: vec![ip("9.9.9.9"), ip("149.112.112.112")],
            v6_static: vec![],
            v4_auto: vec![],
            v6_auto: vec![],
        }
    }

    #[test]
    fn points_adapters_at_the_resolver_with_their_old_server_second() {
        let sys = Fake::default();
        sys.adapters.borrow_mut().extend([wifi(), ethernet()]);
        let mut pointed = Vec::new();
        point_at_resolver(&sys, true, &mut pointed).unwrap();

        let set = sys.set.borrow();
        assert_eq!(set[&(7, false)], [RESOLVER_V4, ip("192.168.1.1")]);
        assert_eq!(set[&(7, true)], [RESOLVER_V6, ip("2001:db8::1")]);
        assert_eq!(set[&(3, false)], [RESOLVER_V4, ip("9.9.9.9")]);
        assert!(!set.contains_key(&(3, true)), "no IPv6 DNS before, so IPv6 is left alone");
        assert_eq!(pointed.len(), 2);

        // Running again changes nothing new.
        drop(set);
        point_at_resolver(&sys, true, &mut pointed).unwrap();
        assert_eq!(pointed.len(), 2);
    }

    #[test]
    fn restore_puts_back_automatic_and_typed_in_servers() {
        let sys = Fake::default();
        sys.adapters.borrow_mut().extend([wifi(), ethernet()]);
        let mut pointed = Vec::new();
        point_at_resolver(&sys, true, &mut pointed).unwrap();
        assert!(restore(&sys, &pointed).is_empty());

        let set = sys.set.borrow();
        assert_eq!(set[&(7, false)], Vec::<IpAddr>::new(), "automatic again");
        assert_eq!(set[&(7, true)], Vec::<IpAddr>::new());
        assert_eq!(set[&(3, false)], [ip("9.9.9.9"), ip("149.112.112.112")]);
    }

    #[test]
    fn a_failure_undoes_the_adapters_already_changed() {
        let sys = Fake {
            fail_index: Some(3),
            ..Fake::default()
        };
        sys.adapters.borrow_mut().extend([wifi(), ethernet()]);
        let mut pointed = Vec::new();
        let err = point_at_resolver(&sys, false, &mut pointed).unwrap_err();
        assert!(err.contains("Ethernet"));
        assert!(pointed.is_empty());
        assert_eq!(sys.set.borrow()[&(7, false)], Vec::<IpAddr>::new(), "Wi-Fi put back");
    }

    #[test]
    fn leftover_resolver_setting_is_never_taken_as_the_original() {
        let sys = Fake::default();
        let mut leftover = wifi();
        leftover.v4_static = vec![RESOLVER_V4, ip("192.168.1.1")];
        sys.adapters.borrow_mut().push(leftover);
        let mut pointed = Vec::new();
        point_at_resolver(&sys, false, &mut pointed).unwrap();
        assert!(pointed[0].v4_static.is_empty());
        restore(&sys, &pointed);
        assert_eq!(sys.set.borrow()[&(7, false)], Vec::<IpAddr>::new());
    }

    #[test]
    fn link_local_ipv6_servers_are_covered_but_never_used_as_backup() {
        let sys = Fake::default();
        let mut home = wifi();
        home.v6_auto = vec![ip("fe80::5e4d:bfff:feef:42d9")];
        sys.adapters.borrow_mut().push(home);
        let mut pointed = Vec::new();
        point_at_resolver(&sys, true, &mut pointed).unwrap();
        assert_eq!(sys.set.borrow()[&(7, true)], [RESOLVER_V6], "IPv6 lookups go to the resolver, no unusable backup");
        assert!(pointed[0].v6_changed);
        assert!(upstreams(&sys, &pointed).iter().all(|u| u.is_ipv4()));
        restore(&sys, &pointed);
        assert!(sys.set.borrow()[&(7, true)].is_empty(), "automatic again");
    }

    #[test]
    fn upstreams_follow_the_current_network() {
        let sys = Fake::default();
        sys.adapters.borrow_mut().extend([wifi(), ethernet()]);
        let mut pointed = Vec::new();
        point_at_resolver(&sys, true, &mut pointed).unwrap();
        let ups: Vec<String> = upstreams(&sys, &pointed).iter().map(ToString::to_string).collect();
        assert_eq!(ups, ["192.168.1.1:53", "9.9.9.9:53", "149.112.112.112:53", "[2001:db8::1]:53"]);
        assert!(stale_fallbacks(&sys, &pointed).is_empty());

        // The laptop joins another Wi-Fi: its router is someone else.
        sys.adapters.borrow_mut()[0].v4_auto = vec![ip("10.0.0.1")];
        assert_eq!(upstreams(&sys, &pointed)[0].to_string(), "10.0.0.1:53");
        assert_eq!(stale_fallbacks(&sys, &pointed), ["{wifi}"]);
    }
}
