//! The real [`DnsSystem`]: reads adapters with the IP Helper API and their
//! DNS settings from the registry, and changes them with `netsh` (the same
//! as Settings > Network > Edit DNS). Changing them needs administrator
//! rights, which the service has.

use crate::switch::{AdapterDns, DnsSystem};
use std::net::IpAddr;

pub struct WindowsDns;

const V4_KEY: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
const V6_KEY: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";

/// Registry lists are separated by commas or spaces.
fn parse_list(text: &str) -> Vec<IpAddr> {
    text.split([',', ' ']).filter_map(|s| s.trim().parse().ok()).collect()
}

fn reg_list(base: &str, id: &str, value: &str) -> Vec<IpAddr> {
    windows_registry::LOCAL_MACHINE
        .open(format!(r"{base}\{id}"))
        .and_then(|k| k.get_string(value))
        .map(|v| parse_list(&v))
        .unwrap_or_default()
}

impl DnsSystem for WindowsDns {
    fn adapters(&self) -> Vec<AdapterDns> {
        let Ok(adapters) = ipconfig::get_adapters() else { return Vec::new() };
        adapters
            .into_iter()
            .filter(|a| {
                a.oper_status() == ipconfig::OperStatus::IfOperStatusUp
                    && a.if_type() != ipconfig::IfType::SoftwareLoopback
                    // Without a gateway it reaches no network (virtual switches, host-only adapters).
                    && !a.gateways().is_empty()
            })
            .map(|a| {
                let id = a.adapter_name().to_owned();
                let v6_static = reg_list(V6_KEY, &id, "NameServer");
                // Windows does not store IPv6 servers learnt from the router;
                // the adapter's current list is the best source.
                let v6_auto = a
                    .dns_servers()
                    .iter()
                    .copied()
                    .filter(|ip| ip.is_ipv6() && !v6_static.contains(ip))
                    .collect();
                AdapterDns {
                    v4_static: reg_list(V4_KEY, &id, "NameServer"),
                    v4_auto: reg_list(V4_KEY, &id, "DhcpNameServer"),
                    v6_static,
                    v6_auto,
                    index: a.ipv6_if_index(),
                    name: a.friendly_name().to_owned(),
                    id,
                }
            })
            .collect()
    }

    fn set(&self, index: u32, ipv6: bool, servers: &[IpAddr]) -> Result<(), String> {
        if index == 0 {
            return Err("the adapter has no interface number".into());
        }
        let family = if ipv6 { "ipv6" } else { "ipv4" };
        let name = format!("name={index}");
        match servers.split_first() {
            None => netsh(&["interface", family, "set", "dnsservers", &name, "source=dhcp"]),
            Some((first, rest)) => {
                netsh(&[
                    "interface",
                    family,
                    "set",
                    "dnsservers",
                    &name,
                    "source=static",
                    &format!("address={first}"),
                    "register=primary",
                    "validate=no",
                ])?;
                for (i, ip) in rest.iter().enumerate() {
                    netsh(&[
                        "interface",
                        family,
                        "add",
                        "dnsservers",
                        &name,
                        &format!("address={ip}"),
                        &format!("index={}", i + 2),
                        "validate=no",
                    ])?;
                }
                Ok(())
            }
        }
    }
}

fn netsh(args: &[&str]) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("netsh")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    // netsh reports most errors on stdout, sometimes with exit code 0.
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let lower = text.to_lowercase();
    if out.status.success() && !lower.contains("error") && !lower.contains("denied") {
        Ok(())
    } else {
        Err(if text.is_empty() { String::from_utf8_lossy(&out.stderr).trim().to_owned() } else { text })
    }
}

#[cfg(test)]
mod tests {
    use super::parse_list;

    /// Lists this PC's adapters (read-only). Run with `--ignored --nocapture`.
    #[test]
    #[ignore = "reads the real network setup"]
    fn lists_this_pcs_adapters() {
        use crate::switch::DnsSystem;
        for a in super::WindowsDns.adapters() {
            println!(
                "{} (index {}): typed-in v4 {:?}, automatic v4 {:?}, typed-in v6 {:?}, other v6 {:?}",
                a.name, a.index, a.v4_static, a.v4_auto, a.v6_static, a.v6_auto
            );
        }
    }

    #[test]
    fn parses_registry_server_lists() {
        assert_eq!(parse_list("192.168.1.1 8.8.8.8").len(), 2);
        assert_eq!(parse_list("9.9.9.9,149.112.112.112").len(), 2);
        assert!(parse_list("").is_empty());
    }
}
