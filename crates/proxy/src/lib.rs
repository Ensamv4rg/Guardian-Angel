//! Opt-in decrypting HTTPS proxy for desktop apps (FR-20, moved into 1.0).
//!
//! Apps send their HTTPS through this local proxy. Connections from apps the
//! user opted in are decrypted with a certificate from a per-install CA,
//! forwarded to the real server over a verified connection, and their
//! tracker payloads decoded. Everything else is tunnelled untouched. If an
//! app refuses the certificate (pinning), its host is tunnelled from then on.
//!
//! This crate never trusts the CA or changes the system proxy itself: both
//! need the user's consent and are done by the desktop app, as the user.
//! It serves the setup script (`PAC_PATH`) the Windows proxy setting uses.

pub mod ca;
pub mod rules;
mod server;

pub use ca::{CA_COMMON_NAME, CaError, CertAuthority};
pub use rules::{Rules, TrackerHosts};
pub use server::{AppId, AppResolver, InspectedRequest, PAC_PATH, Proxy, ProxyConfig, ProxyEvent, UpstreamTrust, pac_script};

/// Resolves which program opened a proxy connection, using Windows' TCP
/// connection table. Returns the executable name, e.g. `Discord.exe`.
#[cfg(windows)]
pub fn windows_app_resolver() -> AppResolver {
    use std::net::SocketAddr;
    std::sync::Arc::new(|client: SocketAddr, proxy: SocketAddr| {
        let (SocketAddr::V4(client), SocketAddr::V4(proxy)) = (client, proxy) else { return None };
        let pid = ga_platform_win::tcp_connection_owner(client, proxy)?;
        let path = ga_platform_win::process_image_path(pid)?;
        Some(server::AppId {
            exe: path.rsplit('\\').next().unwrap_or(&path).to_owned(),
            user: ga_platform_win::process_user_sid(pid),
        })
    })
}

#[cfg(test)]
mod tests;
