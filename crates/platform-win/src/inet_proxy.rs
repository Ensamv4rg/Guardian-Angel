//! The signed-in user's Windows proxy setting (Settings > Network > Proxy),
//! read and changed the way Internet Options does it, then announced so
//! running apps pick it up. Applies to the LAN/Wi-Fi connection; dial-up and
//! VPN connections keep their own settings.

use std::io;
use windows::Win32::Foundation::{GlobalFree, HGLOBAL};
use windows::Win32::Networking::WinInet::{
    INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    INTERNET_PER_CONN, INTERNET_PER_CONN_AUTOCONFIG_URL, INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_OPTION_LISTW,
    INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER, InternetQueryOptionW,
    InternetSetOptionW,
};
use windows::core::PWSTR;

pub use windows::Win32::Networking::WinInet::{PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY};

/// One connection's proxy setting.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxySetting {
    /// `PROXY_TYPE_*` bits; `PROXY_TYPE_DIRECT` alone means no proxy.
    pub flags: u32,
    /// "host:port" when `PROXY_TYPE_PROXY` is set.
    pub server: Option<String>,
    pub bypass: Option<String>,
    /// Setup script address when `PROXY_TYPE_AUTO_PROXY_URL` is set.
    pub script_url: Option<String>,
}

fn option(kind: INTERNET_PER_CONN) -> INTERNET_PER_CONN_OPTIONW {
    INTERNET_PER_CONN_OPTIONW {
        dwOption: kind,
        ..Default::default()
    }
}

/// Takes ownership of a string WinInet allocated and frees it.
fn take_string(p: PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: WinInet returned a valid, NUL-terminated string allocated with
    // GlobalAlloc; it is read once and then freed exactly once.
    let text = unsafe { p.to_string() }.ok();
    // SAFETY: as above; the pointer is not used after this.
    let _ = unsafe { GlobalFree(Some(HGLOBAL(p.0.cast()))) };
    text.filter(|t| !t.is_empty())
}

pub fn current_proxy() -> io::Result<ProxySetting> {
    let mut options = [
        option(INTERNET_PER_CONN_FLAGS),
        option(INTERNET_PER_CONN_PROXY_SERVER),
        option(INTERNET_PER_CONN_PROXY_BYPASS),
        option(INTERNET_PER_CONN_AUTOCONFIG_URL),
    ];
    let mut list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: PWSTR::null(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };
    let mut size = size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32;
    // SAFETY: `list` points at `options`, both live for the call; `size` is
    // the size of `list`. A null handle means the process-wide settings.
    unsafe {
        InternetQueryOptionW(
            None,
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            Some(std::ptr::from_mut(&mut list).cast()),
            &mut size,
        )
    }
    .map_err(io::Error::other)?;
    // SAFETY: WinInet filled each union with the member its option uses:
    // a number for FLAGS, strings for the others.
    unsafe {
        Ok(ProxySetting {
            flags: options[0].Value.dwValue,
            server: take_string(options[1].Value.pszValue),
            bypass: take_string(options[2].Value.pszValue),
            script_url: take_string(options[3].Value.pszValue),
        })
    }
}

pub fn set_proxy(setting: &ProxySetting) -> io::Result<()> {
    let wide = |s: &Option<String>| -> Vec<u16> { s.as_deref().unwrap_or("").encode_utf16().chain([0]).collect() };
    let (mut server, mut bypass, mut script) = (wide(&setting.server), wide(&setting.bypass), wide(&setting.script_url));
    let mut options = [
        option(INTERNET_PER_CONN_FLAGS),
        option(INTERNET_PER_CONN_PROXY_SERVER),
        option(INTERNET_PER_CONN_PROXY_BYPASS),
        option(INTERNET_PER_CONN_AUTOCONFIG_URL),
    ];
    options[0].Value.dwValue = setting.flags;
    options[1].Value.pszValue = PWSTR(server.as_mut_ptr());
    options[2].Value.pszValue = PWSTR(bypass.as_mut_ptr());
    options[3].Value.pszValue = PWSTR(script.as_mut_ptr());
    let list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: PWSTR::null(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    };
    // SAFETY: `list`, `options` and the three NUL-terminated buffers live
    // until after the calls; WinInet copies what it keeps.
    unsafe {
        InternetSetOptionW(
            None,
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            Some(std::ptr::from_ref(&list).cast()),
            size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        )
        .map_err(io::Error::other)?;
        // Tell running apps the setting changed, and reload it here.
        let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
        let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
    }
    Ok(())
}
