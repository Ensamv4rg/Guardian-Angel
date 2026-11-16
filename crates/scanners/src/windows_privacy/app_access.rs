//! Which apps may use, and have used, location, camera and microphone.
//!
//! Windows records this under the CapabilityAccessManager "ConsentStore":
//! one subkey per Store app (package family name, with an Allow/Deny value)
//! and, under `NonPackaged`, one subkey per desktop program (its path with
//! `\` replaced by `#`). Both carry FILETIME timestamps of the last use.

use super::registry::{Hive, Registry};
use super::settings::CONSENT_STORE;
use ga_core::{AppAccess, Capability};

const CAPABILITIES: [(Capability, &str); 3] = [
    (Capability::Location, "location"),
    (Capability::Camera, "webcam"),
    (Capability::Microphone, "microphone"),
];

/// Seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01.
const FILETIME_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;

pub fn read_app_access(reg: &dyn Registry) -> Vec<AppAccess> {
    let mut apps = Vec::new();
    for (capability, key) in CAPABILITIES {
        let base = format!(r"{CONSENT_STORE}\{key}");
        for sub in reg.subkeys(Hive::CurrentUser, &base) {
            if sub.eq_ignore_ascii_case("NonPackaged") {
                let np = format!(r"{base}\{sub}");
                for program in reg.subkeys(Hive::CurrentUser, &np) {
                    apps.push(entry(reg, capability, &np, &program, false));
                }
            } else {
                apps.push(entry(reg, capability, &base, &sub, true));
            }
        }
    }

    // Apps using a capability right now first, then most recently used.
    apps.sort_by(|a, b| {
        b.in_use_now
            .cmp(&a.in_use_now)
            .then_with(|| b.last_used_start_unix.cmp(&a.last_used_start_unix))
            .then_with(|| a.capability.cmp(&b.capability))
            .then_with(|| a.app.cmp(&b.app))
    });
    apps
}

fn entry(reg: &dyn Registry, capability: Capability, parent: &str, key: &str, packaged: bool) -> AppAccess {
    let path = format!(r"{parent}\{key}");
    let start = reg
        .qword(Hive::CurrentUser, &path, "LastUsedTimeStart")
        .and_then(filetime_to_unix);
    let stop = reg
        .qword(Hive::CurrentUser, &path, "LastUsedTimeStop")
        .and_then(filetime_to_unix);

    let (app, identifier, allowed) = if packaged {
        let allowed = reg
            .string(Hive::CurrentUser, &path, "Value")
            .map(|v| v.eq_ignore_ascii_case("Allow"));
        (package_display_name(key), key.to_owned(), allowed)
    } else {
        let exe_path = key.replace('#', "\\");
        let name = exe_path.rsplit('\\').next().unwrap_or(&exe_path).to_owned();
        (name, exe_path, None)
    };

    // While an app is using the capability, Windows leaves the stop time at 0.
    let in_use_now = match (start, stop) {
        (Some(_), None) => true,
        (Some(s), Some(e)) => e < s,
        _ => false,
    };

    AppAccess {
        capability,
        app,
        identifier,
        packaged,
        allowed,
        last_used_start_unix: start,
        last_used_stop_unix: stop,
        in_use_now,
    }
}

/// `Microsoft.WindowsCamera_8wekyb3d8bbwe` -> `Microsoft.WindowsCamera`
/// (drops the 13-character publisher ID).
fn package_display_name(family: &str) -> String {
    match family.rsplit_once('_') {
        Some((name, publisher)) if publisher.len() == 13 => name.to_owned(),
        _ => family.to_owned(),
    }
}

/// FILETIME is 100-nanosecond intervals since 1601-01-01; 0 means never.
fn filetime_to_unix(ft: u64) -> Option<i64> {
    (ft > 0).then(|| (ft / 10_000_000) as i64 - FILETIME_EPOCH_OFFSET_SECS)
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn converts_filetime() {
        // 2024-01-01T00:00:00Z
        assert_eq!(filetime_to_unix(133_485_408_000_000_000), Some(1_704_067_200));
        assert_eq!(filetime_to_unix(0), None);
    }

    #[test]
    fn strips_publisher_id() {
        assert_eq!(package_display_name("Microsoft.WindowsCamera_8wekyb3d8bbwe"), "Microsoft.WindowsCamera");
        assert_eq!(package_display_name("Some_App"), "Some_App");
    }
}
