// Links the Visual C++ runtime into guardian-service.exe so it starts on a
// clean Windows install that never got the "VC++ Redistributable". The
// Universal CRT stays dynamic because it ships with Windows 10 and later.
// This is the same approach tauri-build uses for the desktop app.

fn main() {
    let windows_msvc = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if !windows_msvc {
        return;
    }
    // Drop the default dynamic runtime libraries...
    for lib in [
        "libvcruntimed.lib",
        "vcruntime.lib",
        "vcruntimed.lib",
        "libcmtd.lib",
        "msvcrt.lib",
        "msvcrtd.lib",
        "libucrt.lib",
        "libucrtd.lib",
    ] {
        println!("cargo:rustc-link-arg-bins=/NODEFAULTLIB:{lib}");
    }
    // ...and use the static VC runtime with the system's Universal CRT.
    for lib in ["libcmt.lib", "libvcruntime.lib", "ucrt.lib"] {
        println!("cargo:rustc-link-arg-bins=/DEFAULTLIB:{lib}");
    }
}
