// Compresses the bundled lists so the tracker addresses they contain never
// appear as plain text inside Guardian Angel's programs. Otherwise a scanner
// (ours included) reading guardian-service.exe finds hundreds of "trackers"
// that are only the list of things to look for. The lists are unpacked in
// memory at start-up.

use std::path::Path;

const FILES: &[&str] = &["seed_trackers.json", "ddg_trackers.json", "sdk_signatures.json"];

fn main() {
    let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/sources");
    let out = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR");
    for name in FILES {
        let src = sources.join(name);
        println!("cargo:rerun-if-changed={}", src.display());
        let json = std::fs::read(&src).unwrap_or_else(|e| panic!("cannot read {}: {e}", src.display()));
        let packed = miniz_oxide::deflate::compress_to_vec(&json, 9);
        std::fs::write(Path::new(&out).join(format!("{name}.deflate")), packed).expect("cannot write packed list");
    }
}
