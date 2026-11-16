//! Reads Electron `app.asar` archives: a JSON index followed by the files.
//!
//! Layout: bytes 0..4 = 4, 4..8 = H (size of the header pickle),
//! 8..12 = H - 4, 12..16 = L (JSON length), 16..16+L = JSON index.
//! File data starts at 8 + H; each index entry has a `size` and an `offset`
//! (a decimal string) relative to that point. Entries marked `unpacked` live
//! in the sibling `app.asar.unpacked` folder instead.

use serde_json::Value;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Refuse absurd headers from corrupt or hostile files.
const MAX_HEADER: u32 = 64 * 1024 * 1024;

pub struct Asar {
    path: PathBuf,
    index: Value,
    data_start: u64,
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

impl Asar {
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut f = File::open(path)?;
        let mut head = [0u8; 16];
        f.read_exact(&mut head)?;
        let word = |i: usize| u32::from_le_bytes([head[i], head[i + 1], head[i + 2], head[i + 3]]);
        let (marker, header_size, json_len) = (word(0), word(4), word(12));
        if marker != 4 || header_size > MAX_HEADER || json_len > header_size {
            return Err(invalid("not an asar archive"));
        }
        let mut json = vec![0u8; json_len as usize];
        f.read_exact(&mut json)?;
        let index: Value = serde_json::from_slice(&json).map_err(|_| invalid("bad asar index"))?;
        Ok(Self {
            path: path.to_owned(),
            index,
            data_start: 8 + u64::from(header_size),
        })
    }

    fn entry(&self, path: &[&str]) -> Option<&Value> {
        let mut node = &self.index;
        for part in path {
            node = node.get("files")?.get(*part)?;
        }
        Some(node)
    }

    /// Reads one file from the archive, if it is no larger than `max` bytes.
    pub fn read(&self, path: &[&str], max: u64) -> Option<Vec<u8>> {
        let entry = self.entry(path)?;
        let size = entry.get("size")?.as_u64()?;
        if size > max {
            return None;
        }
        if entry.get("unpacked").and_then(Value::as_bool) == Some(true) {
            let mut unpacked = self.path.as_os_str().to_owned();
            unpacked.push(".unpacked");
            let mut p = PathBuf::from(unpacked);
            p.extend(path);
            return std::fs::read(p).ok();
        }
        let offset: u64 = entry.get("offset")?.as_str()?.parse().ok()?;
        let mut f = File::open(&self.path).ok()?;
        f.seek(SeekFrom::Start(self.data_start.checked_add(offset)?)).ok()?;
        let mut buf = vec![0u8; size as usize];
        f.read_exact(&mut buf).ok()?;
        Some(buf)
    }

    /// Package names under the top-level `node_modules`, including scoped
    /// ones (`@sentry/electron`).
    pub fn packages(&self) -> Vec<String> {
        let Some(Value::Object(mods)) = self.entry(&["node_modules"]).and_then(|e| e.get("files")) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (name, entry) in mods {
            if name.starts_with('@') {
                if let Some(Value::Object(scoped)) = entry.get("files") {
                    out.extend(scoped.keys().map(|s| format!("{name}/{s}")));
                }
            } else if !name.starts_with('.') {
                out.push(name.clone());
            }
        }
        out
    }

    /// `dependencies` from the app's own `package.json`.
    pub fn dependencies(&self) -> Vec<String> {
        let Some(bytes) = self.read(&["package.json"], 4 * 1024 * 1024) else { return Vec::new() };
        let Ok(json) = serde_json::from_slice::<Value>(&bytes) else { return Vec::new() };
        json.get("dependencies")
            .and_then(Value::as_object)
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Builds an asar archive in memory, for tests.
#[cfg(test)]
pub fn build(files: &[(&str, &[u8])]) -> Vec<u8> {
    use serde_json::{Map, json};
    let mut root = Map::new();
    let mut data = Vec::new();
    for (path, content) in files {
        let parts: Vec<&str> = path.split('/').collect();
        let mut node = &mut root;
        for dir in &parts[..parts.len() - 1] {
            node = node
                .entry(*dir)
                .or_insert_with(|| json!({"files": {}}))
                .get_mut("files")
                .and_then(Value::as_object_mut)
                .unwrap();
        }
        node.insert(
            parts[parts.len() - 1].to_owned(),
            json!({"size": content.len(), "offset": data.len().to_string()}),
        );
        data.extend_from_slice(content);
    }
    let json = serde_json::to_vec(&json!({"files": root})).unwrap();
    let padded = json.len().div_ceil(4) * 4;
    let header_size = (4 + 4 + padded) as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&4u32.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&(header_size - 4).to_le_bytes());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(&json);
    out.resize(8 + header_size as usize, 0);
    out.extend_from_slice(&data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_index_packages_and_files() {
        let bytes = build(&[
            ("package.json", br#"{"name":"demo","dependencies":{"@sentry/electron":"5","left-pad":"1"}}"#),
            ("node_modules/mixpanel/index.js", b"api.mixpanel.com"),
            ("node_modules/@sentry/electron/index.js", b"x"),
            ("dist/main.js", b"console.log('hi')"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.asar");
        std::fs::write(&path, bytes).unwrap();

        let asar = Asar::open(&path).unwrap();
        let mut pkgs = asar.packages();
        pkgs.sort();
        assert_eq!(pkgs, ["@sentry/electron", "mixpanel"]);
        let mut deps = asar.dependencies();
        deps.sort();
        assert_eq!(deps, ["@sentry/electron", "left-pad"]);
        assert_eq!(asar.read(&["dist", "main.js"], 100).unwrap(), b"console.log('hi')");
        assert!(asar.read(&["dist", "main.js"], 3).is_none());
        assert!(asar.read(&["missing.js"], 100).is_none());
    }

    #[test]
    fn rejects_non_asar_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.asar");
        std::fs::write(&path, b"MZ\x90\x00 definitely not an asar file").unwrap();
        assert!(Asar::open(&path).is_err());
    }
}
