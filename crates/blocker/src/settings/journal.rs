//! The change journal: one JSON file per applied change, written before the
//! change is made, holding every value it replaces. Undone changes are kept
//! (renamed) as history.

use super::store::{Hive, RegValue};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// One registry value a change wrote, and what was there before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub hive: Hive,
    pub path: String,
    pub name: String,
    /// `None`: the value did not exist, so undo deletes it.
    pub previous: Option<RegValue>,
    pub written: RegValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeRecord {
    pub id: String,
    pub setting_id: String,
    pub title: String,
    pub applied_unix: i64,
    pub entries: Vec<Entry>,
}

pub struct Journal {
    dir: PathBuf,
}

const ACTIVE: &str = ".json";
const UNDONE: &str = ".undone.json";

impl Journal {
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self { dir: dir.to_owned() })
    }

    /// An ID not used before in this journal.
    pub fn new_id(&self, setting_id: &str, now_unix: i64) -> String {
        let base = format!("{now_unix}-{setting_id}");
        let mut id = base.clone();
        let mut n = 1;
        while self.dir.join(format!("{id}{ACTIVE}")).exists() || self.dir.join(format!("{id}{UNDONE}")).exists() {
            n += 1;
            id = format!("{base}-{n}");
        }
        id
    }

    /// Writes the record durably (temp file, flush, rename).
    pub fn save(&self, record: &ChangeRecord) -> io::Result<()> {
        let path = self.dir.join(format!("{}{ACTIVE}", record.id));
        let tmp = self.dir.join(format!("{}.tmp", record.id));
        let json = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        std::fs::rename(tmp, path)
    }

    pub fn load(&self, id: &str) -> io::Result<ChangeRecord> {
        let bytes = std::fs::read(self.dir.join(format!("{id}{ACTIVE}")))?;
        serde_json::from_slice(&bytes).map_err(io::Error::other)
    }

    /// Forgets a record whose change never happened (rolled back on failure).
    pub fn discard(&self, id: &str) -> io::Result<()> {
        std::fs::remove_file(self.dir.join(format!("{id}{ACTIVE}")))
    }

    pub fn mark_undone(&self, id: &str) -> io::Result<()> {
        std::fs::rename(self.dir.join(format!("{id}{ACTIVE}")), self.dir.join(format!("{id}{UNDONE}")))
    }

    /// Changes still in effect, newest first.
    pub fn active(&self) -> io::Result<Vec<ChangeRecord>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(ACTIVE)
                && !name.ends_with(UNDONE)
            {
                out.push(self.load(id)?);
            }
        }
        out.sort_by(|a, b| b.applied_unix.cmp(&a.applied_unix).then_with(|| b.id.cmp(&a.id)));
        Ok(out)
    }
}
