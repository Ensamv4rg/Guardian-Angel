//! Read-write registry access behind a trait, so the apply/undo logic can be
//! tested against an in-memory fake.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Hive {
    LocalMachine,
    CurrentUser,
}

impl Hive {
    pub fn prefix(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKLM",
            Hive::CurrentUser => "HKCU",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegValue {
    Dword(u32),
    String(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("Windows denied access (administrator rights needed)")]
    AccessDenied,
    #[error("the value has an unexpected type, so it is left alone")]
    UnsupportedType,
    #[error("{0}")]
    Other(String),
}

pub trait RegistryStore {
    /// `Ok(None)` when the key or value does not exist.
    fn get(&self, hive: Hive, path: &str, name: &str) -> Result<Option<RegValue>, StoreError>;
    /// Creates the key if needed.
    fn set(&mut self, hive: Hive, path: &str, name: &str, value: &RegValue) -> Result<(), StoreError>;
    /// Succeeds if the value is already absent.
    fn delete(&mut self, hive: Hive, path: &str, name: &str) -> Result<(), StoreError>;
}

#[cfg(windows)]
pub use windows_store::WindowsStore;

#[cfg(windows)]
mod windows_store {
    use super::*;
    use windows_registry::{CURRENT_USER, Key, LOCAL_MACHINE, Type, USERS};

    /// The real registry. `CurrentUser` is this process's user unless built
    /// with [`WindowsStore::for_user`], which targets `HKEY_USERS\<SID>`
    /// (for the service, running as SYSTEM).
    #[derive(Debug, Default)]
    pub struct WindowsStore {
        user_sid: Option<String>,
    }

    impl WindowsStore {
        pub fn for_user(sid: &str) -> Self {
            Self {
                user_sid: Some(sid.to_owned()),
            }
        }

        /// The root key and the path below it for a hive-relative path.
        fn locate(&self, hive: Hive, path: &str) -> (&'static Key, String) {
            match (hive, &self.user_sid) {
                (Hive::LocalMachine, _) => (LOCAL_MACHINE, path.to_owned()),
                (Hive::CurrentUser, None) => (CURRENT_USER, path.to_owned()),
                (Hive::CurrentUser, Some(sid)) => (USERS, format!(r"{sid}\{path}")),
            }
        }
    }

    const E_ACCESSDENIED: i32 = 0x8007_0005_u32 as i32;
    const E_NOT_FOUND: i32 = 0x8007_0002_u32 as i32;

    fn map(e: windows_result::Error) -> StoreError {
        if e.code().0 == E_ACCESSDENIED {
            StoreError::AccessDenied
        } else {
            StoreError::Other(e.message())
        }
    }

    impl RegistryStore for WindowsStore {
        fn get(&self, hive: Hive, path: &str, name: &str) -> Result<Option<RegValue>, StoreError> {
            let (root, path) = self.locate(hive, path);
            let key = match root.open(&path) {
                Ok(k) => k,
                Err(e) if e.code().0 == E_NOT_FOUND => return Ok(None),
                Err(e) => return Err(map(e)),
            };
            match key.get_type(name) {
                Err(e) if e.code().0 == E_NOT_FOUND => Ok(None),
                Err(e) => Err(map(e)),
                Ok(Type::U32) => key.get_u32(name).map(|v| Some(RegValue::Dword(v))).map_err(map),
                Ok(Type::String | Type::ExpandString) => {
                    key.get_string(name).map(|v| Some(RegValue::String(v))).map_err(map)
                }
                Ok(_) => Err(StoreError::UnsupportedType),
            }
        }

        fn set(&mut self, hive: Hive, path: &str, name: &str, value: &RegValue) -> Result<(), StoreError> {
            let (root, path) = self.locate(hive, path);
            let key = root.create(&path).map_err(map)?;
            match value {
                RegValue::Dword(v) => key.set_u32(name, *v),
                RegValue::String(s) => key.set_string(name, s),
            }
            .map_err(map)
        }

        fn delete(&mut self, hive: Hive, path: &str, name: &str) -> Result<(), StoreError> {
            let (root, path) = self.locate(hive, path);
            let key = match root.options().read().write().open(&path) {
                Ok(k) => k,
                Err(e) if e.code().0 == E_NOT_FOUND => return Ok(()),
                Err(e) => return Err(map(e)),
            };
            match key.remove_value(name) {
                Err(e) if e.code().0 != E_NOT_FOUND => Err(map(e)),
                _ => Ok(()),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// In-memory registry. Hives listed in `read_only` reject writes, like
    /// HKLM for a non-administrator.
    #[derive(Default)]
    pub struct FakeStore {
        pub values: BTreeMap<(Hive, String, String), RegValue>,
        pub read_only: BTreeSet<Hive>,
        /// Fail the n-th write (1-based) to test rollback.
        pub fail_write_number: Option<usize>,
        writes: usize,
    }

    impl FakeStore {
        pub fn value(&self, hive: Hive, path: &str, name: &str) -> Option<&RegValue> {
            self.values.get(&(hive, path.to_owned(), name.to_owned()))
        }

        pub fn put(&mut self, hive: Hive, path: &str, name: &str, v: RegValue) {
            self.values.insert((hive, path.to_owned(), name.to_owned()), v);
        }

        fn check_write(&mut self, hive: Hive) -> Result<(), StoreError> {
            if self.read_only.contains(&hive) {
                return Err(StoreError::AccessDenied);
            }
            self.writes += 1;
            if self.fail_write_number == Some(self.writes) {
                return Err(StoreError::Other("simulated failure".into()));
            }
            Ok(())
        }
    }

    impl RegistryStore for FakeStore {
        fn get(&self, hive: Hive, path: &str, name: &str) -> Result<Option<RegValue>, StoreError> {
            Ok(self.value(hive, path, name).cloned())
        }

        fn set(&mut self, hive: Hive, path: &str, name: &str, value: &RegValue) -> Result<(), StoreError> {
            self.check_write(hive)?;
            self.put(hive, path, name, value.clone());
            Ok(())
        }

        fn delete(&mut self, hive: Hive, path: &str, name: &str) -> Result<(), StoreError> {
            self.check_write(hive)?;
            self.values.remove(&(hive, path.to_owned(), name.to_owned()));
            Ok(())
        }
    }
}
