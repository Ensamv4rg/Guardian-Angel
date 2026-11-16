//! Read-only registry access behind a trait, so the interpretation logic can
//! be tested with an in-memory fake.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

/// Read-only view of the registry. A missing key or value, or a value of the
/// wrong type, reads as `None` / empty.
pub trait Registry {
    fn dword(&self, hive: Hive, path: &str, name: &str) -> Option<u32>;
    fn qword(&self, hive: Hive, path: &str, name: &str) -> Option<u64>;
    fn string(&self, hive: Hive, path: &str, name: &str) -> Option<String>;
    /// Names of the direct subkeys of `path`.
    fn subkeys(&self, hive: Hive, path: &str) -> Vec<String>;
}

/// The real Windows registry, opened with read access only.
///
/// By default `CurrentUser` means the user this process runs as. A service
/// running as SYSTEM uses [`WindowsRegistry::for_user`] to read a signed-in
/// user's hive (`HKEY_USERS\<SID>`) instead.
#[cfg(windows)]
#[derive(Debug, Default, Clone)]
pub struct WindowsRegistry {
    user_sid: Option<String>,
}

#[cfg(windows)]
impl WindowsRegistry {
    pub fn for_user(sid: &str) -> Self {
        Self {
            user_sid: Some(sid.to_owned()),
        }
    }

    fn open(&self, hive: Hive, path: &str) -> Option<windows_registry::Key> {
        match (hive, &self.user_sid) {
            (Hive::LocalMachine, _) => windows_registry::LOCAL_MACHINE.open(path).ok(),
            (Hive::CurrentUser, None) => windows_registry::CURRENT_USER.open(path).ok(),
            (Hive::CurrentUser, Some(sid)) => windows_registry::USERS.open(format!(r"{sid}\{path}")).ok(),
        }
    }
}

#[cfg(windows)]
impl Registry for WindowsRegistry {
    fn dword(&self, hive: Hive, path: &str, name: &str) -> Option<u32> {
        self.open(hive, path)?.get_u32(name).ok()
    }

    fn qword(&self, hive: Hive, path: &str, name: &str) -> Option<u64> {
        self.open(hive, path)?.get_u64(name).ok()
    }

    fn string(&self, hive: Hive, path: &str, name: &str) -> Option<String> {
        self.open(hive, path)?.get_string(name).ok()
    }

    fn subkeys(&self, hive: Hive, path: &str) -> Vec<String> {
        self.open(hive, path)
            .and_then(|key| key.keys().ok().map(Iterator::collect))
            .unwrap_or_default()
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::{Hive, Registry};
    use std::collections::{BTreeSet, HashMap};

    enum Value {
        Dword(u32),
        Qword(u64),
        Str(String),
    }

    /// In-memory registry for tests.
    #[derive(Default)]
    pub struct FakeRegistry {
        values: HashMap<(Hive, String, String), Value>,
        keys: BTreeSet<(Hive, String)>,
    }

    impl FakeRegistry {
        fn insert(&mut self, hive: Hive, path: &str, name: &str, value: Value) -> &mut Self {
            // Register the key and all its parents so `subkeys` can find it.
            let mut prefix = String::new();
            for part in path.split('\\') {
                if !prefix.is_empty() {
                    prefix.push('\\');
                }
                prefix.push_str(part);
                self.keys.insert((hive, prefix.clone()));
            }
            self.values.insert((hive, path.into(), name.into()), value);
            self
        }

        pub fn set_dword(&mut self, hive: Hive, path: &str, name: &str, v: u32) -> &mut Self {
            self.insert(hive, path, name, Value::Dword(v))
        }

        pub fn set_qword(&mut self, hive: Hive, path: &str, name: &str, v: u64) -> &mut Self {
            self.insert(hive, path, name, Value::Qword(v))
        }

        pub fn set_string(&mut self, hive: Hive, path: &str, name: &str, v: &str) -> &mut Self {
            self.insert(hive, path, name, Value::Str(v.into()))
        }
    }

    impl Registry for FakeRegistry {
        fn dword(&self, hive: Hive, path: &str, name: &str) -> Option<u32> {
            match self.values.get(&(hive, path.into(), name.into()))? {
                Value::Dword(v) => Some(*v),
                _ => None,
            }
        }

        fn qword(&self, hive: Hive, path: &str, name: &str) -> Option<u64> {
            match self.values.get(&(hive, path.into(), name.into()))? {
                Value::Qword(v) => Some(*v),
                _ => None,
            }
        }

        fn string(&self, hive: Hive, path: &str, name: &str) -> Option<String> {
            match self.values.get(&(hive, path.into(), name.into()))? {
                Value::Str(v) => Some(v.clone()),
                _ => None,
            }
        }

        fn subkeys(&self, hive: Hive, path: &str) -> Vec<String> {
            let prefix = format!("{path}\\");
            self.keys
                .iter()
                .filter(|(h, k)| *h == hive && k.starts_with(&prefix))
                .map(|(_, k)| &k[prefix.len()..])
                .filter(|rest| !rest.contains('\\'))
                .map(str::to_owned)
                .collect()
        }
    }
}
