//! Changes Windows privacy settings to their privacy-friendly values, with a
//! snapshot first and one-step undo (FR-8, NFR-9).
//!
//! Every value a fix writes is recorded, with what was there before, in the
//! journal before anything changes. If any write fails, the ones already made
//! are rolled back. Undo restores the recorded values, but skips any value the
//! user has changed since, so it never overwrites their own later choice.

pub mod journal;
pub mod store;

use journal::{ChangeRecord, Entry, Journal};
use store::{Hive, RegValue, RegistryStore, StoreError};

/// A value a fix writes.
pub struct Write {
    pub hive: Hive,
    pub path: &'static str,
    pub name: &'static str,
    pub value: FixValue,
}

pub enum FixValue {
    Dword(u32),
    Str(&'static str),
}

impl FixValue {
    fn to_reg(&self) -> RegValue {
        match self {
            FixValue::Dword(v) => RegValue::Dword(*v),
            FixValue::Str(s) => RegValue::String((*s).to_owned()),
        }
    }
}

/// The privacy-friendly change for one setting the scanner reports. IDs
/// match `ga_core::PrivacySetting::id`.
pub struct Fix {
    pub setting_id: &'static str,
    pub title: &'static str,
    pub writes: &'static [Write],
    /// Writes to HKLM, so only the service (or an administrator) can apply it.
    pub needs_admin: bool,
    /// Windows picks the change up only after signing out or restarting Explorer.
    pub needs_restart: bool,
}

const CU: Hive = Hive::CurrentUser;
const LM: Hive = Hive::LocalMachine;
const CONTENT_DELIVERY: &str = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";

pub const FIXES: &[Fix] = &[
    Fix {
        setting_id: "diagnostic_data",
        title: "Send only required diagnostic data",
        writes: &[Write {
            hive: LM,
            path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
            name: "AllowTelemetry",
            value: FixValue::Dword(1),
        }],
        needs_admin: true,
        needs_restart: false,
    },
    Fix {
        setting_id: "advertising_id",
        title: "Turn off the advertising ID",
        writes: &[Write {
            hive: CU,
            path: r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            name: "Enabled",
            value: FixValue::Dword(0),
        }],
        needs_admin: false,
        needs_restart: false,
    },
    Fix {
        setting_id: "tailored_experiences",
        title: "Turn off tailored experiences",
        writes: &[Write {
            hive: CU,
            path: r"Software\Microsoft\Windows\CurrentVersion\Privacy",
            name: "TailoredExperiencesWithDiagnosticDataEnabled",
            value: FixValue::Dword(0),
        }],
        needs_admin: false,
        needs_restart: false,
    },
    Fix {
        setting_id: "language_list",
        title: "Stop websites reading your language list",
        writes: &[Write {
            hive: CU,
            path: r"Control Panel\International\User Profile",
            name: "HttpAcceptLanguageOptOut",
            value: FixValue::Dword(1),
        }],
        needs_admin: false,
        needs_restart: false,
    },
    Fix {
        setting_id: "app_launch_tracking",
        title: "Stop tracking which apps you open",
        writes: &[Write {
            hive: CU,
            path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            name: "Start_TrackProgs",
            value: FixValue::Dword(0),
        }],
        needs_admin: false,
        needs_restart: true,
    },
    Fix {
        setting_id: "typing_personalization",
        title: "Stop collecting typing and handwriting history",
        writes: &[
            Write {
                hive: CU,
                path: r"Software\Microsoft\InputPersonalization",
                name: "RestrictImplicitTextCollection",
                value: FixValue::Dword(1),
            },
            Write {
                hive: CU,
                path: r"Software\Microsoft\InputPersonalization",
                name: "RestrictImplicitInkCollection",
                value: FixValue::Dword(1),
            },
        ],
        needs_admin: false,
        needs_restart: true,
    },
    Fix {
        setting_id: "improve_inking_typing",
        title: "Stop sending typing and inking data to Microsoft",
        writes: &[Write {
            hive: CU,
            path: r"Software\Microsoft\Input\TIPC",
            name: "Enabled",
            value: FixValue::Dword(0),
        }],
        needs_admin: false,
        needs_restart: false,
    },
    Fix {
        setting_id: "online_speech",
        title: "Turn off online speech recognition",
        writes: &[Write {
            hive: CU,
            path: r"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy",
            name: "HasAccepted",
            value: FixValue::Dword(0),
        }],
        needs_admin: false,
        needs_restart: false,
    },
    Fix {
        setting_id: "silent_app_installs",
        title: "Stop automatic installs of suggested apps",
        writes: &[Write {
            hive: CU,
            path: CONTENT_DELIVERY,
            name: "SilentInstalledAppsEnabled",
            value: FixValue::Dword(0),
        }],
        needs_admin: false,
        needs_restart: true,
    },
    Fix {
        setting_id: "start_suggestions",
        title: "Hide suggested apps in Start",
        writes: &[Write {
            hive: CU,
            path: CONTENT_DELIVERY,
            name: "SystemPaneSuggestionsEnabled",
            value: FixValue::Dword(0),
        }],
        needs_admin: false,
        needs_restart: true,
    },
    Fix {
        setting_id: "location",
        title: "Turn off location for your account",
        writes: &[Write {
            hive: CU,
            path: r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
            name: "Value",
            value: FixValue::Str("Deny"),
        }],
        needs_admin: false,
        needs_restart: false,
    },
];

pub fn fix_for(setting_id: &str) -> Option<&'static Fix> {
    FIXES.iter().find(|f| f.setting_id == setting_id)
}

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("this change needs administrator rights")]
    NeedsAdmin,
    #[error("registry: {0}")]
    Store(#[from] StoreError),
    #[error("change journal: {0}")]
    Journal(#[from] std::io::Error),
    #[error("every value is already set the privacy-friendly way")]
    NothingToChange,
}

/// Applies a fix. The journal record is written before any change; on any
/// failure the writes already made are undone and the record discarded.
pub fn apply(store: &mut dyn RegistryStore, journal: &Journal, fix: &Fix, now_unix: i64) -> Result<ChangeRecord, SettingsError> {
    let mut entries = Vec::new();
    for w in fix.writes {
        let previous = store.get(w.hive, w.path, w.name)?;
        let written = w.value.to_reg();
        if previous.as_ref() != Some(&written) {
            entries.push(Entry {
                hive: w.hive,
                path: w.path.to_owned(),
                name: w.name.to_owned(),
                previous,
                written,
            });
        }
    }
    if entries.is_empty() {
        return Err(SettingsError::NothingToChange);
    }

    let record = ChangeRecord {
        id: journal.new_id(fix.setting_id, now_unix),
        setting_id: fix.setting_id.to_owned(),
        title: fix.title.to_owned(),
        applied_unix: now_unix,
        entries,
    };
    journal.save(&record)?;

    for (i, e) in record.entries.iter().enumerate() {
        if let Err(err) = store.set(e.hive, &e.path, &e.name, &e.written) {
            // Put back what was already changed, newest first.
            for done in record.entries[..i].iter().rev() {
                let _ = restore(store, done);
            }
            journal.discard(&record.id)?;
            return Err(match err {
                StoreError::AccessDenied => SettingsError::NeedsAdmin,
                other => other.into(),
            });
        }
    }
    Ok(record)
}

fn restore(store: &mut dyn RegistryStore, e: &Entry) -> Result<(), StoreError> {
    match &e.previous {
        Some(v) => store.set(e.hive, &e.path, &e.name, v),
        None => store.delete(e.hive, &e.path, &e.name),
    }
}

/// What undo did with each value.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct UndoReport {
    pub restored: usize,
    /// Values the user changed after we did; left as the user set them.
    pub skipped_changed_since: Vec<String>,
}

pub fn undo(store: &mut dyn RegistryStore, journal: &Journal, id: &str) -> Result<UndoReport, SettingsError> {
    let record = journal.load(id)?;
    let mut report = UndoReport::default();
    for e in record.entries.iter().rev() {
        let current = store.get(e.hive, &e.path, &e.name)?;
        if current.as_ref() != Some(&e.written) {
            report
                .skipped_changed_since
                .push(format!(r"{}\{}\{}", e.hive.prefix(), e.path, e.name));
            continue;
        }
        restore(store, e).map_err(|err| match err {
            StoreError::AccessDenied => SettingsError::NeedsAdmin,
            other => other.into(),
        })?;
        report.restored += 1;
    }
    journal.mark_undone(id)?;
    Ok(report)
}

/// Undoes every change still in effect, newest first ("restore defaults").
pub fn undo_all(store: &mut dyn RegistryStore, journal: &Journal) -> Result<Vec<(String, UndoReport)>, SettingsError> {
    let mut out = Vec::new();
    for record in journal.active()? {
        let report = undo(store, journal, &record.id)?;
        out.push((record.title, report));
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
