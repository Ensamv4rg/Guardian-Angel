use super::store::fake::FakeStore;
use super::*;

const ADV: &str = r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo";
const INPUT: &str = r"Software\Microsoft\InputPersonalization";

fn journal() -> (tempfile::TempDir, Journal) {
    let dir = tempfile::tempdir().unwrap();
    let j = Journal::open(dir.path()).unwrap();
    (dir, j)
}

#[test]
fn every_scanner_setting_has_a_fix_and_ids_are_unique() {
    let ids = [
        "diagnostic_data",
        "advertising_id",
        "tailored_experiences",
        "language_list",
        "app_launch_tracking",
        "typing_personalization",
        "improve_inking_typing",
        "online_speech",
        "silent_app_installs",
        "start_suggestions",
        "location",
    ];
    for id in ids {
        assert!(fix_for(id).is_some(), "{id}");
    }
    assert_eq!(FIXES.len(), ids.len());
    // Only HKLM fixes are marked as needing admin.
    for f in FIXES {
        assert_eq!(f.needs_admin, f.writes.iter().any(|w| w.hive == Hive::LocalMachine), "{}", f.setting_id);
    }
}

#[test]
fn applies_and_undoes_a_fix() {
    let (_d, j) = journal();
    let mut reg = FakeStore::default();
    reg.put(Hive::CurrentUser, ADV, "Enabled", RegValue::Dword(1));

    let rec = apply(&mut reg, &j, fix_for("advertising_id").unwrap(), 1_000).unwrap();
    assert_eq!(reg.value(Hive::CurrentUser, ADV, "Enabled"), Some(&RegValue::Dword(0)));
    assert_eq!(j.active().unwrap().len(), 1);
    assert_eq!(rec.entries[0].previous, Some(RegValue::Dword(1)));

    let report = undo(&mut reg, &j, &rec.id).unwrap();
    assert_eq!(report.restored, 1);
    assert_eq!(reg.value(Hive::CurrentUser, ADV, "Enabled"), Some(&RegValue::Dword(1)));
    assert!(j.active().unwrap().is_empty());
}

#[test]
fn undo_deletes_values_that_did_not_exist() {
    let (_d, j) = journal();
    let mut reg = FakeStore::default();
    let rec = apply(&mut reg, &j, fix_for("typing_personalization").unwrap(), 1).unwrap();
    assert_eq!(rec.entries.len(), 2);
    assert_eq!(reg.values.len(), 2);
    undo(&mut reg, &j, &rec.id).unwrap();
    assert!(reg.values.is_empty());
}

#[test]
fn undo_keeps_values_the_user_changed_since() {
    let (_d, j) = journal();
    let mut reg = FakeStore::default();
    reg.put(Hive::CurrentUser, ADV, "Enabled", RegValue::Dword(1));
    let rec = apply(&mut reg, &j, fix_for("advertising_id").unwrap(), 1).unwrap();
    // The user flips it themselves later, to something else.
    reg.put(Hive::CurrentUser, ADV, "Enabled", RegValue::Dword(7));

    let report = undo(&mut reg, &j, &rec.id).unwrap();
    assert_eq!(report.restored, 0);
    assert_eq!(report.skipped_changed_since.len(), 1);
    assert_eq!(reg.value(Hive::CurrentUser, ADV, "Enabled"), Some(&RegValue::Dword(7)));
}

#[test]
fn failure_midway_rolls_back_and_leaves_no_record() {
    let (_d, j) = journal();
    let mut reg = FakeStore::default();
    reg.put(Hive::CurrentUser, INPUT, "RestrictImplicitTextCollection", RegValue::Dword(0));
    reg.fail_write_number = Some(2);

    let err = apply(&mut reg, &j, fix_for("typing_personalization").unwrap(), 1).unwrap_err();
    assert!(matches!(err, SettingsError::Store(_)));
    assert_eq!(
        reg.value(Hive::CurrentUser, INPUT, "RestrictImplicitTextCollection"),
        Some(&RegValue::Dword(0)),
        "first write rolled back"
    );
    assert_eq!(reg.value(Hive::CurrentUser, INPUT, "RestrictImplicitInkCollection"), None);
    assert!(j.active().unwrap().is_empty());
}

#[test]
fn machine_wide_fix_without_admin_reports_needs_admin_and_changes_nothing() {
    let (_d, j) = journal();
    let mut reg = FakeStore::default();
    reg.read_only.insert(Hive::LocalMachine);
    let err = apply(&mut reg, &j, fix_for("diagnostic_data").unwrap(), 1).unwrap_err();
    assert!(matches!(err, SettingsError::NeedsAdmin));
    assert!(reg.values.is_empty());
    assert!(j.active().unwrap().is_empty());
}

#[test]
fn already_private_settings_are_left_alone() {
    let (_d, j) = journal();
    let mut reg = FakeStore::default();
    reg.put(Hive::CurrentUser, ADV, "Enabled", RegValue::Dword(0));
    let err = apply(&mut reg, &j, fix_for("advertising_id").unwrap(), 1).unwrap_err();
    assert!(matches!(err, SettingsError::NothingToChange));
}

#[test]
fn undo_all_restores_everything_newest_first_and_ids_never_collide() {
    let (_d, j) = journal();
    let mut reg = FakeStore::default();
    reg.put(Hive::CurrentUser, ADV, "Enabled", RegValue::Dword(1));
    let a = apply(&mut reg, &j, fix_for("advertising_id").unwrap(), 5).unwrap();
    // Undo then re-apply in the same second: a new, distinct ID.
    undo(&mut reg, &j, &a.id).unwrap();
    let b = apply(&mut reg, &j, fix_for("advertising_id").unwrap(), 5).unwrap();
    assert_ne!(a.id, b.id);
    apply(&mut reg, &j, fix_for("online_speech").unwrap(), 6).unwrap();

    let done = undo_all(&mut reg, &j).unwrap();
    assert_eq!(done.len(), 2);
    assert_eq!(done[0].0, "Turn off online speech recognition");
    assert_eq!(reg.value(Hive::CurrentUser, ADV, "Enabled"), Some(&RegValue::Dword(1)));
    assert!(j.active().unwrap().is_empty());
}

/// Exercises the real registry under a scratch key, then removes it.
/// Ignored by default so normal test runs never write to the registry:
/// run with `cargo test -p ga-blocker real_registry -- --ignored`.
#[cfg(windows)]
#[test]
#[ignore]
fn real_registry_round_trip_under_scratch_key() {
    use super::store::WindowsStore;
    let path = format!(r"Software\GuardianAngelTest\{}", std::process::id());
    let mut reg = WindowsStore::default();
    assert_eq!(reg.get(Hive::CurrentUser, &path, "Missing").unwrap(), None);
    reg.set(Hive::CurrentUser, &path, "Number", &RegValue::Dword(42)).unwrap();
    reg.set(Hive::CurrentUser, &path, "Text", &RegValue::String("Deny".into())).unwrap();
    assert_eq!(reg.get(Hive::CurrentUser, &path, "Number").unwrap(), Some(RegValue::Dword(42)));
    assert_eq!(reg.get(Hive::CurrentUser, &path, "Text").unwrap(), Some(RegValue::String("Deny".into())));
    reg.delete(Hive::CurrentUser, &path, "Number").unwrap();
    reg.delete(Hive::CurrentUser, &path, "Number").unwrap(); // already gone: still fine
    assert_eq!(reg.get(Hive::CurrentUser, &path, "Number").unwrap(), None);
    windows_registry::CURRENT_USER.remove_tree(r"Software\GuardianAngelTest").unwrap();
}
