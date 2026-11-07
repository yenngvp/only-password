mod common;

use std::path::Path;

use common::*;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use onlypassword_core::format::{HEADER_LEN, TRAILER_LEN};
use onlypassword_core::{Error, Item, SecretString, Vault};
use onlypassword_desktop::error::UiError;
use onlypassword_desktop::state::{Action, AppState, MaintenanceKind, Screen};
use onlypassword_desktop::view;

const NEW: &str = "NEWPW-SENTINEL-brand new";
const EXP: &str = "EXPPW-SENTINEL-export pw";

fn pw(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

/// An unlocked app whose vault holds two items.
fn setup(env: &Env) -> AppState {
    let (v, k) = env.make_vault("u.opw", "u.key");
    let key = onlypassword_core::keyfile::read(&k).unwrap();
    let mut vault = Vault::unlock(&v, &pw(PW), &key).unwrap();
    for (t, p) in [("alpha", "pass-alpha-1"), ("beta", "pass-beta-2")] {
        let mut item = Item::new_login(t);
        item.password = Some(pw(p));
        vault.add(&item).unwrap();
    }
    vault.lock();
    let (mut s, _c) = env.state_with_clock();
    fill_open(&mut s, &v, &k, PW);
    s.dispatch(Action::SubmitOpen);
    assert!(s.is_unlocked());
    s
}

fn dump(path: &Path, pass: &str, key: &Path) -> Vec<(String, Option<String>)> {
    let key = onlypassword_core::keyfile::read(key).unwrap();
    let v = Vault::unlock(path, &pw(pass), &key).unwrap();
    let mut out: Vec<_> = v
        .list()
        .unwrap()
        .iter()
        .map(|s| {
            let it = v.get(&s.id).unwrap();
            (
                it.item.title.clone(),
                it.item.password.map(|p| p.expose().to_owned()),
            )
        })
        .collect();
    out.sort();
    out
}

fn region(b: &[u8]) -> Vec<u8> {
    b[HEADER_LEN..b.len() - TRAILER_LEN].to_vec()
}

fn change(s: &mut AppState, cur: &str, new: &str, confirm: &str, rotate: bool) {
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::ChangePassword));
    let f = s.maintenance_form_mut();
    f.current.push_str(cur);
    f.new.push_str(new);
    f.confirm.push_str(confirm);
    f.rotate = rotate;
    s.dispatch(Action::SubmitChangePassword);
}

fn assert_bufs_empty(s: &mut AppState) {
    let f = s.maintenance_form_mut();
    assert!(f.current.is_empty() && f.new.is_empty() && f.confirm.is_empty());
}

#[test]
fn change_password_with_rotate_then_relock() {
    let env = Env::new();
    let mut s = setup(&env);
    let before = dump(&env.path("u.opw"), PW, &env.path("u.key"));
    let old_bytes = std::fs::read(env.path("u.opw")).unwrap();
    assert!(s.maintenance_form_mut().rotate, "default on");
    change(&mut s, PW, NEW, NEW, true);
    assert!(s.notice().is_none(), "{:?}", s.notice());
    assert_eq!(s.screen(), &Screen::Browse);
    let info = s.info().unwrap().to_owned();
    assert!(!info.contains(NEW) && !info.contains(PW));
    assert_bufs_empty(&mut s);
    assert_ne!(
        region(&old_bytes),
        region(&std::fs::read(env.path("u.opw")).unwrap())
    );
    assert_eq!(s.rows().len(), 2);
    s.dispatch(Action::Lock);
    assert!(s.is_clean());
    fill_open(&mut s, &env.path("u.opw"), &env.path("u.key"), PW);
    s.dispatch(Action::SubmitOpen);
    assert_eq!(s.notice(), Some(&UiError::Core(Error::Authentication)));
    fill_open(&mut s, &env.path("u.opw"), &env.path("u.key"), NEW);
    s.dispatch(Action::SubmitOpen);
    assert!(s.is_unlocked());
    assert_eq!(dump(&env.path("u.opw"), NEW, &env.path("u.key")), before);
}

#[test]
fn change_password_without_rotate_keeps_records() {
    let env = Env::new();
    let mut s = setup(&env);
    let old = std::fs::read(env.path("u.opw")).unwrap();
    change(&mut s, PW, NEW, NEW, false);
    assert!(s.notice().is_none());
    let new = std::fs::read(env.path("u.opw")).unwrap();
    assert_ne!(old, new);
    assert_eq!(region(&old), region(&new));
    let info = s.info().unwrap();
    assert!(!info.contains(NEW));
    assert_eq!(dump(&env.path("u.opw"), NEW, &env.path("u.key")).len(), 2);
}

#[test]
fn change_password_failures_leave_file_untouched() {
    let env = Env::new();
    let mut s = setup(&env);
    let old = std::fs::read(env.path("u.opw")).unwrap();
    change(&mut s, "wrong password!!", NEW, NEW, true);
    assert_eq!(s.notice(), Some(&UiError::Core(Error::Authentication)));
    assert_bufs_empty(&mut s);
    change(&mut s, PW, "short77", "short77", true);
    assert!(matches!(
        s.notice(),
        Some(UiError::Core(Error::InvalidInput(_)))
    ));
    change(&mut s, PW, NEW, "something else", true);
    assert_eq!(s.notice(), Some(&UiError::PasswordMismatch));
    assert_bufs_empty(&mut s);
    assert_eq!(old, std::fs::read(env.path("u.opw")).unwrap());
    // Session still usable.
    change(&mut s, PW, NEW, NEW, true);
    assert!(s.notice().is_none());
}

#[test]
fn rotate_needs_confirmation() {
    let env = Env::new();
    let mut s = setup(&env);
    let before_items = dump(&env.path("u.opw"), PW, &env.path("u.key"));
    let old = std::fs::read(env.path("u.opw")).unwrap();
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::RotateKey));
    s.maintenance_form_mut().current.push_str(PW);
    s.dispatch(Action::SubmitRotate);
    assert_eq!(s.notice(), Some(&UiError::ConfirmationRequired));
    assert_bufs_empty(&mut s);
    assert_eq!(old, std::fs::read(env.path("u.opw")).unwrap());
    let f = s.maintenance_form_mut();
    f.current.push_str(PW);
    f.confirmed = true;
    s.dispatch(Action::SubmitRotate);
    assert!(s.notice().is_none(), "{:?}", s.notice());
    let new = std::fs::read(env.path("u.opw")).unwrap();
    assert_ne!(region(&old), region(&new));
    assert_eq!(
        dump(&env.path("u.opw"), PW, &env.path("u.key")),
        before_items
    );
    assert_eq!(s.rows().len(), 2);
}

fn export(env: &Env, s: &mut AppState, target: &Path, pass: &str, confirm: &str) {
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::Export));
    if pass == confirm {
        env.picker.push(Some(target.to_path_buf()));
    }
    let f = s.maintenance_form_mut();
    f.new.push_str(pass);
    f.confirm.push_str(confirm);
    s.dispatch(Action::SubmitExport);
}

fn import(env: &Env, s: &mut AppState, file: &Path, key: &Path, pass: &str) {
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::Import));
    env.picker.push(Some(file.to_path_buf()));
    env.picker.push(Some(key.to_path_buf()));
    s.maintenance_form_mut().new.push_str(pass);
    s.dispatch(Action::SubmitImport);
}

/// A second app with its own fresh vault.
fn second(env: &Env) -> AppState {
    let (mut s, _c) = env.state_with_clock();
    s.dispatch(Action::ShowCreate);
    fill_create(&mut s, &env.path("v2.opw"), &env.path("v2.key"), PW, PW);
    s.dispatch(Action::SubmitCreate);
    assert!(s.is_unlocked(), "{:?}", s.notice());
    s
}

#[test]
fn export_import_roundtrip_and_failures() {
    let env = Env::new();
    let mut s = setup(&env);
    let exp = env.path("out.opwx");
    export(&env, &mut s, &exp, EXP, "other-export-pw");
    assert_eq!(s.notice(), Some(&UiError::PasswordMismatch));
    assert!(!exp.exists());
    export(&env, &mut s, &exp, EXP, EXP);
    assert!(s.notice().is_none(), "{:?}", s.notice());
    assert!(exp.exists());
    assert_bufs_empty(&mut s);
    let want = dump(&env.path("u.opw"), PW, &env.path("u.key"));
    let ukey = env.path("u.key");

    let mut t = second(&env);
    let v2 = std::fs::read(env.path("v2.opw")).unwrap();
    // The second vault's own key file: Authentication, nothing changed.
    import(&env, &mut t, &exp, &env.path("v2.key"), EXP);
    assert_eq!(t.notice(), Some(&UiError::Core(Error::Authentication)));
    assert_bufs_empty(&mut t);
    // Wrong export password.
    import(&env, &mut t, &exp, &ukey, "wrong export pw");
    assert_eq!(t.notice(), Some(&UiError::Core(Error::Authentication)));
    // Flipped byte.
    let mut bytes = std::fs::read(&exp).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    let bad = env.path("bad.opwx");
    std::fs::write(&bad, bytes).unwrap();
    import(&env, &mut t, &bad, &ukey, EXP);
    assert!(matches!(
        t.notice(),
        Some(UiError::Core(Error::Authentication | Error::Corrupt(_)))
    ));
    assert_eq!(v2, std::fs::read(env.path("v2.opw")).unwrap());
    assert!(t.rows().is_empty());
    // Good import.
    import(&env, &mut t, &exp, &ukey, EXP);
    assert!(t.notice().is_none(), "{:?}", t.notice());
    assert!(t.info().unwrap().contains('2'));
    assert_eq!(t.rows().len(), 2);
    assert_bufs_empty(&mut t);
    t.dispatch(Action::Lock);
    assert!(t.is_clean());
    assert_eq!(dump(&env.path("v2.opw"), PW, &env.path("v2.key")), want);
    // Same export twice: Conflict, count unchanged.
    fill_open(&mut t, &env.path("v2.opw"), &env.path("v2.key"), PW);
    t.dispatch(Action::SubmitOpen);
    let after = std::fs::read(env.path("v2.opw")).unwrap();
    import(&env, &mut t, &exp, &ukey, EXP);
    assert_eq!(t.notice(), Some(&UiError::Core(Error::Conflict)));
    assert_eq!(t.rows().len(), 2);
    assert_eq!(after, std::fs::read(env.path("v2.opw")).unwrap());
}

#[test]
fn export_to_vault_path_is_invalid_input() {
    let env = Env::new();
    let mut s = setup(&env);
    let vault = env.path("u.opw");
    let old = std::fs::read(&vault).unwrap();
    export(&env, &mut s, &vault, EXP, EXP);
    assert!(matches!(
        s.notice(),
        Some(UiError::Core(Error::InvalidInput(_)))
    ));
    assert_eq!(old, std::fs::read(&vault).unwrap());
    #[cfg(unix)]
    {
        let link = env.path("link.opw");
        std::os::unix::fs::symlink(&vault, &link).unwrap();
        export(&env, &mut s, &link, EXP, EXP);
        assert!(matches!(
            s.notice(),
            Some(UiError::Core(Error::InvalidInput(_)))
        ));
        assert_eq!(old, std::fs::read(&vault).unwrap());
    }
    assert_bufs_empty(&mut s);
}

#[test]
fn cancel_lock_and_picker_cancel_clear_buffers() {
    let env = Env::new();
    let mut s = setup(&env);
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::ChangePassword));
    s.maintenance_form_mut().current.push_str(PW);
    s.dispatch(Action::CancelMaintenance);
    assert_bufs_empty(&mut s);
    assert_eq!(s.screen(), &Screen::Browse);
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::ChangePassword));
    s.maintenance_form_mut().new.push_str(NEW);
    s.dispatch(Action::Lock);
    assert!(s.is_clean());
    // Picker cancel: silent, buffers still cleared.
    let env = Env::new();
    let mut s = setup(&env);
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::Export));
    env.picker.push(None);
    s.maintenance_form_mut().new.push_str(EXP);
    s.maintenance_form_mut().confirm.push_str(EXP);
    s.dispatch(Action::SubmitExport);
    assert!(s.notice().is_none());
    assert_bufs_empty(&mut s);
    assert!(!format!("{s:?} {:?}", s.maintenance_form()).contains("SENTINEL"));
}

#[test]
fn idle_expiry_empties_typed_passwords() {
    let env = Env::new();
    let (v, k) = env.make_vault("u.opw", "u.key");
    let (mut s, clock) = env.state_with_clock();
    fill_open(&mut s, &v, &k, PW);
    s.dispatch(Action::SubmitOpen);
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::ChangePassword));
    let f = s.maintenance_form_mut();
    f.current.push_str(PW);
    f.new.push_str(NEW);
    f.confirm.push_str(NEW);
    clock.advance(std::time::Duration::from_secs(10_000));
    s.tick();
    assert!(!s.is_unlocked());
    assert_bufs_empty(&mut s);
    assert!(s.is_clean());
}

#[test]
fn change_password_form_masks_and_drives_flow() {
    let env = Env::new();
    let s = setup(&env);
    let mut h = Harness::new_ui_state(|ui, s: &mut AppState| view::show(ui, s), s);
    h.run();
    h.get_by_label("Change password").click();
    h.run();
    assert_eq!(
        h.state().screen(),
        &Screen::Maintenance(MaintenanceKind::ChangePassword)
    );
    for label in ["Current password", "New password", "Confirm new password"] {
        h.get_by_label(label).focus();
        h.run();
        h.get_by_label(label).type_text("TYPED-SENTINEL-x1");
        h.run();
    }
    assert_eq!(
        h.state().maintenance_form().new.expose(),
        "TYPED-SENTINEL-x1"
    );
    assert!(h.query_by_label_contains("TYPED-SENTINEL").is_none());
    h.get_by_label("Change").click();
    h.run();
    // Wrong current password: fixed message, fields emptied.
    h.get_by_label("authentication failed");
    assert!(h.query_by_label_contains("TYPED-SENTINEL").is_none());
    assert!(h.state().maintenance_form().buffers_empty());
}
