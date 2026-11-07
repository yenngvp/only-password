//! Phase-2 definition of done as one headless scenario (F037).
//! Real default KDF parameters, ManualClock, MemoryClipboard, ScriptedPicker, tempdir config.

use std::path::Path;
use std::time::Duration;

use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use onlypassword_core::crypto::kdf::KdfParams;
use onlypassword_core::{base32, Error, ItemKind, SecretString, StoredItem, TotpAlgorithm, Vault};
use onlypassword_desktop::clipboard::MemoryClipboard;
use onlypassword_desktop::clock::ManualClock;
use onlypassword_desktop::config::ConfigStore;
use onlypassword_desktop::error::UiError;
use onlypassword_desktop::picker::ScriptedPicker;
use onlypassword_desktop::state::{Action, AppDeps, AppState, FieldRef, MaintenanceKind, Screen};
use onlypassword_desktop::view;

const MASTER: &str = "correct-horse-test-only";
const NEW_MASTER: &str = "battery-staple-test-only-2";
const EXPORT_PW: &str = "export-passphrase-test-only";
const LOGIN_PW: &str = "login-secret-test-only-17";
const LOGIN_NOTES: &str = "login-notes-test-only";
const NOTE_BODY: &str = "secure-note-body-test-only";
const PLAIN_VAL: &str = "plain-field-value-test-only";
const HIDDEN_VAL: &str = "hidden-field-value-test-only";
const IDLE_SECS: u64 = 300;
const CLIP_SECS: u64 = 30;

struct Rig {
    clock: ManualClock,
    clipboard: MemoryClipboard,
    picker: ScriptedPicker,
    config_dir: std::path::PathBuf,
}

fn app(
    dir: &Path,
    name: &str,
    clipboard: &MemoryClipboard,
    picker: &ScriptedPicker,
) -> (AppState, Rig) {
    let clock = ManualClock::new();
    let config_dir = dir.join(name);
    std::fs::create_dir_all(&config_dir).unwrap();
    let state = AppState::new(AppDeps {
        clock: Box::new(clock.clone()),
        clipboard: Box::new(clipboard.clone()),
        picker: Box::new(picker.clone()),
        config_store: Some(ConfigStore::new(config_dir.clone())),
        kdf: KdfParams::DEFAULT,
    });
    (
        state,
        Rig {
            clock,
            clipboard: clipboard.clone(),
            picker: picker.clone(),
            config_dir,
        },
    )
}

/// Every field of an item as plain strings, for comparisons.
fn snapshot(s: &StoredItem) -> Vec<String> {
    let i = &s.item;
    let mut v = vec![
        format!("{:?}", i.kind),
        i.title.clone(),
        i.username.clone().unwrap_or_default(),
        i.urls.join("|"),
        i.password
            .as_ref()
            .map(|p| p.expose().to_owned())
            .unwrap_or_default(),
        i.notes.expose().to_owned(),
    ];
    match &i.totp {
        Some(t) => v.push(format!(
            "{}/{:?}/{}/{}",
            t.secret.expose(),
            t.algorithm,
            t.digits,
            t.period
        )),
        None => v.push("no-totp".into()),
    }
    for f in &i.fields {
        v.push(format!("{}={}:{}", f.name, f.value.expose(), f.hidden));
    }
    v
}

/// Open each row through the detail view state and snapshot it.
fn read_all(s: &mut AppState) -> Vec<Vec<String>> {
    let ids: Vec<_> = s.rows().iter().map(|r| r.id.clone()).collect();
    let mut out = Vec::new();
    for id in ids {
        if *s.screen() != Screen::Browse {
            s.dispatch(Action::Back);
        }
        s.dispatch(Action::Select(id));
        assert!(s.notice().is_none(), "{:?}", s.notice());
        out.push(snapshot(s.selected().expect("detail state")));
    }
    if *s.screen() != Screen::Browse {
        s.dispatch(Action::Back);
    }
    out.sort();
    out
}

fn select_title(s: &mut AppState, title: &str) {
    if *s.screen() != Screen::Browse {
        s.dispatch(Action::Back);
    }
    let id = s
        .rows()
        .iter()
        .find(|r| r.title == title)
        .expect("row")
        .id
        .clone();
    s.dispatch(Action::Select(id));
    assert_eq!(
        s.screen(),
        &Screen::Detail(s.selected().unwrap().id.clone())
    );
}

fn totp_vector() -> (String, u64, String) {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/totp.json");
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    for v in doc["vectors"].as_array().unwrap() {
        if v["mode"] == "SHA1" && v["time"].as_u64() == Some(1111111109) {
            let raw = base32::hex_decode(v["secret_hex"].as_str().unwrap()).unwrap();
            return (
                base32::encode(&raw),
                1111111109,
                v["totp"].as_str().unwrap().to_owned(),
            );
        }
    }
    panic!("vector missing");
}

fn record(notices: &mut Vec<String>, s: &AppState) {
    if let Some(n) = s.notice() {
        notices.push(n.to_string());
    }
    if let Some(i) = s.info() {
        notices.push(i.to_owned());
    }
}

#[test]
fn phase2_definition_of_done() {
    let dir = tempfile::tempdir().unwrap();
    let clipboard = MemoryClipboard::new();
    let picker = ScriptedPicker::new();
    let (state, rig) = app(dir.path(), "cfg1", &clipboard, &picker);
    let (v1, k1) = (dir.path().join("one.opw"), dir.path().join("one.key"));
    let mut notices: Vec<String> = Vec::new();
    let (totp_secret, totp_time, totp_code) = totp_vector();

    // ---- 1. create a vault with a new key file (real default KDF) ----
    let mut h = Harness::new_ui_state(|ui, s: &mut AppState| view::show(ui, s), state);
    h.run();
    assert_eq!(h.state().screen(), &Screen::Open);
    h.state_mut().dispatch(Action::ShowCreate);
    {
        let f = h.state_mut().create_form_mut();
        f.vault_path = v1.to_string_lossy().into_owned();
        f.key_path = k1.to_string_lossy().into_owned();
        f.password.push_str(MASTER);
        f.confirm.push_str(MASTER);
    }
    h.state_mut().dispatch(Action::SubmitCreate);
    record(&mut notices, h.state());
    assert!(h.state().is_unlocked(), "{:?}", h.state().notice());
    assert!(k1.exists() && v1.exists());
    assert!(h.state().rows().is_empty());
    let key_text_1 = std::fs::read_to_string(&k1).unwrap();
    assert!(!key_text_1.trim().is_empty());

    // ---- 2. add a login (TOTP SHA-1/8, plain + hidden field) and a note ----
    rig.clock.set_unix(totp_time);
    {
        let s = h.state_mut();
        s.dispatch(Action::BeginAdd(ItemKind::Login));
        s.dispatch(Action::SetTitle("Example login".into()));
        s.dispatch(Action::SetUsername("alice-test".into()));
        s.dispatch(Action::AddUrl);
        s.dispatch(Action::SetUrl(0, "https://example.invalid".into()));
        s.dispatch(Action::SetTotpAlgorithm(TotpAlgorithm::Sha1));
        s.dispatch(Action::SetTotpDigits(8));
        s.dispatch(Action::SetTotpPeriod(30));
        s.dispatch(Action::AddField);
        s.dispatch(Action::AddField);
        s.dispatch(Action::SetFieldName(0, "Plain".into()));
        s.dispatch(Action::SetFieldName(1, "Hidden".into()));
        s.dispatch(Action::SetFieldHidden(0, false));
        s.dispatch(Action::SetFieldHidden(1, true));
        let d = s.draft_mut().unwrap();
        d.password.push_str(LOGIN_PW);
        d.notes.push_str(LOGIN_NOTES);
        d.totp_secret.push_str(&totp_secret);
        d.fields[0].value.push_str(PLAIN_VAL);
        d.fields[1].value.push_str(HIDDEN_VAL);
        s.dispatch(Action::SaveDraft);
        record(&mut notices, s);
        assert!(s.notice().is_none(), "{:?}", s.notice());
        assert!(matches!(s.screen(), Screen::Detail(_)));
        s.dispatch(Action::Back);
    }
    // The note is added through the edit view: the title is typed into the form.
    h.state_mut().dispatch(Action::BeginAdd(ItemKind::Note));
    h.run();
    h.get_by_label("Title").focus();
    h.run();
    h.get_by_label("Title").type_text("Secure note");
    h.run();
    assert_eq!(h.state().draft().unwrap().title, "Secure note");
    h.state_mut().draft_mut().unwrap().notes.push_str(NOTE_BODY);
    h.state_mut().dispatch(Action::SaveDraft);
    record(&mut notices, h.state());
    assert!(h.state().notice().is_none(), "{:?}", h.state().notice());
    h.state_mut().dispatch(Action::Back);
    h.run();
    assert_eq!(h.state().rows().len(), 2);

    // Core ground truth for the later comparisons.
    let expected = {
        let key = onlypassword_core::keyfile::read(&k1).unwrap();
        let vault = Vault::unlock(&v1, &SecretString::new(MASTER.to_owned()), &key).unwrap();
        let mut v: Vec<Vec<String>> = vault
            .list()
            .unwrap()
            .iter()
            .map(|s| snapshot(&vault.get(&s.id).unwrap()))
            .collect();
        v.sort();
        vault.lock();
        v
    };
    assert_eq!(expected.len(), 2);

    // ---- 3. lock manually (button), check is_clean ----
    h.get_by_label("Lock").click();
    h.run();
    assert_eq!(h.state().screen(), &Screen::Unlock);
    assert!(h.state().is_clean());
    assert!(rig.clipboard.text().is_none());

    // ---- 4. unlock again through the unlock view ----
    {
        let f = h.state_mut().open_form_mut();
        f.vault_path = v1.to_string_lossy().into_owned();
        f.key_path = k1.to_string_lossy().into_owned();
    }
    h.run();
    h.get_by_label("Master password").focus();
    h.run();
    h.get_by_label("Master password").type_text(MASTER);
    h.run();
    h.get_by_label("Unlock").click();
    h.run();
    record(&mut notices, h.state());
    assert!(h.state().is_unlocked(), "{:?}", h.state().notice());
    let s = h.state_mut();

    // ---- 5. read both items back through the detail state ----
    assert_eq!(read_all(s), expected);
    select_title(s, "Example login");
    s.tick();
    let totp = s.totp().expect("totp view");
    assert_eq!(totp.code.as_ref().unwrap().as_str(), totp_code);
    assert_eq!(totp.remaining, 1);
    // Clipboard copy and timed clear of the password.
    s.dispatch(Action::Copy(FieldRef::Password));
    assert!(s.notice().is_none());
    assert_eq!(rig.clipboard.text().as_deref(), Some(LOGIN_PW));
    assert!(rig.clipboard.sensitive());
    rig.clock.advance(Duration::from_secs(CLIP_SECS - 1));
    s.tick();
    assert_eq!(rig.clipboard.text().as_deref(), Some(LOGIN_PW), "not yet");
    rig.clock.advance(Duration::from_secs(1));
    s.tick();
    assert!(rig.clipboard.text().is_none(), "cleared at the timeout");
    assert!(s.is_unlocked());

    // ---- 6. idle-timeout lock, no sleeping ----
    s.dispatch(Action::Activity);
    rig.clock.advance(Duration::from_secs(IDLE_SECS - 1));
    s.tick();
    assert!(s.is_unlocked(), "just before the timeout");
    rig.clock.advance(Duration::from_secs(2));
    s.tick();
    assert!(!s.is_unlocked());
    assert!(s.is_clean());

    // ---- 7. unlock, change the master password (rotate on) ----
    unlock_via(s, &v1, &k1, MASTER);
    record(&mut notices, s);
    assert!(s.is_unlocked(), "{:?}", s.notice());
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::ChangePassword));
    {
        let f = s.maintenance_form_mut();
        assert!(f.rotate, "rotate is on by default");
        f.current.push_str(MASTER);
        f.new.push_str(NEW_MASTER);
        f.confirm.push_str(NEW_MASTER);
    }
    s.dispatch(Action::SubmitChangePassword);
    record(&mut notices, s);
    assert!(s.notice().is_none(), "{:?}", s.notice());
    assert_eq!(s.screen(), &Screen::Browse);
    s.dispatch(Action::Lock);
    assert!(s.is_clean());
    // The old password fails with the generic message; the new one unlocks.
    unlock_via(s, &v1, &k1, MASTER);
    record(&mut notices, s);
    assert_eq!(s.notice(), Some(&UiError::Core(Error::Authentication)));
    assert_eq!(
        s.notice().unwrap().to_string(),
        Error::Authentication.to_string()
    );
    assert!(!s.is_unlocked() && s.is_clean());
    unlock_via(s, &v1, &k1, NEW_MASTER);
    assert!(s.is_unlocked(), "{:?}", s.notice());
    assert_eq!(
        read_all(s),
        expected,
        "items survive the change and rotation"
    );

    // ---- 8. export ----
    let export_path = dir.path().join("backup.opwx");
    s.dispatch(Action::ShowMaintenance(MaintenanceKind::Export));
    rig.picker.push(Some(export_path.clone()));
    {
        let f = s.maintenance_form_mut();
        f.new.push_str(EXPORT_PW);
        f.confirm.push_str(EXPORT_PW);
    }
    s.dispatch(Action::SubmitExport);
    record(&mut notices, s);
    assert!(s.notice().is_none(), "{:?}", s.notice());
    assert!(export_path.exists());
    let key_text_1_after = std::fs::read_to_string(&k1).unwrap();

    // ---- 9. a fresh vault with another key file, import the export ----
    let (mut t, rig2) = app(dir.path(), "cfg2", &clipboard, &picker);
    let (v2, k2) = (dir.path().join("two.opw"), dir.path().join("two.key"));
    t.dispatch(Action::ShowCreate);
    {
        let f = t.create_form_mut();
        f.vault_path = v2.to_string_lossy().into_owned();
        f.key_path = k2.to_string_lossy().into_owned();
        f.password.push_str(MASTER);
        f.confirm.push_str(MASTER);
    }
    t.dispatch(Action::SubmitCreate);
    record(&mut notices, &t);
    assert!(t.is_unlocked(), "{:?}", t.notice());
    assert!(t.rows().is_empty());
    let key_text_2 = std::fs::read_to_string(&k2).unwrap();
    assert_ne!(key_text_2, key_text_1);

    let import = |t: &mut AppState, key: &Path| {
        t.dispatch(Action::ShowMaintenance(MaintenanceKind::Import));
        rig2.picker.push(Some(export_path.clone()));
        rig2.picker.push(Some(key.to_path_buf()));
        t.maintenance_form_mut().new.push_str(EXPORT_PW);
        t.dispatch(Action::SubmitImport);
    };
    // The second vault's own key file cannot open the export.
    import(&mut t, &k2);
    record(&mut notices, &t);
    assert_eq!(t.notice(), Some(&UiError::Core(Error::Authentication)));
    assert!(t.rows().is_empty());
    // The first vault's key file can.
    import(&mut t, &k1);
    record(&mut notices, &t);
    assert!(t.notice().is_none(), "{:?}", t.notice());
    assert_eq!(t.rows().len(), 2);
    assert_eq!(read_all(&mut t), expected, "fresh vault equals the first");
    let mut titles: Vec<_> = t.rows().iter().map(|r| r.title.clone()).collect();
    titles.sort();
    assert_eq!(titles, ["Example login", "Secure note"]);

    // ---- 10. final lock: no plaintext anywhere ----
    t.dispatch(Action::Lock);
    s.dispatch(Action::Lock);
    assert!(t.is_clean() && s.is_clean());
    assert!(rig.clipboard.text().is_none() && rig2.clipboard.text().is_none());
    let _ = &rig2.clock;

    let sentinels: Vec<&str> = vec![
        MASTER,
        NEW_MASTER,
        EXPORT_PW,
        LOGIN_PW,
        LOGIN_NOTES,
        NOTE_BODY,
        PLAIN_VAL,
        HIDDEN_VAL,
        &totp_secret,
        &key_text_1,
        &key_text_1_after,
        &key_text_2,
    ];
    let key_lines: Vec<String> = [&key_text_1, &key_text_2]
        .iter()
        .flat_map(|k| k.lines().map(|l| l.trim().to_owned()))
        .filter(|l| l.len() >= 12)
        .collect();
    let mut haystacks = vec![format!("{s:?}"), format!("{t:?}")];
    for cfg in [&rig.config_dir, &rig2.config_dir] {
        let text = std::fs::read_to_string(cfg.join("config.json")).expect("config saved");
        haystacks.push(text);
    }
    haystacks.extend(notices.iter().cloned());
    assert!(!notices.is_empty(), "notices were captured");
    for hay in &haystacks {
        for needle in sentinels
            .iter()
            .copied()
            .chain(key_lines.iter().map(String::as_str))
        {
            assert!(!needle.is_empty());
            assert!(
                !hay.contains(needle),
                "plaintext found in {} chars of output",
                hay.len()
            );
        }
    }
}

fn unlock_via(s: &mut AppState, vault: &Path, key: &Path, pw: &str) {
    let f = s.open_form_mut();
    f.vault_path = vault.to_string_lossy().into_owned();
    f.key_path = key.to_string_lossy().into_owned();
    f.password.clear();
    f.password.push_str(pw);
    s.dispatch(Action::SubmitOpen);
}
