mod common;

use std::time::Duration;

use common::*;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use onlypassword_core::{Error, ItemId, ItemKind, SecretString, StoredItem, TotpAlgorithm, Vault};
use onlypassword_desktop::error::UiError;
use onlypassword_desktop::state::{Action, AppState, Screen};
use onlypassword_desktop::view;

const PWD: &str = "PWSENT-draft-password";
const NEWPWD: &str = "NEWPWSENT-changed";
const NOTES: &str = "NOTESENT-draft-notes";
const HID: &str = "HIDSENT-field";
const PLN: &str = "PLNSENT-field";
const TOTP_SENT: &str = "totp-ignored";

fn core(env: &Env) -> Vault {
    let key = onlypassword_core::keyfile::read(&env.path("u.key")).unwrap();
    Vault::unlock(&env.path("u.opw"), &SecretString::new(PW.to_owned()), &key).unwrap()
}

fn vault_bytes(env: &Env) -> Vec<u8> {
    std::fs::read(env.path("u.opw")).unwrap()
}

fn stored(env: &Env, st: &AppState, title: &str) -> StoredItem {
    let v = core(env);
    let row = st.rows().iter().find(|r| r.title == title).expect("row");
    v.get(&row.id).unwrap()
}

/// Fill a login draft with every field.
fn fill_login(st: &mut AppState) {
    st.dispatch(Action::BeginAdd(ItemKind::Login));
    assert_eq!(st.screen(), &Screen::Edit(None));
    st.dispatch(Action::SetTitle("Example".into()));
    st.dispatch(Action::SetUsername("alice".into()));
    st.dispatch(Action::AddUrl);
    st.dispatch(Action::AddUrl);
    st.dispatch(Action::SetUrl(0, "https://a.example".into()));
    st.dispatch(Action::SetUrl(1, "https://b.example".into()));
    st.dispatch(Action::SetTotpAlgorithm(TotpAlgorithm::Sha256));
    st.dispatch(Action::SetTotpDigits(8));
    st.dispatch(Action::SetTotpPeriod(60));
    st.dispatch(Action::AddField);
    st.dispatch(Action::AddField);
    st.dispatch(Action::SetFieldName(0, "Plain".into()));
    st.dispatch(Action::SetFieldName(1, "Hidden".into()));
    st.dispatch(Action::SetFieldHidden(1, true));
    let d = st.draft_mut().unwrap();
    d.password.push_str(PWD);
    d.notes.push_str(NOTES);
    d.totp_secret.push_str("jbsw y3dp ehpk 3pxp");
    d.fields[0].value.push_str(PLN);
    d.fields[1].value.push_str(HID);
}

fn add_example(env: &Env) -> (AppState, ItemId) {
    let (mut st, _) = env.unlocked();
    fill_login(&mut st);
    st.dispatch(Action::SaveDraft);
    assert!(st.notice().is_none(), "{:?}", st.notice());
    let Screen::Detail(id) = st.screen().clone() else {
        panic!("not on detail: {:?}", st.screen());
    };
    (st, id)
}

#[test]
fn add_login_with_every_field_reads_back() {
    let env = Env::new();
    let (st, id) = add_example(&env);
    assert!(st.draft().is_none());
    let got = core(&env).get(&id).unwrap();
    let i = &got.item;
    assert_eq!(got.revision, 1);
    assert_eq!(i.kind, ItemKind::Login);
    assert_eq!(i.title, "Example");
    assert_eq!(i.username.as_deref(), Some("alice"));
    assert_eq!(i.password.as_ref().unwrap().expose(), PWD);
    assert_eq!(i.urls, ["https://a.example", "https://b.example"]);
    assert_eq!(i.notes.expose(), NOTES);
    let t = i.totp.as_ref().unwrap();
    assert_eq!(t.secret.expose(), "JBSWY3DPEHPK3PXP");
    assert_eq!(t.algorithm, TotpAlgorithm::Sha256);
    assert_eq!((t.digits, t.period), (8, 60));
    assert_eq!(i.fields.len(), 2);
    assert_eq!(
        (
            i.fields[0].name.as_str(),
            i.fields[0].value.expose(),
            i.fields[0].hidden
        ),
        ("Plain", PLN, false)
    );
    assert_eq!(
        (
            i.fields[1].name.as_str(),
            i.fields[1].value.expose(),
            i.fields[1].hidden
        ),
        ("Hidden", HID, true)
    );
    assert!(st.rows().iter().any(|r| r.title == "Example" && r.id == id));
    assert_eq!(st.selected().unwrap().id, id);
}

#[test]
fn edit_item_changes_and_drops_old_values() {
    let env = Env::new();
    let (mut st, id) = add_example(&env);
    let created = core(&env).get(&id).unwrap().created_ms;
    st.dispatch(Action::BeginEdit);
    assert_eq!(st.screen(), &Screen::Edit(Some(id.clone())));
    {
        let d = st.draft().unwrap();
        assert_eq!(d.title, "Example");
        assert_eq!(d.password.expose(), PWD);
        assert_eq!(d.totp_secret.expose(), "JBSWY3DPEHPK3PXP");
    }
    st.dispatch(Action::SetTitle("Renamed".into()));
    st.dispatch(Action::RemoveUrl(0));
    let d = st.draft_mut().unwrap();
    d.password.clear();
    d.password.push_str(NEWPWD);
    d.totp_secret.clear();
    st.dispatch(Action::SaveDraft);
    assert!(st.notice().is_none());
    assert_eq!(st.screen(), &Screen::Detail(id.clone()));
    let got = core(&env).get(&id).unwrap();
    assert_eq!(got.revision, 2);
    assert_eq!(got.created_ms, created);
    assert_eq!(got.item.title, "Renamed");
    assert_eq!(got.item.password.as_ref().unwrap().expose(), NEWPWD);
    assert_eq!(got.item.urls, ["https://b.example"]);
    assert!(got.item.totp.is_none());
    assert!(st.rows().iter().any(|r| r.title == "Renamed"));
    assert!(!st.rows().iter().any(|r| r.title == "Example"));
}

#[test]
fn add_note_and_kind_switch_does_not_submit_login_fields() {
    let env = Env::new();
    let (mut st, _) = env.unlocked();
    st.dispatch(Action::BeginAdd(ItemKind::Note));
    st.dispatch(Action::SetTitle("My note".into()));
    st.draft_mut().unwrap().notes.push_str(NOTES);
    st.dispatch(Action::SaveDraft);
    let n = stored(&env, &st, "My note");
    assert_eq!(n.item.kind, ItemKind::Note);
    assert_eq!(n.item.notes.expose(), NOTES);

    // Type login values, then switch to a note.
    st.dispatch(Action::Back);
    st.dispatch(Action::BeginAdd(ItemKind::Login));
    st.dispatch(Action::SetTitle("Switched".into()));
    st.dispatch(Action::SetUsername("bob".into()));
    st.dispatch(Action::AddUrl);
    st.dispatch(Action::SetUrl(0, "https://x.example".into()));
    st.dispatch(Action::AddField);
    st.dispatch(Action::SetFieldName(0, "F".into()));
    let d = st.draft_mut().unwrap();
    d.password.push_str(TOTP_SENT);
    d.totp_secret.push_str("JBSWY3DPEHPK3PXP");
    d.notes.push_str("kept-notes");
    st.dispatch(Action::SetKind(ItemKind::Note));
    st.dispatch(Action::SaveDraft);
    assert!(st.notice().is_none(), "{:?}", st.notice());
    let n = stored(&env, &st, "Switched");
    let i = &n.item;
    assert_eq!(i.kind, ItemKind::Note);
    assert!(i.username.is_none() && i.password.is_none() && i.totp.is_none());
    assert!(i.urls.is_empty() && i.fields.is_empty());
    assert_eq!(i.notes.expose(), "kept-notes");
}

#[test]
fn invalid_drafts_keep_draft_and_vault_bytes() {
    let env = Env::new();
    let (mut st, _) = env.unlocked();
    let before = vault_bytes(&env);
    let long_totp = "A".repeat(210); // 129 bytes of base32 payload or more
    let long_title = "t".repeat(5000);
    let cases: Vec<(&str, &str, String)> = vec![
        ("empty title", "", String::new()),
        ("long title", &long_title, String::new()),
        ("bad totp", "T", "!!!".to_owned()),
        ("129 byte totp", "T", long_totp),
    ];
    for (name, title, totp) in cases {
        st.dispatch(Action::BeginAdd(ItemKind::Login));
        st.dispatch(Action::SetTitle(title.to_owned()));
        let d = st.draft_mut().unwrap();
        d.password.push_str(PWD);
        d.totp_secret.push_str(&totp);
        st.dispatch(Action::SaveDraft);
        assert_eq!(st.screen(), &Screen::Edit(None), "{name}");
        let n = st.notice().unwrap_or_else(|| panic!("{name}: no notice"));
        assert!(matches!(n, UiError::Core(_)), "{name}");
        let msg = n.to_string();
        assert!(!msg.contains(PWD) && !msg.contains("!!!"), "{name}");
        let d = st.draft().unwrap_or_else(|| panic!("{name}: draft lost"));
        assert_eq!(d.password.expose(), PWD, "{name}");
        assert_eq!(d.title, title, "{name}");
        assert_eq!(vault_bytes(&env), before, "{name}");
        st.dispatch(Action::CancelDraft);
    }
}

#[test]
fn delete_needs_request_then_confirm() {
    let env = Env::new();
    let (mut st, id) = add_example(&env);
    st.dispatch(Action::ConfirmDelete);
    assert!(core(&env).get(&id).is_ok(), "confirm without request");
    st.dispatch(Action::RequestDelete);
    assert!(st.delete_pending());
    st.dispatch(Action::CancelDelete);
    assert!(!st.delete_pending());
    st.dispatch(Action::ConfirmDelete);
    assert!(core(&env).get(&id).is_ok(), "confirm after cancel");
    // Select of another item cancels the pending request.
    st.dispatch(Action::RequestDelete);
    st.dispatch(Action::Select(id.clone()));
    assert!(!st.delete_pending());
    st.dispatch(Action::ConfirmDelete);
    assert!(core(&env).get(&id).is_ok());
    // Lock leaves it present.
    st.dispatch(Action::RequestDelete);
    st.dispatch(Action::Lock);
    assert!(core(&env).get(&id).is_ok());
    assert!(st.is_clean());
}

#[test]
fn confirmed_delete_removes_item_and_row() {
    let env = Env::new();
    let (mut st, id) = add_example(&env);
    st.dispatch(Action::RequestDelete);
    st.dispatch(Action::ConfirmDelete);
    assert_eq!(core(&env).get(&id).unwrap_err(), Error::NotFound);
    assert!(!st.rows().iter().any(|r| r.id == id));
    assert_eq!(st.screen(), &Screen::Browse);
    assert!(st.selected().is_none());
}

#[test]
fn idle_expiry_discards_draft() {
    let env = Env::new();
    let (mut st, clock) = env.unlocked();
    fill_login(&mut st);
    clock.advance(Duration::from_secs(301));
    st.tick();
    assert!(!st.is_unlocked());
    assert!(st.draft().is_none());
    assert!(st.is_clean());
    assert_eq!(st.screen(), &Screen::Unlock);
}

#[test]
fn cancel_navigation_and_lock_drop_draft_and_debug_is_redacted() {
    let env = Env::new();
    let (mut st, id) = add_example(&env);
    st.dispatch(Action::BeginEdit);
    let dbg = format!("{st:?}");
    for s in [PWD, NOTES, HID, PLN] {
        assert!(!dbg.contains(s));
    }
    assert!(!format!("{:?}", st.draft().unwrap()).contains(PWD));
    st.dispatch(Action::CancelDraft);
    assert!(st.draft().is_none());
    assert_eq!(st.screen(), &Screen::Detail(id.clone()));
    assert_eq!(core(&env).get(&id).unwrap().revision, 1);

    st.dispatch(Action::BeginEdit);
    st.dispatch(Action::Back);
    assert!(st.draft().is_none());
    assert_eq!(st.screen(), &Screen::Detail(id.clone()));
    st.dispatch(Action::Back);
    st.dispatch(Action::BeginAdd(ItemKind::Login));
    st.draft_mut().unwrap().password.push_str(PWD);
    st.dispatch(Action::ShowSettings);
    assert!(st.draft().is_none());
    st.dispatch(Action::CloseSettings);

    st.dispatch(Action::BeginAdd(ItemKind::Login));
    st.draft_mut().unwrap().password.push_str(PWD);
    st.dispatch(Action::Lock);
    assert!(st.draft().is_none());
    assert!(st.is_clean());
    assert!(!format!("{st:?}").contains(PWD));
}

#[test]
fn edit_failure_leaves_item_untouched() {
    let env = Env::new();
    let (mut st, id) = add_example(&env);
    st.dispatch(Action::BeginEdit);
    st.dispatch(Action::SetTitle(String::new()));
    let before = vault_bytes(&env);
    st.dispatch(Action::SaveDraft);
    assert!(st.notice().is_some());
    assert_eq!(st.screen(), &Screen::Edit(Some(id.clone())));
    assert_eq!(vault_bytes(&env), before);
    assert_eq!(core(&env).get(&id).unwrap().revision, 1);
}

fn harness(st: AppState) -> Harness<'static, AppState> {
    Harness::new_ui_state(|ui, s: &mut AppState| view::show(ui, s), st)
}

fn tree(h: &Harness<'_, AppState>) -> String {
    format!("{:?}", h.root())
}

#[test]
fn view_typing_password_masked_save_and_reveal() {
    let env = Env::new();
    let (st, _) = env.unlocked();
    let mut h = harness(st);
    h.run();
    h.get_by_label("Add Login").click();
    h.run();
    assert!(matches!(h.state().screen(), Screen::Edit(None)));
    h.get_by_label("Title").focus();
    h.run();
    h.get_by_label("Title").type_text("ViaView");
    h.run();
    h.get_by_label("Password").focus();
    h.run();
    h.get_by_label("Password").type_text(PWD);
    h.run();
    assert_eq!(h.state().draft().unwrap().password.expose(), PWD);
    assert_eq!(h.state().draft().unwrap().title, "ViaView");
    assert!(!tree(&h).contains(PWD), "password in accessibility tree");
    // The reveal toggle shows this field only.
    h.get_by_label("Notes").focus();
    h.run();
    h.get_by_label("Notes").type_text(NOTES);
    h.run();
    h.get_by_label("Reveal Password").click();
    h.run();
    let t = tree(&h);
    assert!(t.contains(PWD));
    assert!(!t.contains(NOTES));
    h.get_by_label("Hide Password").click();
    h.run();
    assert!(!tree(&h).contains(PWD));
    h.get_by_label("Save").click();
    h.run();
    let st = h.state();
    assert!(
        matches!(st.screen(), Screen::Detail(_)),
        "{:?}",
        st.notice()
    );
    let row = st.rows().iter().find(|r| r.title == "ViaView").unwrap();
    let got = core(&env).get(&row.id).unwrap();
    assert_eq!(got.item.password.as_ref().unwrap().expose(), PWD);
    assert_eq!(got.item.notes.expose(), NOTES);
    // Detail offers Edit and Delete.
    h.get_by_label("Delete").click();
    h.run();
    let t = tree(&h);
    assert!(t.contains("Delete \\\"ViaView\\\"?") || t.contains("ViaView"));
    assert!(!t.contains(PWD));
    h.get_by_label("Cancel delete").click();
    h.run();
    h.get_by_label("Edit").click();
    h.run();
    assert!(matches!(h.state().screen(), Screen::Edit(Some(_))));
    h.get_by_label("Cancel").click();
    h.run();
    assert!(h.state().draft().is_none());
}
