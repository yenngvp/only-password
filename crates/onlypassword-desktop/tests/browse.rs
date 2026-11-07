mod common;

use common::*;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use onlypassword_core::crypto::kdf::KdfParams;
use onlypassword_core::crypto::keys::SecretKey;
use onlypassword_core::{
    CustomField, Item, ItemId, ItemKind, SecretString, TotpAlgorithm, TotpConfig, Vault,
};
use onlypassword_desktop::state::{Action, AppState, FieldRef, Row, Screen};
use onlypassword_desktop::view;
use std::path::{Path, PathBuf};
use zeroize::ZeroizeOnDrop;

const PWD: &str = "PWSENT-login-password";
const NOTE: &str = "NOTESENT-login-notes";
const TOTP: &str = "JBSWY3DPEHPK3PXP";
const HIDDEN: &str = "HIDDENSENT-value";
const PLAIN: &str = "PLAINSENT-value";

fn s(x: &str) -> SecretString {
    SecretString::new(x.to_owned())
}

fn login(title: &str, user: &str, urls: &[&str]) -> Item {
    let mut i = Item::new_login(title);
    i.username = Some(user.to_owned());
    i.password = Some(s("pw-for-others"));
    i.urls = urls.iter().map(|u| (*u).to_owned()).collect();
    i
}

/// Vault with five items made through the core; returns paths.
fn fixture(env: &Env) -> (PathBuf, PathBuf) {
    let (vp, kp) = env.make_vault("b.opw", "b.key");
    let key = onlypassword_core::keyfile::read(&kp).unwrap();
    let mut v = Vault::unlock(&vp, &s(PW), &key).unwrap();
    let mut gh = login("GitHub", "octo", &["https://github.com/login"]);
    gh.password = Some(s(PWD));
    gh.notes = s(NOTE);
    gh.totp = Some(TotpConfig {
        secret: s(TOTP),
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period: 30,
    });
    v.add(&gh).unwrap();
    let mut h = login("Bank", "alice", &[]);
    h.fields = vec![
        CustomField {
            name: "PIN".into(),
            value: s(HIDDEN),
            hidden: true,
        },
        CustomField {
            name: "Branch".into(),
            value: s(PLAIN),
            hidden: false,
        },
    ];
    v.add(&h).unwrap();
    v.add(&Item::new_note("Memo", s("memo-body-SENT"))).unwrap();
    v.add(&login("İstanbul ΣΑΣ", "ünï", &["https://example.org/Ä"]))
        .unwrap();
    let mut onlypw = login("Zeta", "zed", &[]);
    onlypw.password = Some(s("only-in-password-SENT"));
    v.add(&onlypw).unwrap();
    v.lock();
    (vp, kp)
}

fn unlocked(env: &Env) -> (AppState, PathBuf, PathBuf) {
    let (vp, kp) = fixture(env);
    let mut st = env.state();
    fill_open(&mut st, &vp, &kp, PW);
    st.dispatch(Action::SubmitOpen);
    assert!(st.is_unlocked(), "{:?}", st.notice());
    (st, vp, kp)
}

fn core_vault(vp: &Path, kp: &Path) -> Vault {
    let key: SecretKey = onlypassword_core::keyfile::read(kp).unwrap();
    Vault::unlock(vp, &s(PW), &key).unwrap()
}

fn id_of(st: &AppState, title: &str) -> ItemId {
    st.rows()
        .iter()
        .find(|r| r.title == title)
        .unwrap()
        .id
        .clone()
}

#[test]
fn rows_equal_list_order() {
    let env = Env::new();
    let (st, vp, kp) = unlocked(&env);
    let list = core_vault(&vp, &kp).list().unwrap();
    assert_eq!(list.len(), 5);
    let got: Vec<_> = st
        .rows()
        .iter()
        .map(|r| (r.id.clone(), r.kind, r.title.clone(), r.username.clone()))
        .collect();
    let want: Vec<_> = list
        .iter()
        .map(|i| (i.id.clone(), i.kind, i.title.clone(), i.username.clone()))
        .collect();
    assert_eq!(got, want);
}

#[test]
fn search_matches_core() {
    let env = Env::new();
    let (mut st, vp, kp) = unlocked(&env);
    let core = core_vault(&vp, &kp);
    for q in [
        "gith",
        "oct",
        "github.com",
        "GiThUb",
        "ı",
        "İ",
        "Σ",
        "σ",
        "ς",
        "ÜNÏ",
        "example.org/ä",
        "",
        "zzz",
    ] {
        st.dispatch(Action::Search(q.to_owned()));
        let want: Vec<ItemId> = core.search(q).unwrap().into_iter().map(|i| i.id).collect();
        let got: Vec<ItemId> = st.rows().iter().map(|r| r.id.clone()).collect();
        assert_eq!(got, want, "query {q:?}");
        assert_eq!(st.search_text(), q);
    }
    st.dispatch(Action::Search("gith".into()));
    assert_eq!(st.rows().len(), 1);
    for q in [
        "PWSENT",
        NOTE,
        HIDDEN,
        "only-in-password",
        "memo-body",
        PLAIN,
    ] {
        st.dispatch(Action::Search(q.to_owned()));
        assert!(st.rows().is_empty(), "query {q:?}");
    }
}

#[test]
fn select_shows_every_field() {
    let env = Env::new();
    let (mut st, _, _) = unlocked(&env);
    let id = id_of(&st, "GitHub");
    st.dispatch(Action::Select(id.clone()));
    assert_eq!(st.screen(), &Screen::Detail(id));
    let it = &st.selected().unwrap().item;
    assert_eq!(it.title, "GitHub");
    assert_eq!(it.username.as_deref(), Some("octo"));
    assert_eq!(it.password.as_ref().unwrap().expose(), PWD);
    assert_eq!(it.urls, vec!["https://github.com/login".to_owned()]);
    assert_eq!(it.notes.expose(), NOTE);
    assert_eq!(it.totp.as_ref().unwrap().secret.expose(), TOTP);

    let id = id_of(&st, "Bank");
    st.dispatch(Action::Select(id));
    let it = &st.selected().unwrap().item;
    assert_eq!(it.fields.len(), 2);
    assert_eq!(
        (
            it.fields[0].name.as_str(),
            it.fields[0].value.expose(),
            it.fields[0].hidden
        ),
        ("PIN", HIDDEN, true)
    );
    assert_eq!(
        (
            it.fields[1].name.as_str(),
            it.fields[1].value.expose(),
            it.fields[1].hidden
        ),
        ("Branch", PLAIN, false)
    );

    let id = id_of(&st, "Memo");
    st.dispatch(Action::Select(id));
    let it = &st.selected().unwrap().item;
    assert_eq!(it.kind, ItemKind::Note);
    assert_eq!(it.notes.expose(), "memo-body-SENT");
}

#[test]
fn reveal_cleared_on_select_back_lock() {
    let env = Env::new();
    let (mut st, _, _) = unlocked(&env);
    let a = id_of(&st, "GitHub");
    let b = id_of(&st, "Bank");
    st.dispatch(Action::Select(a));
    st.dispatch(Action::ToggleReveal(FieldRef::Password));
    st.dispatch(Action::ToggleReveal(FieldRef::Notes));
    assert!(st.is_revealed(FieldRef::Password) && st.is_revealed(FieldRef::Notes));
    st.dispatch(Action::ToggleReveal(FieldRef::Notes));
    assert!(!st.is_revealed(FieldRef::Notes));
    // Fields the item does not have cannot be revealed.
    st.dispatch(Action::ToggleReveal(FieldRef::Custom(0)));
    assert!(!st.is_revealed(FieldRef::Custom(0)));
    st.dispatch(Action::Select(b));
    assert!(st.revealed().unwrap().is_empty());
    st.dispatch(Action::ToggleReveal(FieldRef::Custom(0)));
    st.dispatch(Action::ToggleReveal(FieldRef::Custom(1))); // not hidden
    assert!(st.is_revealed(FieldRef::Custom(0)) && !st.is_revealed(FieldRef::Custom(1)));
    st.dispatch(Action::Back);
    assert_eq!(st.screen(), &Screen::Browse);
    assert!(st.revealed().unwrap().is_empty());
    assert!(st.selected().is_none());

    let a = id_of(&st, "GitHub");
    st.dispatch(Action::Select(a));
    st.dispatch(Action::ToggleReveal(FieldRef::Password));
    st.dispatch(Action::Lock);
    assert!(st.revealed().is_none());
    assert!(st.is_clean());
    assert!(st.rows().is_empty() && st.selected().is_none() && st.search_text().is_empty());
    let dbg = format!("{st:?}");
    for t in ["GitHub", "Bank", "Memo", "octo", "Zeta"] {
        assert!(!dbg.contains(t));
    }
}

#[test]
fn lock_drops_search_text() {
    let env = Env::new();
    let (mut st, vp, kp) = unlocked(&env);
    st.dispatch(Action::Search("gith".into()));
    st.dispatch(Action::Lock);
    assert_eq!(st.search_text(), "");
    fill_open(&mut st, &vp, &kp, PW);
    st.dispatch(Action::SubmitOpen);
    assert_eq!(st.search_text(), "");
    assert_eq!(st.rows().len(), 5);
}

fn assert_zod<T: ZeroizeOnDrop>() {}

#[test]
fn row_zeroizes_and_debug_is_redacted() {
    assert_zod::<Row>();
    let env = Env::new();
    let (mut st, _, _) = unlocked(&env);
    let row_dbg = format!("{:?}", st.rows());
    assert!(!row_dbg.contains("GitHub") && !row_dbg.contains("octo"));
    let id = id_of(&st, "GitHub");
    st.dispatch(Action::Select(id));
    let d = format!("{st:?}");
    assert!(!d.contains("GitHub") && !d.contains(PWD) && !d.contains("octo"));
    let det = onlypassword_desktop::state::Detail(
        onlypassword_core::Vault::get(
            &core_vault(&env.path("b.opw"), &env.path("b.key")),
            &id_of(&st, "GitHub"),
        )
        .unwrap(),
    );
    let d = format!("{det:?}");
    assert!(!d.contains("GitHub") && !d.contains(PWD));
    let _ = KdfParams::FAST_FOR_TESTS;
}

fn harness(st: AppState) -> Harness<'static, AppState> {
    Harness::new_ui_state(|ui, s: &mut AppState| view::show(ui, s), st)
}

fn tree(h: &Harness<'_, AppState>) -> String {
    format!("{:?}", h.root())
}

#[test]
fn view_masks_and_reveals() {
    let env = Env::new();
    let (mut st, _, _) = unlocked(&env);
    let id = id_of(&st, "GitHub");
    st.dispatch(Action::Select(id));
    let mut h = harness(st);
    h.run();
    let t = tree(&h);
    assert!(t.contains("GitHub") && t.contains("octo"));
    assert!(t.contains(view::MASK));
    for secret in [PWD, NOTE, TOTP, HIDDEN] {
        assert!(!t.contains(secret), "{secret} leaked");
    }
    h.get_by_label("Reveal Password").click();
    h.run();
    let t = tree(&h);
    assert!(t.contains(PWD));
    for secret in [NOTE, TOTP, HIDDEN] {
        assert!(!t.contains(secret), "{secret} leaked");
    }
    h.get_by_label("Hide Password").click();
    h.run();
    assert!(!tree(&h).contains(PWD));
}

#[test]
fn view_hidden_custom_field_and_plain_field() {
    let env = Env::new();
    let (mut st, _, _) = unlocked(&env);
    let id = id_of(&st, "Bank");
    st.dispatch(Action::Select(id));
    let mut h = harness(st);
    h.run();
    let t = tree(&h);
    assert!(t.contains("PIN") && t.contains(PLAIN) && !t.contains(HIDDEN));
    h.get_by_label("Reveal PIN").click();
    h.run();
    assert!(tree(&h).contains(HIDDEN));
}

#[test]
fn view_browse_click_row_and_search_and_lock() {
    let env = Env::new();
    let (st, _, _) = unlocked(&env);
    let mut h = harness(st);
    h.run();
    h.get_by_label_contains("Memo").click();
    h.run();
    assert!(matches!(h.state().screen(), Screen::Detail(_)));
    h.get_by_label("Back").click();
    h.run();
    assert_eq!(h.state().screen(), &Screen::Browse);
    h.get_by_label("Search").focus();
    h.run();
    h.get_by_label("Search").type_text("gith");
    h.run();
    assert_eq!(h.state().rows().len(), 1);
    h.get_by_label("Lock").click();
    h.run();
    let t = tree(&h);
    assert!(h.state().is_clean());
    for title in ["GitHub", "Bank", "Memo", "Zeta", "octo"] {
        assert!(!t.contains(title), "{title} on the unlock screen");
    }
}

#[test]
fn placeholder_is_independent_of_length() {
    let env = Env::new();
    let (vp, kp) = env.make_vault("c.opw", "c.key");
    let mut v = core_vault(&vp, &kp);
    for (title, pw) in [("One", "x".to_owned()), ("Long", "y".repeat(200))] {
        let mut i = Item::new_login(title);
        i.password = Some(s(&pw));
        v.add(&i).unwrap();
    }
    v.lock();
    let mut st = env.state();
    fill_open(&mut st, &vp, &kp, PW);
    st.dispatch(Action::SubmitOpen);
    let mut trees = Vec::new();
    for title in ["One", "Long"] {
        let id = id_of(&st, title);
        st.dispatch(Action::Select(id));
        let mut h = harness(st);
        h.run();
        let n = h.get_all_by_label(view::MASK).count();
        let t = tree(&h);
        assert!(!t.contains("xxxx") && !t.contains("yyyy"));
        trees.push((n, t.matches(view::MASK).count()));
        st = {
            let mut s2 = std::mem::replace(h.state_mut(), env.state());
            s2.dispatch(Action::Back);
            s2
        };
    }
    assert_eq!(trees[0], trees[1]);
    assert_eq!(view::MASK.chars().count(), 8);
}
