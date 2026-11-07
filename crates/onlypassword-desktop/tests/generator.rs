mod common;

use common::*;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use onlypassword_core::{Error, ItemKind, PassphraseOptions, PasswordOptions, SecretString, Vault};
use onlypassword_desktop::error::UiError;
use onlypassword_desktop::state::{Action, AppState, GeneratorMode, Screen};
use onlypassword_desktop::view;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";
const AMBIGUOUS: &str = "0Oo1lI";

fn gen_with(st: &mut AppState, o: PasswordOptions) -> String {
    st.dispatch(Action::SetPasswordOptions(o));
    st.dispatch(Action::GenerateNow);
    assert!(st.notice().is_none(), "{:?}", st.notice());
    st.generator()
        .unwrap()
        .value()
        .expect("value")
        .expose()
        .to_owned()
}

fn phrase_with(st: &mut AppState, o: PassphraseOptions) -> String {
    st.dispatch(Action::SetGeneratorMode(GeneratorMode::Passphrase));
    st.dispatch(Action::SetPassphraseOptions(o));
    st.dispatch(Action::GenerateNow);
    assert!(st.notice().is_none(), "{:?}", st.notice());
    st.generator()
        .unwrap()
        .value()
        .expect("value")
        .expose()
        .to_owned()
}

fn has(s: &str, set: &str) -> bool {
    s.chars().any(|c| set.contains(c))
}

fn invalid_msg() -> String {
    UiError::Core(Error::InvalidInput("x")).to_string()
}

#[test]
fn defaults_match_core_and_give_twenty_chars_with_all_classes() {
    let env = Env::new();
    let (mut st, _) = env.unlocked();
    let g = st.generator().unwrap();
    assert_eq!(g.password, PasswordOptions::default());
    assert_eq!(g.passphrase, PassphraseOptions::default());
    assert_eq!(g.mode, GeneratorMode::Password);
    assert!(g.value().is_none());
    st.dispatch(Action::GenerateNow);
    let v = st.generator().unwrap().value().unwrap().expose().to_owned();
    assert_eq!(v.chars().count(), 20);
    for set in [LOWER, UPPER, DIGITS, SYMBOLS] {
        assert!(has(&v, set), "missing class {set}");
    }
}

#[test]
fn password_option_variants_are_accepted() {
    let env = Env::new();
    let (mut st, _) = env.unlocked();
    let d = PasswordOptions::default;
    assert_eq!(
        gen_with(&mut st, PasswordOptions { length: 4, ..d() })
            .chars()
            .count(),
        4
    );
    assert_eq!(
        gen_with(&mut st, PasswordOptions { length: 256, ..d() })
            .chars()
            .count(),
        256
    );
    let v = gen_with(
        &mut st,
        PasswordOptions {
            exclude_ambiguous: true,
            length: 128,
            ..d()
        },
    );
    assert!(!has(&v, AMBIGUOUS));
    let v = gen_with(
        &mut st,
        PasswordOptions {
            lower: false,
            ..d()
        },
    );
    assert!(!has(&v, LOWER) && has(&v, UPPER));
    let v = gen_with(
        &mut st,
        PasswordOptions {
            upper: false,
            ..d()
        },
    );
    assert!(!has(&v, UPPER) && has(&v, LOWER));
    let v = gen_with(
        &mut st,
        PasswordOptions {
            digits: false,
            ..d()
        },
    );
    assert!(!has(&v, DIGITS) && has(&v, LOWER));
    let v = gen_with(
        &mut st,
        PasswordOptions {
            symbols: false,
            ..d()
        },
    );
    assert!(!has(&v, SYMBOLS) && has(&v, DIGITS));
}

#[test]
fn passphrase_option_variants_are_accepted() {
    let env = Env::new();
    let (mut st, _) = env.unlocked();
    let d = PassphraseOptions::default;
    assert_eq!(
        phrase_with(&mut st, PassphraseOptions { words: 4, ..d() })
            .matches('-')
            .count(),
        3
    );
    assert_eq!(
        phrase_with(&mut st, PassphraseOptions { words: 24, ..d() })
            .matches('-')
            .count(),
        23
    );
    let v = phrase_with(
        &mut st,
        PassphraseOptions {
            separator: ".".into(),
            ..d()
        },
    );
    assert_eq!(v.matches('.').count(), 6);
    assert!(!v.contains('-'));
    let v = phrase_with(
        &mut st,
        PassphraseOptions {
            capitalize: true,
            ..d()
        },
    );
    assert!(v
        .split('-')
        .all(|w| w.chars().next().is_some_and(char::is_uppercase)));
    let v = phrase_with(
        &mut st,
        PassphraseOptions {
            include_digit: true,
            ..d()
        },
    );
    assert!(has(&v, DIGITS));
}

#[test]
fn invalid_options_show_core_message_and_keep_no_value() {
    let env = Env::new();
    let (mut st, _) = env.unlocked();
    // A valid value first: a failed generation must drop it.
    st.dispatch(Action::GenerateNow);
    assert!(st.generator().unwrap().value().is_some());
    let d = PasswordOptions::default;
    let bad = [
        PasswordOptions { length: 3, ..d() },
        PasswordOptions {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            ..d()
        },
    ];
    for o in bad {
        st.dispatch(Action::SetPasswordOptions(o));
        st.dispatch(Action::GenerateNow);
        assert_eq!(st.notice().unwrap().to_string(), invalid_msg());
        assert!(st.generator().unwrap().value().is_none());
        st.dispatch(Action::SetPasswordOptions(d()));
        st.dispatch(Action::GenerateNow);
        assert!(st.generator().unwrap().value().is_some());
    }
    st.dispatch(Action::SetGeneratorMode(GeneratorMode::Passphrase));
    let p = PassphraseOptions::default;
    for o in [
        PassphraseOptions { words: 25, ..p() },
        PassphraseOptions {
            separator: "123456789".into(),
            ..p()
        },
    ] {
        st.dispatch(Action::SetPassphraseOptions(p()));
        st.dispatch(Action::GenerateNow);
        assert!(st.generator().unwrap().value().is_some());
        st.dispatch(Action::SetPassphraseOptions(o));
        st.dispatch(Action::GenerateNow);
        assert_eq!(st.notice().unwrap().to_string(), invalid_msg());
        assert!(st.generator().unwrap().value().is_none());
    }
}

fn core(env: &Env) -> Vault {
    let key = onlypassword_core::keyfile::read(&env.path("u.key")).unwrap();
    Vault::unlock(&env.path("u.opw"), &SecretString::new(PW.to_owned()), &key).unwrap()
}

#[test]
fn use_generated_replaces_draft_password_and_saves() {
    let env = Env::new();
    let (mut st, _) = env.unlocked();
    st.dispatch(Action::BeginAdd(ItemKind::Login));
    st.dispatch(Action::SetTitle("Gen".into()));
    st.draft_mut()
        .unwrap()
        .password
        .push_str("OLDPASS-sentinel");
    st.dispatch(Action::GenerateNow);
    let v = st.generator().unwrap().value().unwrap().expose().to_owned();
    st.dispatch(Action::UseGenerated);
    assert!(st.notice().is_none());
    assert_eq!(st.draft().unwrap().password.expose(), v);
    assert!(st.generator().unwrap().value().is_none());
    st.dispatch(Action::SaveDraft);
    let row = st.rows().iter().find(|r| r.title == "Gen").unwrap();
    let got = core(&env).get(&row.id).unwrap();
    assert_eq!(got.item.password.as_ref().unwrap().expose(), v);
}

#[test]
fn use_generated_without_draft_is_rejected() {
    let env = Env::new();
    let (mut st, _) = env.unlocked();
    st.dispatch(Action::GenerateNow);
    let before = st.generator().unwrap().value().unwrap().expose().to_owned();
    st.dispatch(Action::UseGenerated);
    assert_eq!(st.notice(), Some(&UiError::NoSelection));
    assert_eq!(st.generator().unwrap().value().unwrap().expose(), before);
    assert_eq!(st.screen(), &Screen::Browse);
}

#[test]
fn value_dropped_on_discard_lock_close_and_cancel() {
    let env = Env::new();
    let (mut st, _) = env.unlocked();
    st.dispatch(Action::GenerateNow);
    st.dispatch(Action::DiscardGenerated);
    assert!(st.generator().unwrap().value().is_none());
    // Standalone screen close.
    st.dispatch(Action::ShowGenerator);
    assert_eq!(st.screen(), &Screen::Generator);
    st.dispatch(Action::GenerateNow);
    st.dispatch(Action::CloseGenerator);
    assert_eq!(st.screen(), &Screen::Browse);
    assert!(st.generator().unwrap().value().is_none());
    // Side panel close and draft cancel.
    st.dispatch(Action::BeginAdd(ItemKind::Login));
    st.dispatch(Action::ToggleGeneratorPanel);
    assert!(st.generator().unwrap().panel_open());
    st.dispatch(Action::GenerateNow);
    st.dispatch(Action::ToggleGeneratorPanel);
    assert!(st.generator().unwrap().value().is_none());
    st.dispatch(Action::ToggleGeneratorPanel);
    st.dispatch(Action::GenerateNow);
    st.dispatch(Action::CancelDraft);
    assert!(st.generator().unwrap().value().is_none());
    assert!(!st.generator().unwrap().panel_open());
    // Lock.
    st.dispatch(Action::ShowGenerator);
    st.dispatch(Action::GenerateNow);
    st.dispatch(Action::Lock);
    assert!(st.generator().is_none());
    assert!(st.is_clean());
}

#[test]
fn copy_generated_uses_clipboard_and_timed_clear() {
    let env = Env::new();
    let (mut st, clock) = env.unlocked();
    st.dispatch(Action::GenerateNow);
    let v = st.generator().unwrap().value().unwrap().expose().to_owned();
    st.dispatch(Action::CopyGenerated);
    assert_eq!(env.clipboard.text().as_deref(), Some(v.as_str()));
    assert!(env.clipboard.sensitive());
    assert_eq!(env.clipboard.sets(), 1);
    clock.advance(std::time::Duration::from_secs(31));
    st.tick();
    assert_eq!(env.clipboard.text(), None);
    assert_eq!(env.clipboard.clears(), 1);
}

#[test]
fn copy_without_value_is_rejected() {
    let env = Env::new();
    let (mut st, _) = env.unlocked();
    st.dispatch(Action::CopyGenerated);
    assert_eq!(st.notice(), Some(&UiError::NoSelection));
    assert_eq!(env.clipboard.sets(), 0);
}

fn harness(st: AppState) -> Harness<'static, AppState> {
    Harness::new_ui_state(|ui, s: &mut AppState| view::show(ui, s), st)
}

#[test]
fn view_value_masked_until_reveal_and_use_this_fills_form() {
    let env = Env::new();
    let (st, _) = env.unlocked();
    let mut h = harness(st);
    h.run();
    h.get_by_label("Add Login").click();
    h.run();
    h.get_by_label("Generator").click();
    h.run();
    assert!(h.state().generator().unwrap().panel_open());
    h.get_by_label("Generate").click();
    h.run();
    let v = h
        .state()
        .generator()
        .unwrap()
        .value()
        .unwrap()
        .expose()
        .to_owned();
    assert!(!format!("{:?}", h.root()).contains(&v), "value in tree");
    h.get_by_label("Reveal generated").click();
    h.run();
    assert!(
        format!("{:?}", h.root()).contains(&v),
        "value not shown after reveal"
    );
    h.get_by_label("Hide generated").click();
    h.run();
    assert!(!format!("{:?}", h.root()).contains(&v));
    assert!(h.state().draft().unwrap().password.is_empty());
    h.get_by_label("Use this").click();
    h.run();
    assert_eq!(h.state().draft().unwrap().password.expose(), v);
    assert!(h.state().generator().unwrap().value().is_none());
}

#[test]
fn view_standalone_generator_has_no_use_button() {
    let env = Env::new();
    let (st, _) = env.unlocked();
    let mut h = harness(st);
    h.run();
    h.get_by_label("Generator").click();
    h.run();
    assert_eq!(h.state().screen(), &Screen::Generator);
    h.get_by_label("Generate").click();
    h.run();
    assert!(h.query_by_label("Use this").is_none());
    h.get_by_label("Close generator").click();
    h.run();
    assert_eq!(h.state().screen(), &Screen::Browse);
}

#[test]
fn source_has_no_random_source() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p).unwrap();
                for bad in [
                    "getrandom",
                    "rand::",
                    "use rand",
                    "SystemTime",
                    "thread_rng",
                ] {
                    // The clock module legitimately reads wall time for the UI, not for generation.
                    if p.ends_with("clock.rs") && bad == "SystemTime" {
                        continue;
                    }
                    assert!(!text.contains(bad), "{} contains {bad}", p.display());
                }
            }
        }
    }
}
