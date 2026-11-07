mod common;

use common::*;
use egui_kittest::Harness;
use onlypassword_core::base32;
use onlypassword_core::{Item, SecretString, TotpAlgorithm, TotpConfig, Vault};
use onlypassword_desktop::clock::ManualClock;
use onlypassword_desktop::state::{totp_view, Action, AppState, FieldRef};
use onlypassword_desktop::view;
use std::time::Duration;

/// (secret as base32, [(time, code)]) for SHA1 / 8 digits from the shared vectors.
fn sha1_vectors() -> (String, Vec<(u64, String)>) {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/totp.json");
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut secret = String::new();
    let mut out = Vec::new();
    for v in doc["vectors"].as_array().unwrap() {
        if v["mode"] == "SHA1" {
            let raw = base32::hex_decode(v["secret_hex"].as_str().unwrap()).unwrap();
            secret = base32::encode(&raw);
            out.push((
                v["time"].as_u64().unwrap(),
                v["totp"].as_str().unwrap().to_owned(),
            ));
        }
    }
    assert!(out.len() >= 3);
    (secret, out)
}

fn cfg(secret: &str, digits: u8, period: u32) -> TotpConfig {
    TotpConfig {
        secret: SecretString::new(secret.to_owned()),
        algorithm: TotpAlgorithm::Sha1,
        digits,
        period,
    }
}

/// Detail state of a TOTP login ("Authy") and a plain login ("Plain").
fn state(env: &Env, secret: &str, period: u32) -> (AppState, ManualClock) {
    let (vp, kp) = env.make_vault("t.opw", "t.key");
    let key = onlypassword_core::keyfile::read(&kp).unwrap();
    let mut v = Vault::unlock(&vp, &SecretString::new(PW.to_owned()), &key).unwrap();
    let mut it = Item::new_login("Authy");
    it.totp = Some(cfg(secret, 8, period));
    v.add(&it).unwrap();
    v.add(&Item::new_login("Plain")).unwrap();
    v.lock();
    let (mut s, clock) = env.state_with_clock();
    fill_open(&mut s, &vp, &kp, PW);
    s.dispatch(Action::SubmitOpen);
    assert!(s.is_unlocked(), "{:?}", s.notice());
    select(&mut s, "Authy");
    (s, clock)
}

fn select(s: &mut AppState, title: &str) {
    if *s.screen() != onlypassword_desktop::state::Screen::Browse {
        s.dispatch(Action::Back);
    }
    let id = s
        .rows()
        .iter()
        .find(|r| r.title == title)
        .unwrap()
        .id
        .clone();
    s.dispatch(Action::Select(id));
}

fn code(s: &AppState) -> String {
    s.totp().unwrap().code.as_ref().unwrap().to_string()
}

#[test]
fn vector_codes_and_remaining() {
    let (secret, vecs) = sha1_vectors();
    let env = Env::new();
    let (mut s, clock) = state(&env, &secret, 30);
    // 1111111109 % 30 = 29, so 1 s remain (the criterion text says 21; see spec-issues.md).
    for (t, expect_remaining) in [(59u64, 1u32), (1111111109, 1), (20000000000, 10)] {
        clock.set_unix(t);
        s.tick();
        let want = &vecs.iter().find(|(vt, _)| *vt == t).unwrap().1;
        assert_eq!(&code(&s), want, "time {t}");
        assert_eq!(s.totp().unwrap().remaining, expect_remaining, "time {t}");
    }
}

#[test]
fn boundary_changes_code_without_input() {
    let (secret, _) = sha1_vectors();
    let env = Env::new();
    let (mut s, clock) = state(&env, &secret, 30);
    clock.set_unix(59);
    s.tick();
    let before = code(&s);
    assert_eq!(s.totp().unwrap().remaining, 1);
    clock.set_unix(60);
    s.tick();
    assert_ne!(code(&s), before);
    assert_eq!(s.totp().unwrap().remaining, 30);
    // Same period: code is stable.
    let c = code(&s);
    clock.advance(Duration::from_secs(5));
    s.tick();
    assert_eq!(code(&s), c);
    assert_eq!(s.totp().unwrap().remaining, 25);
}

#[test]
fn remaining_is_in_range() {
    let (secret, _) = sha1_vectors();
    for period in [1u32, 30, 300] {
        for t in (0..2000u64).chain([59, 1111111109, 20000000000, u64::MAX]) {
            let v = totp_view(&cfg(&secret, 8, period), t);
            assert!((1..=period).contains(&v.remaining), "p{period} t{t}");
            assert_eq!(
                u64::from(v.remaining),
                u64::from(period) - t % u64::from(period)
            );
        }
    }
}

#[test]
fn invalid_parameters_show_core_message() {
    let (secret, _) = sha1_vectors();
    let v = totp_view(&cfg(&secret, 9, 30), 59);
    assert!(v.code.is_none());
    let want = onlypassword_core::Error::InvalidInput("x").to_string();
    assert_eq!(v.error.as_deref(), Some(want.as_str()));
    // Bad period, bad secret and period 0 do not panic either.
    assert!(totp_view(&cfg(&secret, 8, 0), 59).code.is_none());
    assert!(totp_view(&cfg(&secret, 8, 301), 59).code.is_none());
    assert!(totp_view(&cfg("!!!", 8, 30), 59).code.is_none());
    assert!(totp_view(&cfg(&secret, 5, 30), u64::MAX).code.is_none());
    // The error view renders the message and no code.
    let mut h = Harness::new_ui_state(
        |ui, v: &mut onlypassword_desktop::state::TotpView| {
            view::totp_section(ui, v, &mut None);
        },
        v,
    );
    h.run();
    let t = format!("{:?}", h.root());
    assert!(t.contains(&want));
    assert!(!t.contains("Copy TOTP code"));
}

#[test]
fn no_totp_section_and_state_dropped() {
    let (secret, _) = sha1_vectors();
    let env = Env::new();
    let (mut s, _clock) = state(&env, &secret, 30);
    assert!(s.totp().is_some());
    select(&mut s, "Plain");
    assert!(s.totp().is_none());
    s.tick();
    assert!(s.totp().is_none());
    select(&mut s, "Authy");
    assert!(s.totp().is_some());
    s.dispatch(Action::Back);
    assert!(s.totp().is_none());
    select(&mut s, "Authy");
    s.dispatch(Action::Lock);
    assert!(s.totp().is_none());
    assert!(s.is_clean());
    // Copy of an absent code does nothing.
    s.dispatch(Action::Copy(FieldRef::TotpCode));
    assert!(env.clipboard.text().is_none());
}

#[test]
fn view_shows_code_and_countdown_not_secret() {
    let (secret, vecs) = sha1_vectors();
    let env = Env::new();
    let (mut s, clock) = state(&env, &secret, 30);
    clock.set_unix(1111111109);
    s.tick();
    let mut h = Harness::new_ui_state(|ui, s: &mut AppState| view::show(ui, s), s);
    h.run();
    let t = format!("{:?}", h.root());
    let want = &vecs.iter().find(|(vt, _)| *vt == 1111111109).unwrap().1;
    assert!(t.contains(want.as_str()), "code missing");
    assert!(t.contains("Expires in 1 s"));
    assert!(!t.contains(&secret), "masked secret leaked");
    // Plain login: no TOTP section.
    let s = h.state_mut();
    select(s, "Plain");
    h.run();
    let t = format!("{:?}", h.root());
    assert!(!t.contains("TOTP code") && !t.contains("Expires in"));
}

#[test]
fn copy_code_uses_clipboard_and_clears() {
    let (secret, vecs) = sha1_vectors();
    let env = Env::new();
    let (mut s, clock) = state(&env, &secret, 30);
    clock.set_unix(59);
    s.tick();
    s.dispatch(Action::Copy(FieldRef::TotpCode));
    let want = &vecs.iter().find(|(vt, _)| *vt == 59).unwrap().1;
    assert_eq!(env.clipboard.text().as_deref(), Some(want.as_str()));
    assert!(env.clipboard.sensitive());
    clock.advance(Duration::from_secs(30));
    s.tick();
    assert!(env.clipboard.text().is_none());
}

#[test]
fn repaint_within_a_second_while_totp_displayed() {
    let (secret, _) = sha1_vectors();
    let env = Env::new();
    let (s, _clock) = state(&env, &secret, 30);
    let d = onlypassword_desktop::app::repaint_after(&s).unwrap();
    assert!(d <= Duration::from_secs(1));
}
