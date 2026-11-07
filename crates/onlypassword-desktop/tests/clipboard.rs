mod common;

use common::*;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use onlypassword_core::{Item, ItemId, SecretString, Vault};
use onlypassword_desktop::clipboard::{ClipboardService, MemoryClipboard};
use onlypassword_desktop::config::Theme;
use onlypassword_desktop::error::UiError;
use onlypassword_desktop::state::{Action, AppState, FieldRef};
use onlypassword_desktop::view;
use std::time::Duration;

const SENT: &str = "CLIPSENT-password-value";
const SENT2: &str = "CLIPSENT-second-value";

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Unlocked state in the detail view of an item whose password is SENT.
fn detail_state(env: &Env) -> (AppState, onlypassword_desktop::clock::ManualClock) {
    let (vp, kp) = env.make_vault("c.opw", "c.key");
    let key = onlypassword_core::keyfile::read(&kp).unwrap();
    let mut v = Vault::unlock(&vp, &SecretString::new(PW.to_owned()), &key).unwrap();
    let mut it = Item::new_login("Site");
    it.password = Some(SecretString::new(SENT.to_owned()));
    v.add(&it).unwrap();
    v.lock();
    let (mut s, clock) = env.state_with_clock();
    fill_open(&mut s, &vp, &kp, PW);
    s.dispatch(Action::SubmitOpen);
    assert!(s.is_unlocked(), "{:?}", s.notice());
    let id: ItemId = s.rows()[0].id.clone();
    s.dispatch(Action::Select(id));
    (s, clock)
}

fn set_settings(s: &mut AppState, clip: &str) {
    s.dispatch(Action::ShowSettings);
    let f = s.settings_form_mut();
    f.idle_timeout_secs = "3000".into();
    f.clipboard_clear_secs = clip.into();
    f.theme = Theme::System;
    s.dispatch(Action::SaveSettings);
    assert!(s.notice().is_none());
}

#[test]
fn copy_then_clear_at_30s() {
    let env = Env::new();
    let (mut s, clock) = detail_state(&env);
    s.dispatch(Action::Copy(FieldRef::Password));
    assert!(s.notice().is_none());
    assert_eq!(env.clipboard.text().as_deref(), Some(SENT));
    assert!(env.clipboard.sensitive());
    assert!(!s.is_clean());
    clock.advance(secs(29));
    s.dispatch(Action::Activity);
    s.tick();
    assert_eq!(env.clipboard.text().as_deref(), Some(SENT));
    assert_eq!(env.clipboard.reads(), 0);
    clock.advance(secs(1));
    s.tick();
    assert!(env.clipboard.text().is_none());
    assert_eq!(env.clipboard.reads(), 1);
    assert_eq!(env.clipboard.clears(), 1);
    // The pending value is forgotten: later ticks read nothing.
    clock.advance(secs(100));
    s.tick();
    assert_eq!(env.clipboard.reads(), 1);
}

#[test]
fn replaced_text_is_left_alone_and_second_copy_restarts() {
    let env = Env::new();
    let (mut s, clock) = detail_state(&env);
    s.dispatch(Action::Copy(FieldRef::Password));
    env.clipboard.set_external("something else");
    clock.advance(secs(30));
    s.tick();
    assert_eq!(env.clipboard.text().as_deref(), Some("something else"));
    assert_eq!(env.clipboard.clears(), 0);
    assert_eq!(env.clipboard.reads(), 1);
    // Forgotten: lock must not read again.
    s.dispatch(Action::Lock);
    assert_eq!(env.clipboard.reads(), 1);
}

#[test]
fn service_second_copy_tracks_only_second_value() {
    let mem = MemoryClipboard::new();
    let mut svc = ClipboardService::new(Box::new(mem.clone()), secs(30));
    svc.copy(SENT, secs(0)).unwrap();
    svc.copy(SENT2, secs(20)).unwrap();
    svc.poll(secs(30)).unwrap(); // first deadline: nothing happens
    assert_eq!(mem.reads(), 0);
    assert_eq!(mem.text().as_deref(), Some(SENT2));
    svc.poll(secs(49)).unwrap();
    assert_eq!(mem.text().as_deref(), Some(SENT2));
    svc.poll(secs(50)).unwrap();
    assert!(mem.text().is_none());
    assert!(svc.is_clean());
    // Re-copy of the first value after the second was cleared: only the new one is tracked.
    svc.copy(SENT, secs(60)).unwrap();
    mem.set_external(SENT2);
    svc.clear_now().unwrap();
    assert_eq!(mem.text().as_deref(), Some(SENT2));
    assert!(svc.is_clean());
}

#[test]
fn lock_and_exit_clear_when_still_ours() {
    for exit in [false, true] {
        let env = Env::new();
        let (mut s, _) = detail_state(&env);
        s.dispatch(Action::Copy(FieldRef::Password));
        if exit {
            s.on_exit();
        } else {
            s.dispatch(Action::Lock);
        }
        assert!(env.clipboard.text().is_none());
        assert!(s.is_clean());
        assert_eq!(env.clipboard.reads(), 1);
        assert_eq!(env.clipboard.clears(), 1);
    }
}

#[test]
fn lock_and_exit_leave_foreign_text() {
    for exit in [false, true] {
        let env = Env::new();
        let (mut s, _) = detail_state(&env);
        s.dispatch(Action::Copy(FieldRef::Password));
        env.clipboard.set_external("foreign");
        if exit {
            s.on_exit();
        } else {
            s.dispatch(Action::Lock);
        }
        assert_eq!(env.clipboard.text().as_deref(), Some("foreign"));
        assert_eq!(env.clipboard.clears(), 0);
        assert!(s.is_clean());
    }
}

#[test]
fn idle_lock_clears_clipboard() {
    let env = Env::new();
    let (mut s, clock) = detail_state(&env);
    s.dispatch(Action::Copy(FieldRef::Password));
    clock.advance(secs(3000));
    s.tick();
    assert!(!s.is_unlocked());
    assert!(env.clipboard.text().is_none());
    assert!(s.is_clean());
}

#[test]
fn timeout_setting_applies_to_next_copy_not_pending() {
    let env = Env::new();
    let (mut s, clock) = detail_state(&env);
    s.dispatch(Action::Copy(FieldRef::Password));
    // Settings are reachable from the detail screen; the pending deadline stays at 30 s.
    set_settings(&mut s, "120");
    s.dispatch(Action::Select(s.rows()[0].id.clone()));
    clock.advance(secs(30));
    s.tick();
    assert!(env.clipboard.text().is_none(), "pending keeps its deadline");
    s.dispatch(Action::Copy(FieldRef::Password));
    clock.advance(secs(119));
    s.tick();
    assert_eq!(env.clipboard.text().as_deref(), Some(SENT));
    clock.advance(secs(1));
    s.tick();
    assert!(env.clipboard.text().is_none());
}

#[test]
fn failing_backend_gives_notice_and_recovers() {
    let env = Env::new();
    let (mut s, clock) = detail_state(&env);
    env.clipboard.set_failing(true);
    s.dispatch(Action::Copy(FieldRef::Password));
    assert_eq!(s.notice(), Some(&UiError::Clipboard));
    assert!(!s.notice().unwrap().to_string().contains(SENT));
    assert!(s.is_unlocked());
    clock.advance(secs(100));
    s.tick();
    assert_eq!(env.clipboard.reads(), 0, "no pending clear was created");
    env.clipboard.set_failing(false);
    s.dispatch(Action::Copy(FieldRef::Password));
    assert!(s.notice().is_none());
    assert_eq!(env.clipboard.text().as_deref(), Some(SENT));
    // Failing read at the deadline: notice, pending forgotten, app usable.
    env.clipboard.set_failing(true);
    clock.advance(secs(30));
    s.tick();
    assert_eq!(s.notice(), Some(&UiError::Clipboard));
    assert!(s.is_unlocked());
    env.clipboard.set_failing(false);
    let reads = env.clipboard.reads();
    s.tick();
    assert_eq!(env.clipboard.reads(), reads);
}

#[test]
fn debug_and_errors_never_show_text() {
    let mem = MemoryClipboard::new();
    let mut svc = ClipboardService::new(Box::new(mem.clone()), secs(30));
    svc.copy(SENT, secs(0)).unwrap();
    let d = format!("{svc:?}");
    assert!(!d.contains(SENT));
    assert!(d.contains("pending: true"));
    mem.set_failing(true);
    let e = svc.copy(SENT2, secs(1)).unwrap_err();
    assert_eq!(e, UiError::Clipboard);
    assert!(!format!("{e} {e:?}").contains(SENT2));
    // A failed copy keeps the earlier pending clear.
    assert!(!svc.is_clean());
}

#[test]
fn copy_outside_detail_or_missing_field_does_nothing() {
    let env = Env::new();
    let (mut s, _) = detail_state(&env);
    s.dispatch(Action::Copy(FieldRef::TotpSecret));
    s.dispatch(Action::Copy(FieldRef::Custom(7)));
    assert_eq!(env.clipboard.sets(), 0);
    s.dispatch(Action::Back);
    s.dispatch(Action::Copy(FieldRef::Password));
    assert_eq!(env.clipboard.sets(), 0);
}

#[test]
fn view_copy_button_puts_sentinel_on_clipboard() {
    let env = Env::new();
    let (s, _) = detail_state(&env);
    let mut h = Harness::new_ui_state(|ui, st: &mut AppState| view::show(ui, st), s);
    h.run();
    h.get_by_label("Copy Password").click();
    h.run();
    assert_eq!(env.clipboard.text().as_deref(), Some(SENT));
    assert!(env.clipboard.sensitive());
    assert!(!format!("{:?}", h.root()).contains(SENT));
}
