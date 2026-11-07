mod common;

use std::time::Duration;

use common::*;
use onlypassword_desktop::app::repaint_after;
use onlypassword_desktop::config::Theme;
use onlypassword_desktop::error::UiError;
use onlypassword_desktop::state::{Action, Screen};

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[test]
fn activity_resets_timer_then_idle_locks() {
    let env = Env::new();
    let (mut s, clock) = env.unlocked();
    clock.advance(secs(299));
    s.tick();
    assert!(s.is_unlocked());
    s.dispatch(Action::Activity);
    clock.advance(secs(299));
    s.tick();
    assert!(s.is_unlocked());
    clock.advance(secs(2));
    s.tick();
    assert_eq!(s.screen(), &Screen::Unlock);
    assert!(s.is_clean());
}

#[test]
fn locked_state_never_expires_and_activity_does_not_arm() {
    let env = Env::new();
    let mut s = env.state();
    let (mut u, clock) = env.unlocked();
    u.dispatch(Action::Lock);
    clock.advance(secs(100_000));
    u.tick();
    u.dispatch(Action::Activity);
    assert_eq!(u.screen(), &Screen::Unlock);
    s.tick();
    assert!(s.is_clean());
}

#[test]
fn idle_expiry_clears_password_buffer_and_settings_screen() {
    let env = Env::new();
    let (mut s, clock) = env.unlocked();
    // A secret is sitting in the open form while the settings screen is open.
    s.open_form_mut().password.push_str(PW);
    s.create_form_mut().password.push_str(PW);
    s.create_form_mut().confirm.push_str(PW);
    s.dispatch(Action::ShowSettings);
    assert_eq!(s.screen(), &Screen::Settings);
    clock.advance(secs(301));
    s.tick();
    assert_eq!(s.screen(), &Screen::Unlock);
    assert!(s.is_clean());
    assert!(s.open_form_mut().password.is_empty());
    assert!(s.create_form_mut().password.is_empty());
    assert!(s.create_form_mut().confirm.is_empty());
}

#[test]
fn long_gap_locks_before_queued_actions() {
    let env = Env::new();
    let (mut s, clock) = env.unlocked();
    clock.advance(secs(10_000));
    s.tick();
    assert_eq!(s.screen(), &Screen::Unlock);
    s.dispatch(Action::ShowSettings);
    s.dispatch(Action::Activity);
    assert!(!s.is_unlocked());
}

#[test]
fn late_activity_after_long_gap_does_not_save_the_session() {
    let env = Env::new();
    let (mut s, clock) = env.unlocked();
    clock.advance(secs(10_000));
    s.dispatch(Action::Activity);
    assert!(!s.is_unlocked());
    assert!(s.is_clean());
}

fn set_form(s: &mut onlypassword_desktop::state::AppState, idle: &str, clip: &str, t: Theme) {
    let f = s.settings_form_mut();
    f.idle_timeout_secs = idle.to_owned();
    f.clipboard_clear_secs = clip.to_owned();
    f.theme = t;
}

#[test]
fn save_settings_applies_to_running_timer_and_file() {
    let env = Env::new();
    let (mut s, clock) = env.unlocked();
    s.dispatch(Action::ShowSettings);
    set_form(&mut s, "60", "45", Theme::Dark);
    s.dispatch(Action::SaveSettings);
    assert!(s.notice().is_none());
    assert_eq!(s.screen(), &Screen::Browse);
    assert_eq!(s.config().idle_timeout_secs, 60);
    clock.advance(secs(59));
    s.tick();
    assert!(s.is_unlocked());
    clock.advance(secs(2));
    s.tick();
    assert!(!s.is_unlocked());

    let text = std::fs::read_to_string(env.config_dir().join("config.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let obj = v.as_object().unwrap();
    let mut keys: Vec<_> = obj.keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "clipboard_clear_secs",
            "idle_timeout_secs",
            "last_vault_path",
            "theme",
            "version"
        ]
    );
    assert_eq!(obj["idle_timeout_secs"], 60);
    assert_eq!(obj["clipboard_clear_secs"], 45);
    assert_eq!(obj["theme"], "dark");
    assert!(!text.contains("u.key"));
}

#[test]
fn invalid_values_change_nothing() {
    let env = Env::new();
    let (mut s, clock) = env.unlocked();
    let before = std::fs::read(env.config_dir().join("config.json")).unwrap();
    for bad in ["9", "86401", "abc", "", "-5", "99999999999999999999"] {
        s.dispatch(Action::ShowSettings);
        set_form(&mut s, bad, "30", Theme::Light);
        s.dispatch(Action::SaveSettings);
        assert_eq!(s.notice(), Some(&UiError::InvalidSetting), "{bad}");
        assert_eq!(s.screen(), &Screen::Settings);
        assert_eq!(s.config().idle_timeout_secs, 300);
        assert_eq!(s.config().theme, Theme::System);
        s.dispatch(Action::CloseSettings);
    }
    set_form(&mut s, "300", "4", Theme::Light);
    s.dispatch(Action::ShowSettings);
    set_form(&mut s, "300", "4", Theme::Light);
    s.dispatch(Action::SaveSettings);
    assert_eq!(s.notice(), Some(&UiError::InvalidSetting));
    assert_eq!(
        std::fs::read(env.config_dir().join("config.json")).unwrap(),
        before
    );
    clock.advance(secs(299));
    s.tick();
    assert!(s.is_unlocked());
}

#[cfg(unix)]
#[test]
fn unwritable_config_dir_reports_but_still_applies() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let (mut s, clock) = env.unlocked();
    let dir = env.config_dir();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let writable = std::fs::File::create(dir.join("probe")).is_ok();
    s.dispatch(Action::ShowSettings);
    set_form(&mut s, "60", "30", Theme::Dark);
    s.dispatch(Action::SaveSettings);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    if !writable {
        assert_eq!(s.notice(), Some(&UiError::ConfigWrite));
    }
    assert_eq!(s.config().idle_timeout_secs, 60);
    assert_eq!(s.config().theme, Theme::Dark);
    clock.advance(secs(61));
    s.tick();
    assert!(!s.is_unlocked());
}

#[test]
fn settings_reachable_from_unlock_and_back() {
    let env = Env::new();
    let (mut s, _clock) = env.unlocked();
    s.dispatch(Action::Lock);
    s.dispatch(Action::ShowSettings);
    assert_eq!(s.screen(), &Screen::Settings);
    assert!(s.is_clean());
    set_form(&mut s, "120", "30", Theme::Light);
    s.dispatch(Action::SaveSettings);
    assert_eq!(s.screen(), &Screen::Unlock);
    assert_eq!(s.config().idle_timeout_secs, 120);
}

#[test]
fn repaint_only_while_session_exists() {
    let env = Env::new();
    let locked = env.state();
    assert_eq!(repaint_after(&locked), None);
    let (mut s, _c) = env.unlocked();
    let d = repaint_after(&s).unwrap();
    assert!(d <= secs(1) && d > Duration::ZERO);
    s.dispatch(Action::Lock);
    assert_eq!(repaint_after(&s), None);
}
