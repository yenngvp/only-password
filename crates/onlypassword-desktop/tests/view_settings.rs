mod common;

use common::*;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use onlypassword_desktop::config::Theme;
use onlypassword_desktop::state::{Action, AppState, Screen};
use onlypassword_desktop::view;

fn harness(state: AppState) -> Harness<'static, AppState> {
    Harness::new_ui_state(|ui, s: &mut AppState| view::show(ui, s), state)
}

#[test]
fn settings_screen_edits_saves_and_shows_fixed_message() {
    let env = Env::new();
    let (state, _clock) = env.unlocked();
    let mut h = harness(state);
    h.run();
    h.get_by_label("Settings").click();
    h.run();
    assert_eq!(h.state().screen(), &Screen::Settings);
    h.get_by_label("Idle timeout (seconds)");
    h.get_by_label("Clipboard timeout (seconds)");
    h.get_by_label("Dark");

    // Invalid value: the fixed message, nothing saved.
    h.state_mut().settings_form_mut().idle_timeout_secs = "9".to_owned();
    h.get_by_label("Save settings").click();
    h.run();
    h.get_by_label("a setting is outside its allowed range");
    assert_eq!(h.state().config().idle_timeout_secs, 300);

    // Valid change, including the theme.
    h.state_mut().settings_form_mut().idle_timeout_secs = "120".to_owned();
    h.get_by_label("Dark").click();
    h.run();
    h.get_by_label("Save settings").click();
    h.run();
    assert_eq!(h.state().config().idle_timeout_secs, 120);
    assert_eq!(h.state().config().theme, Theme::Dark);
    assert_eq!(h.state().screen(), &Screen::Browse);
    let text = std::fs::read_to_string(env.config_dir().join("config.json")).unwrap();
    assert!(text.contains("\"idle_timeout_secs\": 120") && text.contains("\"dark\""));
    h.run();
    assert!(h.ctx.global_style().visuals.dark_mode);
}

#[test]
fn theme_sets_visuals_and_system_falls_back_to_light() {
    let env = Env::new();
    let mut h = harness(env.state());
    h.run();
    // System with no reported preference is light.
    assert!(!h.ctx.global_style().visuals.dark_mode);
    let (mut state, _c) = env.unlocked();
    drop(h);
    for (theme, dark) in [
        (Theme::Dark, true),
        (Theme::Light, false),
        (Theme::Dark, true),
    ] {
        state.dispatch(Action::ShowSettings);
        state.settings_form_mut().theme = theme;
        state.dispatch(Action::SaveSettings);
        let mut h = harness(state);
        h.run();
        assert_eq!(h.ctx.global_style().visuals.dark_mode, dark);
        state = h.into_state();
    }
}

#[test]
fn settings_reachable_from_unlock_screen() {
    let env = Env::new();
    let (mut state, _c) = env.unlocked();
    state.dispatch(onlypassword_desktop::state::Action::Lock);
    let mut h = harness(state);
    h.run();
    h.get_by_label("Settings").click();
    h.run();
    assert_eq!(h.state().screen(), &Screen::Settings);
    h.get_by_label("Back").click();
    h.run();
    assert_eq!(h.state().screen(), &Screen::Unlock);
}
