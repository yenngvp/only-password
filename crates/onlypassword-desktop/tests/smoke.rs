use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use onlypassword_desktop::state::{AppState, Screen};
use onlypassword_desktop::view;

#[test]
fn heading_and_locked_text_are_present() {
    let mut harness = Harness::new_ui_state(
        |ui, state: &mut AppState| view::show(ui, state),
        AppState::default(),
    );
    harness.run();
    harness.get_by_label("onlypassword");
    harness.get_by_label("Locked");
    assert!(harness.query_by_label("no such label").is_none());
    assert_eq!(harness.state().screen(), &Screen::Open);
}
