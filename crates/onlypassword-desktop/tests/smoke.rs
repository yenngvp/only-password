mod common;

use common::Env;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use onlypassword_desktop::state::{AppState, Screen};
use onlypassword_desktop::view;

#[test]
fn heading_and_open_screen_are_present() {
    let env = Env::new();
    let mut harness = Harness::new_ui_state(
        |ui, state: &mut AppState| view::show(ui, state),
        env.state(),
    );
    harness.run();
    harness.get_by_label("onlypassword");
    harness.get_by_label("Open a vault");
    assert!(harness.query_by_label("no such label").is_none());
    assert_eq!(harness.state().screen(), &Screen::Open);
}
