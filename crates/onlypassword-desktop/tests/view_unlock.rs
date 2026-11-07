mod common;

use common::*;
use egui_kittest::kittest::Queryable;
use egui_kittest::Harness;
use onlypassword_desktop::state::{AppState, Screen};
use onlypassword_desktop::view;

#[test]
fn typing_password_and_clicking_unlock_reaches_browse() {
    let env = Env::new();
    let (v, k) = env.make_vault("a.opw", "a.key");
    let state = env.state();
    let mut h = Harness::new_ui_state(|ui, s: &mut AppState| view::show(ui, s), state);
    h.run();
    assert_eq!(h.state().screen(), &Screen::Open);

    env.picker.push(Some(v.clone()));
    h.get_by_label("Browse Vault file").click();
    h.run();
    env.picker.push(Some(k.clone()));
    h.get_by_label("Browse Key file").click();
    h.run();
    assert_eq!(
        h.state_mut().open_form_mut().vault_path,
        v.to_string_lossy()
    );

    let field = h.get_by_label("Master password");
    field.focus();
    h.run();
    h.get_by_label("Master password").type_text(PW);
    h.run();
    assert_eq!(h.state_mut().open_form_mut().password.expose(), PW);

    // The typed text is nowhere in the accessibility tree.
    let tree = format!("{:?}", h.root());
    assert!(!tree.contains("SENTINEL"), "password leaked into the tree");
    assert!(!tree.contains("correct horse"));

    h.get_by_label("Open").click();
    h.run();
    assert_eq!(h.state().screen(), &Screen::Browse);
    assert!(h.state_mut().open_form_mut().password.is_empty());
    h.get_by_label("Unlocked");

    h.get_by_label("Lock").click();
    h.run();
    assert_eq!(h.state().screen(), &Screen::Unlock);
    assert!(h.state().is_clean());
    h.get_by_label("Vault locked");
}
