//! Rendering of the application state.

use crate::config::Theme;
use crate::secret_buf::SecretBuf;
use crate::state::{Action, AppState, Screen};

/// Draw the current screen and dispatch what the user did.
pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    apply_theme(ui.ctx(), state.config().theme);
    egui::CentralPanel::default().show(ui, |ui| {
        ui.heading("onlypassword");
        if let Some(n) = state.notice() {
            ui.colored_label(ui.visuals().error_fg_color, n.to_string());
        }
        let action = match state.screen() {
            Screen::Open => open(ui, state),
            Screen::Create => create(ui, state),
            Screen::Unlock => unlock(ui, state),
            Screen::Browse => browse(ui),
            Screen::Settings => settings(ui, state),
        };
        if let Some(action) = action {
            state.dispatch(action);
        }
    });
    // egui keeps text-edit state (undo history) in its memory: drop it after
    // every submit, cancel or lock.
    if state.take_wipe_request() {
        ui.ctx().memory_mut(|m| m.data.clear());
    }
}

/// The egui theme a setting selects: `System` follows what eframe reports,
/// light when it reports nothing (REQ-CFG-006).
pub fn effective_theme(ctx: &egui::Context, theme: Theme) -> egui::Theme {
    match theme {
        Theme::Light => egui::Theme::Light,
        Theme::Dark => egui::Theme::Dark,
        Theme::System => ctx.system_theme().unwrap_or(egui::Theme::Light),
    }
}

/// Select the visuals for this frame.
pub fn apply_theme(ctx: &egui::Context, theme: Theme) {
    ctx.set_theme(effective_theme(ctx, theme));
}

/// A labelled plain-text path field with a Browse button.
fn path_row(ui: &mut egui::Ui, label: &str, text: &mut String) -> bool {
    let mut browse = false;
    ui.horizontal(|ui| {
        let l = ui.label(label);
        ui.add(egui::TextEdit::singleline(text)).labelled_by(l.id);
        browse = ui.button(format!("Browse {label}")).clicked();
    });
    browse
}

/// A labelled masked secret field editing the `SecretBuf` in place.
pub fn secret_edit(ui: &mut egui::Ui, label: &str, buf: &mut SecretBuf) -> egui::Response {
    ui.horizontal(|ui| {
        let l = ui.label(label);
        let mut adapter = SecretAdapter(buf);
        ui.add(egui::TextEdit::singleline(&mut adapter).password(true))
            .labelled_by(l.id)
    })
    .inner
}

/// Private `TextBuffer` over a `SecretBuf`: egui never gets a `String` copy.
struct SecretAdapter<'a>(&'a mut SecretBuf);

impl egui::TextBuffer for SecretAdapter<'_> {
    fn is_mutable(&self) -> bool {
        true
    }

    fn as_str(&self) -> &str {
        self.0.expose()
    }

    fn insert_text(&mut self, text: &str, char_index: egui::text::CharIndex) -> usize {
        if self.0.insert_at_char(char_index.0, text) {
            text.chars().count()
        } else {
            0
        }
    }

    fn delete_char_range(&mut self, char_range: std::ops::Range<egui::text::CharIndex>) {
        self.0
            .delete_char_range(char_range.start.0..char_range.end.0);
    }

    fn type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<SecretAdapter<'static>>()
    }

    fn clear(&mut self) {
        self.0.clear();
    }

    fn replace_with(&mut self, text: &str) {
        self.0.clear();
        self.0.push_str(text);
    }
}

/// Open screen: vault path, key-file path, password.
pub fn open(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    ui.label("Open a vault");
    open_fields(ui, state, "Open", Action::ShowCreate, "Create a new vault")
}

/// Unlock screen: same form, shown after a lock or for the last vault.
pub fn unlock(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    ui.label("Vault locked");
    let mut action = open_fields(ui, state, "Unlock", Action::ShowOpen, "Open another vault");
    if ui.button("Create a new vault").clicked() {
        action = Some(Action::ShowCreate);
    }
    if ui.button("Settings").clicked() {
        action = Some(Action::ShowSettings);
    }
    action
}

fn open_fields(
    ui: &mut egui::Ui,
    state: &mut AppState,
    submit: &str,
    other: Action,
    other_label: &str,
) -> Option<Action> {
    let mut action = None;
    let form = state.open_form_mut();
    if path_row(ui, "Vault file", &mut form.vault_path) {
        action = Some(Action::BrowseVault);
    }
    if path_row(ui, "Key file", &mut form.key_path) {
        action = Some(Action::BrowseKeyFile);
    }
    let pw = secret_edit(ui, "Master password", &mut form.password);
    let enter = pw.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
    if ui.button(submit).clicked() || enter {
        action = Some(Action::SubmitOpen);
    }
    if ui.button(other_label).clicked() {
        action = Some(other);
    }
    action
}

/// Create screen: new vault path, new key-file path, password and confirmation.
pub fn create(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    ui.label("Create a vault");
    let mut action = None;
    let form = state.create_form_mut();
    if path_row(ui, "New vault file", &mut form.vault_path) {
        action = Some(Action::BrowseNewVault);
    }
    if path_row(ui, "New key file", &mut form.key_path) {
        action = Some(Action::BrowseNewKeyFile);
    }
    secret_edit(ui, "New master password", &mut form.password);
    secret_edit(ui, "Confirm password", &mut form.confirm);
    if ui.button("Create").clicked() {
        action = Some(Action::SubmitCreate);
    }
    if ui.button("Cancel").clicked() {
        action = Some(Action::Cancel);
    }
    action
}

/// Placeholder browse screen.
pub fn browse(ui: &mut egui::Ui) -> Option<Action> {
    ui.label("Unlocked");
    let mut action = None;
    if ui.button("Settings").clicked() {
        action = Some(Action::ShowSettings);
    }
    if ui.button("Lock").clicked() {
        action = Some(Action::Lock);
    }
    action
}

/// Settings screen: idle timeout, clipboard timeout and theme.
pub fn settings(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    ui.label("Settings");
    let mut action = None;
    let form = state.settings_form_mut();
    for (label, text) in [
        ("Idle timeout (seconds)", &mut form.idle_timeout_secs),
        (
            "Clipboard timeout (seconds)",
            &mut form.clipboard_clear_secs,
        ),
    ] {
        ui.horizontal(|ui| {
            let l = ui.label(label);
            ui.add(egui::TextEdit::singleline(text)).labelled_by(l.id);
        });
    }
    ui.horizontal(|ui| {
        ui.label("Theme");
        ui.selectable_value(&mut form.theme, Theme::System, "System");
        ui.selectable_value(&mut form.theme, Theme::Light, "Light");
        ui.selectable_value(&mut form.theme, Theme::Dark, "Dark");
    });
    if ui.button("Save settings").clicked() {
        action = Some(Action::SaveSettings);
    }
    if ui.button("Back").clicked() {
        action = Some(Action::CloseSettings);
    }
    action
}
