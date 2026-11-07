//! Rendering of the application state.

use crate::config::Theme;
use crate::secret_buf::SecretBuf;
use crate::state::{Action, AppState, FieldRef, Screen};
use onlypassword_core::ItemKind;

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
            Screen::Browse => browse(ui, state),
            Screen::Detail(_) => detail(ui, state),
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

/// What a masked field draws instead of its text: fixed, whatever the length.
pub const MASK: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";

/// Browse screen: search box and the list of rows.
pub fn browse(ui: &mut egui::Ui, state: &AppState) -> Option<Action> {
    ui.label("Unlocked");
    let mut action = None;
    ui.horizontal(|ui| {
        let l = ui.label("Search");
        let mut text = state.search_text().to_owned();
        if ui
            .add(egui::TextEdit::singleline(&mut text))
            .labelled_by(l.id)
            .changed()
        {
            action = Some(Action::Search(text));
        }
    });
    for (i, row) in state.rows().iter().enumerate() {
        ui.push_id(i, |ui| {
            let text = match &row.username {
                Some(u) => format!("{} ({})", row.title, u),
                None => row.title.clone(),
            };
            if ui.button(text).clicked() {
                action = Some(Action::Select(row.id.clone()));
            }
        });
    }
    if ui.button("Settings").clicked() {
        action = Some(Action::ShowSettings);
    }
    if ui.button("Lock").clicked() {
        action = Some(Action::Lock);
    }
    action
}

fn copy_button(ui: &mut egui::Ui, name: &str, field: FieldRef, action: &mut Option<Action>) {
    if ui.button(format!("Copy {name}")).clicked() {
        *action = Some(Action::Copy(field));
    }
}

/// One masked field: placeholder (or the revealed text) and a Reveal/Hide toggle.
fn masked(
    ui: &mut egui::Ui,
    state: &AppState,
    name: &str,
    field: FieldRef,
    value: &str,
    action: &mut Option<Action>,
) {
    let shown = state.is_revealed(field);
    ui.horizontal(|ui| {
        ui.label(format!("{name}:"));
        ui.label(if shown { value } else { MASK });
        let verb = if shown { "Hide" } else { "Reveal" };
        if ui.button(format!("{verb} {name}")).clicked() {
            *action = Some(Action::ToggleReveal(field));
        }
        copy_button(ui, name, field, action);
    });
}

/// TOTP code, countdown label and progress bar.
pub fn totp_section(ui: &mut egui::Ui, t: &crate::state::TotpView, action: &mut Option<Action>) {
    ui.horizontal(|ui| match (&t.code, &t.error) {
        (Some(code), _) => {
            ui.label(format!("TOTP code: {}", code.as_str()));
            copy_button(ui, "TOTP code", FieldRef::TotpCode, action);
        }
        (None, e) => {
            ui.label(format!(
                "TOTP code: {}",
                e.as_deref().unwrap_or("invalid input")
            ));
        }
    });
    if t.code.is_some() && t.period > 0 {
        let frac = t.remaining as f32 / t.period as f32;
        ui.label(format!("Expires in {} s", t.remaining));
        ui.add(egui::ProgressBar::new(frac));
    }
}

/// Detail screen of the selected login or note.
pub fn detail(ui: &mut egui::Ui, state: &AppState) -> Option<Action> {
    let mut action = None;
    if let Some(stored) = state.selected() {
        let item = &stored.item;
        ui.label(item.title.as_str());
        match item.kind {
            ItemKind::Login => {
                if let Some(u) = &item.username {
                    ui.label(format!("Username: {u}"));
                }
                if let Some(p) = &item.password {
                    masked(
                        ui,
                        state,
                        "Password",
                        FieldRef::Password,
                        p.expose(),
                        &mut action,
                    );
                }
                for u in &item.urls {
                    ui.label(format!("URL: {u}"));
                }
                masked(
                    ui,
                    state,
                    "Notes",
                    FieldRef::Notes,
                    item.notes.expose(),
                    &mut action,
                );
                if let Some(t) = &item.totp {
                    masked(
                        ui,
                        state,
                        "TOTP secret",
                        FieldRef::TotpSecret,
                        t.secret.expose(),
                        &mut action,
                    );
                }
                if let Some(t) = state.totp() {
                    totp_section(ui, t, &mut action);
                }
                for (i, c) in item.fields.iter().enumerate() {
                    ui.push_id(i, |ui| {
                        if c.hidden {
                            masked(
                                ui,
                                state,
                                &c.name,
                                FieldRef::Custom(i),
                                c.value.expose(),
                                &mut action,
                            );
                        } else {
                            ui.horizontal(|ui| {
                                ui.label(format!("{}: {}", c.name, c.value.expose()));
                                copy_button(ui, &c.name, FieldRef::Custom(i), &mut action);
                            });
                        }
                    });
                }
            }
            ItemKind::Note => {
                masked(
                    ui,
                    state,
                    "Notes",
                    FieldRef::Notes,
                    item.notes.expose(),
                    &mut action,
                );
            }
        }
    }
    if ui.button("Back").clicked() {
        action = Some(Action::Back);
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
