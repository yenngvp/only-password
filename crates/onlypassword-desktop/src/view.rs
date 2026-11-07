//! Rendering of the application state.

use crate::config::Theme;
use crate::secret_buf::SecretBuf;
use crate::state::{Action, AppState, FieldRef, Screen};
use onlypassword_core::{ItemKind, TotpAlgorithm};

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
            Screen::Edit(_) => edit(ui, state),
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
    secret_edit_with(ui, label, buf, false)
}

/// Like `secret_edit`, with the text shown in the clear when `revealed`.
pub fn secret_edit_with(
    ui: &mut egui::Ui,
    label: &str,
    buf: &mut SecretBuf,
    revealed: bool,
) -> egui::Response {
    ui.horizontal(|ui| {
        let l = ui.label(label);
        let mut adapter = SecretAdapter(buf);
        ui.add(egui::TextEdit::singleline(&mut adapter).password(!revealed))
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
    if ui.button("Add Login").clicked() {
        action = Some(Action::BeginAdd(ItemKind::Login));
    }
    if ui.button("Add Note").clicked() {
        action = Some(Action::BeginAdd(ItemKind::Note));
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
    if let Some(stored) = state.selected() {
        if state.delete_pending() {
            ui.label(format!("Delete \"{}\"?", stored.item.title));
            if ui.button("Confirm delete").clicked() {
                action = Some(Action::ConfirmDelete);
            }
            if ui.button("Cancel delete").clicked() {
                action = Some(Action::CancelDelete);
            }
        } else {
            if ui.button("Edit").clicked() {
                action = Some(Action::BeginEdit);
            }
            if ui.button("Delete").clicked() {
                action = Some(Action::RequestDelete);
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

/// A labelled plain-text field of the edit form; returns the new text when changed.
fn text_field(ui: &mut egui::Ui, label: &str, current: &str) -> Option<String> {
    let mut text = current.to_owned();
    let changed = ui
        .horizontal(|ui| {
            let l = ui.label(label);
            ui.add(egui::TextEdit::singleline(&mut text))
                .labelled_by(l.id)
                .changed()
        })
        .inner;
    changed.then_some(text)
}

/// A masked draft field with its per-field Reveal/Hide toggle.
fn draft_secret(
    ui: &mut egui::Ui,
    state: &mut AppState,
    label: &str,
    field: FieldRef,
    pick: impl Fn(&mut crate::state::Draft) -> &mut SecretBuf,
    action: &mut Option<Action>,
) {
    let Some(d) = state.draft_mut() else {
        return;
    };
    let shown = d.revealed.contains(&field);
    secret_edit_with(ui, label, pick(d), shown);
    let verb = if shown { "Hide" } else { "Reveal" };
    if ui.button(format!("{verb} {label}")).clicked() {
        *action = Some(Action::ToggleDraftReveal(field));
    }
}

/// Edit form for a new or existing item. Notes drafts show only title and notes.
pub fn edit(ui: &mut egui::Ui, state: &mut AppState) -> Option<Action> {
    let mut action = None;
    let d = state.draft()?;
    let kind = d.kind;
    let adding = matches!(state.screen(), Screen::Edit(None));
    ui.label(match (adding, kind) {
        (true, ItemKind::Login) => "Add login",
        (true, ItemKind::Note) => "Add note",
        (false, _) => "Edit item",
    });
    if adding {
        ui.horizontal(|ui| {
            if ui
                .selectable_label(kind == ItemKind::Login, "Login")
                .clicked()
            {
                action = Some(Action::SetKind(ItemKind::Login));
            }
            if ui
                .selectable_label(kind == ItemKind::Note, "Note")
                .clicked()
            {
                action = Some(Action::SetKind(ItemKind::Note));
            }
        });
    }
    let title = d.title.clone();
    if let Some(t) = text_field(ui, "Title", &title) {
        action = Some(Action::SetTitle(t));
    }
    if kind == ItemKind::Login {
        let (username, urls) = (d.username.clone(), d.urls.clone());
        let (alg, digits, period) = (d.totp_algorithm, d.totp_digits, d.totp_period);
        let fields: Vec<(String, bool)> = d
            .fields
            .iter()
            .map(|f| (f.name.clone(), f.hidden))
            .collect();
        if let Some(u) = text_field(ui, "Username", &username) {
            action = Some(Action::SetUsername(u));
        }
        draft_secret(
            ui,
            state,
            "Password",
            FieldRef::Password,
            |d| &mut d.password,
            &mut action,
        );
        for (i, u) in urls.iter().enumerate() {
            ui.push_id(("url", i), |ui| {
                if let Some(t) = text_field(ui, &format!("URL {}", i + 1), u) {
                    action = Some(Action::SetUrl(i, t));
                }
                if ui.button(format!("Remove URL {}", i + 1)).clicked() {
                    action = Some(Action::RemoveUrl(i));
                }
            });
        }
        if ui.button("Add URL").clicked() {
            action = Some(Action::AddUrl);
        }
        draft_secret(
            ui,
            state,
            "Notes",
            FieldRef::Notes,
            |d| &mut d.notes,
            &mut action,
        );
        draft_secret(
            ui,
            state,
            "TOTP secret",
            FieldRef::TotpSecret,
            |d| &mut d.totp_secret,
            &mut action,
        );
        ui.horizontal(|ui| {
            ui.label("TOTP algorithm");
            for (a, name) in [
                (TotpAlgorithm::Sha1, "SHA-1"),
                (TotpAlgorithm::Sha256, "SHA-256"),
                (TotpAlgorithm::Sha512, "SHA-512"),
            ] {
                if ui.selectable_label(alg == a, name).clicked() {
                    action = Some(Action::SetTotpAlgorithm(a));
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("TOTP digits");
            for n in 6u8..=8 {
                if ui.selectable_label(digits == n, n.to_string()).clicked() {
                    action = Some(Action::SetTotpDigits(n));
                }
            }
        });
        if let Some(t) = text_field(ui, "TOTP period (seconds)", &period.to_string()) {
            // Unparsable text maps to 0, which the core rejects on save.
            action = Some(Action::SetTotpPeriod(t.trim().parse().unwrap_or(0)));
        }
        for (i, (name, hidden)) in fields.iter().enumerate() {
            ui.push_id(("field", i), |ui| {
                if let Some(t) = text_field(ui, &format!("Field {} name", i + 1), name) {
                    action = Some(Action::SetFieldName(i, t));
                }
                let label = format!("Field {} value", i + 1);
                if let Some(d) = state.draft_mut() {
                    let shown = !*hidden || d.revealed.contains(&FieldRef::Custom(i));
                    if let Some(f) = d.fields.get_mut(i) {
                        secret_edit_with(ui, &label, &mut f.value, shown);
                    }
                }
                let mut h = *hidden;
                if ui
                    .checkbox(&mut h, format!("Hide field {}", i + 1))
                    .changed()
                {
                    action = Some(Action::SetFieldHidden(i, h));
                }
                if *hidden {
                    let shown = state
                        .draft()
                        .is_some_and(|d| d.revealed.contains(&FieldRef::Custom(i)));
                    let verb = if shown { "Hide" } else { "Reveal" };
                    if ui.button(format!("{verb} {label}")).clicked() {
                        action = Some(Action::ToggleDraftReveal(FieldRef::Custom(i)));
                    }
                }
                if ui.button(format!("Remove field {}", i + 1)).clicked() {
                    action = Some(Action::RemoveField(i));
                }
            });
        }
        if ui.button("Add field").clicked() {
            action = Some(Action::AddField);
        }
    } else {
        draft_secret(
            ui,
            state,
            "Notes",
            FieldRef::Notes,
            |d| &mut d.notes,
            &mut action,
        );
    }
    if ui.button("Save").clicked() {
        action = Some(Action::SaveDraft);
    }
    if ui.button("Cancel").clicked() {
        action = Some(Action::CancelDraft);
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
