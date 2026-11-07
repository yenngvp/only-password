//! Change password, rotate key, export and import (REQ-GUI-060..064).
//!
//! The password buffers live in `MaintenanceForm`, owned by `AppState`. They
//! are emptied after every submit, on cancel, on lock and on idle expiry.

use std::fmt;
use std::path::PathBuf;

use onlypassword_core::{keyfile, SecretString};

use super::{Action, AppState, Screen};
use crate::error::UiError;
use crate::secret_buf::SecretBuf;

/// The four maintenance forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceKind {
    ChangePassword,
    RotateKey,
    Export,
    Import,
}

/// Form buffers shared by the four forms. `Debug` is redacted.
pub struct MaintenanceForm {
    /// Current master password (change password, rotate key).
    pub current: SecretBuf,
    /// New master password (change) or export password (export, import).
    pub new: SecretBuf,
    /// Confirmation of `new` (change, export).
    pub confirm: SecretBuf,
    /// Also rotate the vault key when changing the password (default on).
    pub rotate: bool,
    /// The explicit confirmation of the rotate-key form.
    pub confirmed: bool,
}

impl Default for MaintenanceForm {
    fn default() -> Self {
        MaintenanceForm {
            current: SecretBuf::new(),
            new: SecretBuf::new(),
            confirm: SecretBuf::new(),
            rotate: true,
            confirmed: false,
        }
    }
}

impl fmt::Debug for MaintenanceForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MaintenanceForm { .. }")
    }
}

impl MaintenanceForm {
    /// Wipe every buffer and reset the flags.
    pub fn reset(&mut self) {
        *self = MaintenanceForm::default();
    }

    pub fn buffers_empty(&self) -> bool {
        self.current.is_empty() && self.new.is_empty() && self.confirm.is_empty()
    }
}

fn secret(buf: &SecretBuf) -> SecretString {
    SecretString::new(buf.expose().to_owned())
}

impl AppState {
    pub fn maintenance_form_mut(&mut self) -> &mut MaintenanceForm {
        &mut self.maint
    }

    pub fn maintenance_form(&self) -> &MaintenanceForm {
        &self.maint
    }

    /// Fixed success text of the last maintenance action (never secret).
    pub fn info(&self) -> Option<&str> {
        self.info.as_deref()
    }

    pub(super) fn reset_maintenance(&mut self) {
        self.maint.reset();
        self.wipe_requested = true;
    }

    pub(super) fn maintenance_action(&mut self, action: Action) {
        if self.session.is_none() {
            return;
        }
        match action {
            Action::ShowMaintenance(kind) => {
                if matches!(self.screen, Screen::Browse | Screen::Maintenance(_)) {
                    self.reset_maintenance();
                    self.screen = Screen::Maintenance(kind);
                }
            }
            Action::CancelMaintenance => {
                if matches!(self.screen, Screen::Maintenance(_)) {
                    self.reset_maintenance();
                    self.screen = Screen::Browse;
                }
            }
            other => {
                let Screen::Maintenance(kind) = self.screen else {
                    return;
                };
                let wanted = match other {
                    Action::SubmitChangePassword => MaintenanceKind::ChangePassword,
                    Action::SubmitRotate => MaintenanceKind::RotateKey,
                    Action::SubmitExport => MaintenanceKind::Export,
                    _ => MaintenanceKind::Import,
                };
                if wanted != kind {
                    return;
                }
                let result = self.run_maintenance(kind);
                self.reset_maintenance();
                match result {
                    Ok(text) => {
                        self.info = Some(text);
                        self.screen = Screen::Browse;
                    }
                    Err(UiError::PickerCancelled) => {}
                    Err(e) => self.notice = Some(e),
                }
            }
        }
    }

    fn run_maintenance(&mut self, kind: MaintenanceKind) -> Result<String, UiError> {
        let Some(session) = self.session.as_mut() else {
            return Err(UiError::NoSelection);
        };
        let form = &self.maint;
        let kdf = self.deps.kdf;
        let text = match kind {
            MaintenanceKind::ChangePassword => {
                if form.new.expose() != form.confirm.expose() {
                    return Err(UiError::PasswordMismatch);
                }
                let (cur, new) = (secret(&form.current), secret(&form.new));
                if form.rotate {
                    session.vault.change_master_password_and_rotate_key(
                        &cur,
                        &session.key,
                        &new,
                        kdf,
                    )?;
                } else {
                    session
                        .vault
                        .change_master_password(&cur, &session.key, &new, kdf)?;
                }
                "master password changed"
            }
            MaintenanceKind::RotateKey => {
                if !form.confirmed {
                    return Err(UiError::ConfirmationRequired);
                }
                let cur = secret(&form.current);
                session.vault.rotate_vault_key(&cur, &session.key)?;
                "vault key rotated"
            }
            MaintenanceKind::Export => {
                if form.new.expose() != form.confirm.expose() {
                    return Err(UiError::PasswordMismatch);
                }
                let path = self
                    .deps
                    .picker
                    .save_export()
                    .ok_or(UiError::PickerCancelled)?;
                let pw = secret(&form.new);
                session.vault.export(&path, &pw, &session.key, kdf)?;
                "export written"
            }
            MaintenanceKind::Import => {
                let path: PathBuf = self
                    .deps
                    .picker
                    .pick_export()
                    .ok_or(UiError::PickerCancelled)?;
                let key_path = self
                    .deps
                    .picker
                    .pick_key_file()
                    .ok_or(UiError::PickerCancelled)?;
                let source_key = keyfile::read(&key_path)?;
                let pw = secret(&form.new);
                let n = session.vault.import(&path, &pw, &source_key)?;
                session.refresh_rows();
                return Ok(format!("imported {n} items"));
            }
        };
        session.refresh_rows();
        Ok(text.to_owned())
    }
}
