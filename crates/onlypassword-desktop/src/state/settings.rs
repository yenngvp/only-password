//! Settings screen state and the `SaveSettings` action (REQ-CFG-007, REQ-CFG-008).

use std::time::Duration;

use super::{AppState, Screen};
use crate::config::{Config, Theme};
use crate::error::UiError;

/// Editable text of the settings screen (not secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsForm {
    pub idle_timeout_secs: String,
    pub clipboard_clear_secs: String,
    pub theme: Theme,
}

impl SettingsForm {
    pub fn from_config(c: &Config) -> Self {
        SettingsForm {
            idle_timeout_secs: c.idle_timeout_secs.to_string(),
            clipboard_clear_secs: c.clipboard_clear_secs.to_string(),
            theme: c.theme,
        }
    }

    /// Parse into a config (keeping `base`'s other fields) and validate.
    fn to_config(&self, base: &Config) -> Result<Config, UiError> {
        let idle = parse_secs(&self.idle_timeout_secs)?;
        let clip = parse_secs(&self.clipboard_clear_secs)?;
        let c = Config {
            idle_timeout_secs: idle,
            clipboard_clear_secs: clip,
            theme: self.theme,
            last_vault_path: base.last_vault_path.clone(),
        };
        c.validate()?;
        Ok(c)
    }
}

fn parse_secs(s: &str) -> Result<u32, UiError> {
    s.trim().parse().map_err(|_| UiError::InvalidSetting)
}

impl AppState {
    pub fn settings_form_mut(&mut self) -> &mut SettingsForm {
        &mut self.settings
    }

    pub(super) fn show_settings(&mut self) {
        if self.screen == Screen::Settings {
            return;
        }
        if matches!(self.screen, Screen::Open | Screen::Create) {
            return;
        }
        self.settings = SettingsForm::from_config(&self.config);
        self.settings_return = self.screen.clone();
        self.screen = Screen::Settings;
    }

    pub(super) fn close_settings(&mut self) {
        if self.screen == Screen::Settings {
            self.screen = self.settings_return.clone();
        }
    }

    pub(super) fn save_settings(&mut self) {
        if self.screen != Screen::Settings {
            return;
        }
        let new = match self.settings.to_config(&self.config) {
            Ok(c) => c,
            Err(e) => {
                self.notice = Some(e);
                return;
            }
        };
        self.config = new;
        self.idle.set_timeout(Duration::from_secs(u64::from(
            self.config.idle_timeout_secs,
        )));
        self.clipboard.set_timeout(Duration::from_secs(u64::from(
            self.config.clipboard_clear_secs,
        )));
        if let Some(store) = &self.deps.config_store {
            if let Err(e) = store.save(&self.config) {
                self.notice = Some(e);
            }
        }
        self.close_settings();
    }
}
