//! Password and passphrase generator panel (REQ-GUI-050, REQ-GUI-051).
//!
//! Values come only from the core's `generate_password` / `generate_passphrase`;
//! this crate has no random source of its own.

use std::fmt;

use onlypassword_core::{
    generate_passphrase, generate_password, PassphraseOptions, PasswordOptions, SecretString,
};

use super::{Action, AppState, Screen};
use crate::error::UiError;

/// Which generator the panel runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratorMode {
    Password,
    Passphrase,
}

/// Generator options and the current value. Lives in the session, so lock
/// drops it. `Debug` is redacted.
pub struct GeneratorState {
    pub mode: GeneratorMode,
    pub password: PasswordOptions,
    pub passphrase: PassphraseOptions,
    value: Option<SecretString>,
    revealed: bool,
    /// The side panel of the edit screen is open.
    panel_open: bool,
}

impl Default for GeneratorState {
    fn default() -> Self {
        GeneratorState {
            mode: GeneratorMode::Password,
            password: PasswordOptions::default(),
            passphrase: PassphraseOptions::default(),
            value: None,
            revealed: false,
            panel_open: false,
        }
    }
}

impl fmt::Debug for GeneratorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GeneratorState { .. }")
    }
}

impl GeneratorState {
    /// The generated value, if any.
    pub fn value(&self) -> Option<&SecretString> {
        self.value.as_ref()
    }

    pub fn is_revealed(&self) -> bool {
        self.revealed
    }

    pub fn panel_open(&self) -> bool {
        self.panel_open
    }

    /// Drop the value and close the side panel.
    pub(super) fn close(&mut self) {
        self.discard();
        self.panel_open = false;
    }

    fn discard(&mut self) {
        self.value = None;
        self.revealed = false;
    }
}

impl AppState {
    /// The generator state (present while unlocked).
    pub fn generator(&self) -> Option<&GeneratorState> {
        self.session.as_ref().map(|s| &s.browse.generator)
    }

    /// Drop the generated value and close the side panel.
    pub(super) fn close_generator_panel(&mut self) {
        if let Some(s) = self.session.as_mut() {
            s.browse.generator.close();
        }
    }

    pub(super) fn generator_action(&mut self, action: Action) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let g = &mut session.browse.generator;
        match action {
            Action::ShowGenerator => {
                if self.screen == Screen::Browse {
                    self.screen = Screen::Generator;
                }
            }
            Action::CloseGenerator => {
                if self.screen == Screen::Generator {
                    g.discard();
                    self.screen = Screen::Browse;
                } else {
                    self.close_generator_panel();
                }
            }
            Action::ToggleGeneratorPanel => {
                if matches!(self.screen, Screen::Edit(_)) {
                    if g.panel_open {
                        self.close_generator_panel();
                    } else {
                        g.panel_open = true;
                    }
                }
            }
            Action::SetGeneratorMode(m) => g.mode = m,
            Action::SetPasswordOptions(o) => g.password = o,
            Action::SetPassphraseOptions(o) => g.passphrase = o,
            Action::ToggleGeneratedReveal => g.revealed = !g.revealed,
            Action::GenerateNow => {
                g.discard();
                let result = match g.mode {
                    GeneratorMode::Password => generate_password(&g.password),
                    GeneratorMode::Passphrase => generate_passphrase(&g.passphrase),
                };
                match result {
                    Ok(v) => g.value = Some(v),
                    Err(e) => self.notice = Some(e.into()),
                }
            }
            Action::DiscardGenerated => g.discard(),
            Action::CopyGenerated => {
                let Some(v) = g.value.as_ref() else {
                    self.notice = Some(UiError::NoSelection);
                    return;
                };
                let now = self.deps.clock.now();
                if let Err(e) = self.clipboard.copy(v.expose(), now) {
                    self.notice = Some(e);
                }
            }
            Action::UseGenerated => {
                let Some(draft) = session.browse.draft.as_mut() else {
                    self.notice = Some(UiError::NoSelection);
                    return;
                };
                let Some(v) = g.value.take() else {
                    self.notice = Some(UiError::NoSelection);
                    return;
                };
                draft.password.clear();
                if !draft.password.push_str(v.expose()) {
                    self.notice = Some(UiError::EmptyField);
                    g.value = Some(v);
                    return;
                }
                g.revealed = false;
                self.wipe_requested = true;
            }
            _ => {}
        }
    }
}
