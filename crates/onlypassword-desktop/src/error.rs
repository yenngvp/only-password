//! The UI error surface: a closed enum with fixed Display strings and no payloads.

use std::fmt;

/// Every user-visible error. No variant carries a path, value or key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiError {
    /// Display is the core's own fixed text.
    Core(onlypassword_core::Error),
    PasswordMismatch,
    EmptyField,
    NoSelection,
    ConfirmationRequired,
    Clipboard,
    ConfigInvalid,
    ConfigWrite,
    InvalidSetting,
    /// Not shown; ends the action silently.
    PickerCancelled,
}

impl fmt::Display for UiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            UiError::Core(e) => return fmt::Display::fmt(e, f),
            UiError::PasswordMismatch => "the passwords do not match",
            UiError::EmptyField => "a required field is empty",
            UiError::NoSelection => "nothing is selected",
            UiError::ConfirmationRequired => "confirmation is required",
            UiError::Clipboard => "the clipboard is not available",
            UiError::ConfigInvalid => "the settings file is invalid; defaults are in use",
            UiError::ConfigWrite => "the settings could not be saved",
            UiError::InvalidSetting => "a setting is outside its allowed range",
            UiError::PickerCancelled => "cancelled",
        };
        f.write_str(s)
    }
}

impl std::error::Error for UiError {}

impl From<onlypassword_core::Error> for UiError {
    fn from(e: onlypassword_core::Error) -> Self {
        UiError::Core(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onlypassword_core::Error;

    #[test]
    fn display_is_fixed_and_leaks_nothing() {
        let sentinel = "/secret/path-SENTINEL-hunter2";
        let all = [
            (UiError::PasswordMismatch, "the passwords do not match"),
            (UiError::EmptyField, "a required field is empty"),
            (UiError::NoSelection, "nothing is selected"),
            (UiError::ConfirmationRequired, "confirmation is required"),
            (UiError::Clipboard, "the clipboard is not available"),
            (
                UiError::ConfigInvalid,
                "the settings file is invalid; defaults are in use",
            ),
            (UiError::ConfigWrite, "the settings could not be saved"),
            (
                UiError::InvalidSetting,
                "a setting is outside its allowed range",
            ),
            (UiError::PickerCancelled, "cancelled"),
            (UiError::Core(Error::Corrupt("SENTINEL")), "data is corrupt"),
        ];
        for (e, want) in all {
            let shown = e.to_string();
            assert_eq!(shown, want);
            assert!(!shown.contains("SENTINEL") && !shown.contains(sentinel));
        }
    }

    #[test]
    fn core_variant_matches_core_text() {
        let cores = [
            Error::Authentication,
            Error::Corrupt("x"),
            Error::UnsupportedVersion,
            Error::InvalidInput("x"),
            Error::NotFound,
            Error::Conflict,
            Error::LimitExceeded,
            Error::Rng,
            Error::Io(std::io::ErrorKind::NotFound),
        ];
        for c in cores {
            let want = c.to_string();
            assert_eq!(UiError::from(c).to_string(), want);
        }
    }
}
