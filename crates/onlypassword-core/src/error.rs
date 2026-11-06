//! Error type. Variants carry only static text or an `io::ErrorKind`, never input data.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Wrong password/secret key, or failed AEAD tag.
    Authentication,
    /// Structurally invalid input; static text only.
    Corrupt(&'static str),
    /// Version/kdf id/schema we do not read.
    UnsupportedVersion,
    /// Caller-supplied value outside limits.
    InvalidInput(&'static str),
    NotFound,
    Conflict,
    LimitExceeded,
    Rng,
    /// Kind only, never a path or message.
    Io(std::io::ErrorKind),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Fixed strings only: the payloads are deliberately not printed.
        let s = match self {
            Error::Authentication => "authentication failed",
            Error::Corrupt(_) => "data is corrupt",
            Error::UnsupportedVersion => "unsupported version",
            Error::InvalidInput(_) => "invalid input",
            Error::NotFound => "not found",
            Error::Conflict => "conflict",
            Error::LimitExceeded => "limit exceeded",
            Error::Rng => "random number generator failure",
            Error::Io(_) => "i/o error",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_fixed_and_excludes_payload() {
        let all = [
            (Error::Authentication, "authentication failed"),
            (Error::Corrupt("hunter2-sentinel"), "data is corrupt"),
            (Error::UnsupportedVersion, "unsupported version"),
            (Error::InvalidInput("hunter2-sentinel"), "invalid input"),
            (Error::NotFound, "not found"),
            (Error::Conflict, "conflict"),
            (Error::LimitExceeded, "limit exceeded"),
            (Error::Rng, "random number generator failure"),
            (Error::Io(std::io::ErrorKind::NotFound), "i/o error"),
        ];
        for (e, want) in all {
            let shown = e.to_string();
            assert_eq!(shown, want);
            assert!(!shown.contains("hunter2-sentinel"));
        }
    }

    #[test]
    fn io_display_ignores_kind() {
        let a = Error::Io(std::io::ErrorKind::NotFound).to_string();
        let b = Error::Io(std::io::ErrorKind::PermissionDenied).to_string();
        assert_eq!(a, b);
    }

    #[test]
    fn is_std_error() {
        fn takes<E: std::error::Error>(_: &E) {}
        takes(&Error::Rng);
    }
}
