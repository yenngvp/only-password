//! CLI errors and their exit codes (0 success, 1 error, 2 usage, 3 authentication).

use onlypassword_core::Error as CoreError;

/// Messages are static text: they never contain a path, a password or any item content.
#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    Usage(&'static str),
    Failure(&'static str),
    Auth,
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::Failure(_) => 1,
            CliError::Usage(_) => 2,
            CliError::Auth => 3,
        }
    }

    pub fn message(&self) -> String {
        match self {
            CliError::Usage(m) => format!("usage error: {m}"),
            CliError::Failure(m) => format!("error: {m}"),
            CliError::Auth => "authentication failed".to_string(),
        }
    }
}

impl From<CoreError> for CliError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::Authentication => CliError::Auth,
            CoreError::NotFound => CliError::Failure("item not found"),
            CoreError::InvalidInput(_) => CliError::Failure("invalid input"),
            CoreError::Corrupt(_) => CliError::Failure("vault or key data is corrupt"),
            CoreError::UnsupportedVersion => CliError::Failure("unsupported version"),
            CoreError::Conflict => CliError::Failure("conflict"),
            CoreError::LimitExceeded => CliError::Failure("limit exceeded"),
            CoreError::Rng => CliError::Failure("random number generator failure"),
            CoreError::Io(_) => CliError::Failure("i/o error"),
            _ => CliError::Failure("unexpected error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        assert_eq!(CliError::Failure("x").exit_code(), 1);
        assert_eq!(CliError::Usage("x").exit_code(), 2);
        assert_eq!(CliError::Auth.exit_code(), 3);
        assert_eq!(CliError::from(CoreError::Authentication), CliError::Auth);
        assert_eq!(CliError::from(CoreError::NotFound).exit_code(), 1);
    }
}
