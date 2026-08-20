//! Failures, and the exit code each one reports.
//!
//! The variants are chosen by what a caller should do about them, not by where they came from —
//! which is why a dispatch refusal and an unroutable intent are separate even though both arrive
//! from [`harness_dispatch::Error`].

use thiserror::Error;

use crate::exit;

/// Result alias for command operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Why a command stopped.
#[derive(Debug, Error)]
pub enum Error {
    /// The arguments, or what arrived on stdin, were wrong.
    #[error("usage: {0}")]
    Usage(String),
    /// The config file could not be read, or did not say enough.
    #[error("config: {0}")]
    Config(String),
    /// The dispatcher refused to act, and this says on what grounds.
    #[error("{0}")]
    Refused(String),
    /// No registered agent handles the intent.
    #[error("no agent handles intent `{0}`")]
    Unroutable(String),
    /// Anything else that stopped the command.
    #[error("{0}")]
    Failed(String),
}

impl Error {
    /// The exit code this failure reports.
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Self::Usage(_) => exit::USAGE,
            Self::Config(_) => exit::CONFIG,
            Self::Refused(_) => exit::REFUSED,
            Self::Unroutable(_) => exit::UNROUTABLE,
            Self::Failed(_) => exit::FAILED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::exit;

    #[test]
    fn each_variant_reports_its_own_code() {
        let cases = [
            (Error::Usage("bad flag".into()), exit::USAGE),
            (Error::Config("no file".into()), exit::CONFIG),
            (Error::Refused("mutating".into()), exit::REFUSED),
            (Error::Unroutable("summarise".into()), exit::UNROUTABLE),
            (Error::Failed("socket".into()), exit::FAILED),
        ];
        for (error, code) in cases {
            assert_eq!(error.code(), code, "{error}");
        }
    }

    #[test]
    fn an_unroutable_intent_names_the_intent() {
        assert_eq!(
            Error::Unroutable("summarise".into()).to_string(),
            "no agent handles intent `summarise`"
        );
    }
}
