//! Policy failures.
//!
//! Everything here is a fault in the policy, found while loading it. Screening itself cannot fail:
//! a screen that could return an error would give the send path a reason to skip it.

use std::path::Path;

use thiserror::Error;

/// Result alias for policy operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Why a policy could not be used.
#[derive(Debug, Error)]
pub enum Error {
    /// The file could not be read.
    ///
    /// The path is in the message because a deployment usually has a shipped policy and an
    /// overriding one, and "cannot read" without a path sends the reader to the wrong file.
    #[error("cannot read policy {path}: {why}")]
    Unreadable {
        /// The file that was tried.
        path: String,
        /// What the filesystem said.
        why: String,
    },
    /// The file is not the TOML this expects.
    #[error("cannot parse policy: {0}")]
    Unparseable(String),
    /// A rule parsed but describes a shape that cannot match anything.
    ///
    /// Rejected at load rather than ignored at match time. A rule that silently never fires is a
    /// screen that reports itself as covering a pattern class it does not cover.
    #[error("rule `{rule}`: {why}")]
    Unusable {
        /// The offending rule's id.
        rule: String,
        /// What is wrong with it.
        why: String,
    },
}

impl Error {
    /// A read failure, tagged with the path that failed.
    pub(crate) fn unreadable(path: &Path, why: &std::io::Error) -> Self {
        Self::Unreadable {
            path: path.display().to_string(),
            why: why.to_string(),
        }
    }

    /// A rule that cannot be used as written.
    pub(crate) fn unusable(rule: &str, why: impl Into<String>) -> Self {
        Self::Unusable {
            rule: rule.to_string(),
            why: why.into(),
        }
    }
}
