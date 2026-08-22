//! What can go wrong before a decision can be made.
//!
//! Every variant here is a *fail-closed* condition: the guard treats an unusable policy or an
//! unreadable payload as a block, because "we could not tell" and "it was fine" are not the same
//! answer and only one of them is safe.

/// A policy that could not be loaded, or a payload that could not be read.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The policy file could not be read.
    #[error("cannot read policy {path}: {why}")]
    Unreadable {
        /// Where the guard looked.
        path: String,
        /// The underlying reason.
        why: String,
    },
    /// The policy or the tool call did not parse.
    #[error("malformed {what}: {why}")]
    Malformed {
        /// Which document.
        what: String,
        /// The parse failure.
        why: String,
    },
    /// The policy declares a version this build does not implement.
    ///
    /// Refused rather than best-effort parsed: a newer policy's rules are exactly the ones an older
    /// guard would silently drop.
    #[error("policy version {found} is not supported (this guard implements {supported})")]
    Version {
        /// What the file declared.
        found: u32,
        /// What this build implements.
        supported: u32,
    },
    /// The harness named for translation is not one this build knows.
    #[error("unknown harness `{0}`")]
    UnknownHarness(String),
}

/// Result carrying [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
