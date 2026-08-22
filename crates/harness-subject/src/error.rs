//! What can go wrong between a raw subject identifier and its pseudonym.

use crate::CanonVer;

/// A canonicalisation or derivation that could not be completed.
///
/// Every variant is a refusal, never a degraded result. A pseudonym derived from something other
/// than the caller's subject is worse than no pseudonym: it files the record under a subject that
/// does not exist, and no erasure request ever reaches it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Canonicalisation consumed the whole input.
    ///
    /// Whitespace-only and empty identifiers would otherwise all canonicalise to `""` and share one
    /// pseudonym, silently merging every subject the resolver failed on into a single erasure unit.
    #[error("subject identifier is empty after canonicalisation under canon_ver {ver}")]
    Empty {
        /// Ruleset that emptied it.
        ver: u32,
    },

    /// The keying secret was not the required length.
    #[error("keying secret must be {expected} bytes, got {got}")]
    KeyLength {
        /// Required length.
        expected: usize,
        /// Length supplied.
        got: usize,
    },

    /// The keying secret was not valid lowercase hex, or had an odd number of digits.
    #[error("keying secret is not valid lowercase hex")]
    KeyNotHex,

    /// A [`Registry`] was handed two canonicalisers claiming the same version.
    ///
    /// Fatal rather than deduplicated: two rulesets under one number means `canon_ver` no longer
    /// identifies the function that produced a hash, and the fan-out in
    /// [`Registry::derive_all`] becomes guesswork instead of enumeration.
    ///
    /// [`Registry`]: crate::Registry
    /// [`Registry::derive_all`]: crate::Registry::derive_all
    #[error("two canonicalisers both claim canon_ver {0}")]
    DuplicateVersion(u32),

    /// A [`Registry`] was built with no canonicalisers at all.
    ///
    /// [`Registry`]: crate::Registry
    #[error("a registry needs at least one canonicaliser")]
    EmptyRegistry,
}

impl Error {
    /// Builds [`Error::Empty`] for a version.
    pub(crate) const fn empty(ver: CanonVer) -> Self {
        Self::Empty { ver: ver.0 }
    }
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;
