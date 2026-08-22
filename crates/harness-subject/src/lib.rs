//! Subject canonicalisation and keyed pseudonym derivation.
//!
//! A record about a person carries no identifier for them. It carries a pseudonym:
//! `HMAC-SHA256(secret, canonical_identifier)`, plus the number of the canonicalisation ruleset that
//! produced it. That pair is the erasure unit — destroy the key material filed under a pseudonym and
//! the sealed bodies naming it become unreadable in every copy, including the backups and the
//! immutable archives a rewrite could never reach.
//!
//! # Why this is on the writer side
//!
//! Because a raw subject identifier must never reach the store at all. Derivation happens before the
//! write leaves this process, so the keying secret stays here and the store is handed only an opaque
//! tag and a version number. It has no use for more and is deliberately given no way to get it. The
//! two sides share no crate and talk over a socket; the wire shapes are restated here — see
//! [`SUBJECT_HASH_PATTERN`] — rather than imported, which is the price of that boundary.
//!
//! # Why versioning is the hard part
//!
//! The pseudonym is a pure function of the canonical identifier, and that is the property the design
//! was chosen for: no state, so nothing to restore wrong and no way for one subject to end up with
//! two pseudonyms because a mapping store lost a row. It also puts the entire accuracy burden on
//! canonicalisation, in two failure modes that are not equally bad:
//!
//! - **Two spellings of one subject under one version — unrecoverable.** If the rules do not fold
//!   case, `Subject-A` and `subject-a` are two people forever. Nothing signals it, the two hashes are
//!   unrelatable, and an erasure request reaches half the records. This is what [`Minimal`] exists to
//!   prevent, and what its tests are about.
//! - **Changing the rules later — expensive, not fatal.** The same person hashes differently across
//!   the bump, and hashes already in paths and in never-deleted tombstones cannot be recomputed. But
//!   they do not need to be: a lookup derives under *every* live version and unions the results. The
//!   cost is that fan-out, paid on every lookup, forever.
//!
//! Which is why the version is never the caller's to supply. [`Canonicaliser::version`] belongs to
//! the ruleset, [`SubjectKey::derive`] reads it off the implementation that actually ran, and
//! [`Pseudonym`] keeps the two together so the version cannot be dropped between derivation and the
//! wire. And it is why the version is an *input* to the HMAC rather than a label beside it: a bump is
//! then a migration for every subject uniformly, instead of for whichever ones the two rulesets
//! happened to disagree about.
//!
//! Prefer as few versions as possible. Every one that has ever been live is fan-out for the rest of
//! the system's life.
//!
//! # Example
//!
//! ```
//! use harness_subject::{Minimal, SubjectKey, SubjectRole};
//!
//! # fn main() -> harness_subject::Result<()> {
//! let key = SubjectKey::from_bytes(&[0x5a; 32])?;
//!
//! // Spelling differences are not different subjects.
//! let a = key.derive(&Minimal, "  Subject-A  ")?;
//! let b = key.derive(&Minimal, "subject-a")?;
//! assert_eq!(a, b);
//!
//! // What goes on the wire: an opaque tag, a role, and the ruleset that produced the tag.
//! let entry = a.with_role(SubjectRole::Principal);
//! assert!(entry.hash.as_str().starts_with("s_"));
//! # Ok(())
//! # }
//! ```

mod canon;
mod error;
mod pseudonym;

pub use canon::{CanonVer, Canonicaliser, Minimal, Registry};
pub use error::{Error, Result};
pub use pseudonym::{
    KEY_LEN, Pseudonym, SUBJECT_HASH_PATTERN, SubjectHash, SubjectKey, SubjectRef, SubjectRole,
};
