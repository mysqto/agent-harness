//! Confinement for a harness deployment: filesystem ACLs, a runtime sandbox, and per-agent
//! signing keys.
//!
//! Three layers that are easy to describe and easy to get wrong, so each one is code with a test
//! rather than a paragraph in a runbook.
//!
//! # One policy, two artefacts
//!
//! A sandbox that is described twice is two sandboxes. The lab runs containers and production runs
//! systemd units, and if each is hand-written then what the lab proves is only that *the lab's*
//! confinement holds. So [`Policy`] is declared once and both artefacts are generated from it, and
//! the equivalence is a test: each emitted artefact is read *back* into a [`Hardening`] and the two
//! must agree. Adding a property to [`Hardening`] and forgetting an emitter fails that read,
//! because both readers require every property to be present rather than defaulting a missing one.
//!
//! The enforcement mechanisms are not identical and are not claimed to be — systemd restricts a
//! cgroup's sockets, a container runtime restricts a network namespace. What the test asserts is
//! that the two artefacts express the *same policy*, which is the part that silently drifts.
//!
//! # Filesystem
//!
//! [`Layout`] lays out the tree the access model in the design depends on: a shared `memory/` tree
//! at [`MODE_SHARED`] owned by a group agents are not in, `memory/private/<owner>/` at
//! [`MODE_PRIVATE`] so an operator shell without that identity cannot open it either, a per-agent
//! workspace, and a key directory. Permissions back up the rule that the service is the only
//! cross-agent interface; without them that rule is a convention.
//!
//! # Keys
//!
//! [`Keyring`] is one agent's signing key plus, during a rotation, the key it replaced. Signing
//! proves *origin*: [`Keyring::verify`] answers "which key sent this", and nothing more. Whether
//! that caller may do what it asked is [`authorize`], a separate call with a separate input. The
//! two are kept apart deliberately — a verified signature that also granted permission would make
//! every holder of a key an operator.

#![forbid(unsafe_code)]

mod cli;
mod keys;
mod policy;
mod role;
mod workspace;

pub use cli::run;
pub use keys::{Keyring, OVERLAP_MS, Verified};
pub use policy::{Hardening, Policy};
pub use role::{Action, Role, authorize};
pub use workspace::{Change, Layout, MODE_KEY_FILE, MODE_PRIVATE, MODE_SHARED};

/// Result alias for everything in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// What can go wrong while confining a deployment.
///
/// The variants split by who has to act: a [`Error::Policy`] or [`Error::Denied`] is a decision this
/// crate made and will make again, while [`Error::Io`] and [`Error::Permissions`] describe a host
/// that needs fixing.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The declared policy is unusable, or two artefacts disagree about it.
    #[error("policy: {0}")]
    Policy(String),
    /// The host refused a filesystem operation, or the path was not there.
    #[error("io: {0}")]
    Io(String),
    /// Something on disk is present but not confined the way it must be.
    #[error("permissions: {0}")]
    Permissions(String),
    /// The access model refused this caller. Not a host problem.
    #[error("denied: {0}")]
    Denied(String),
    /// Key material is missing, malformed, or unusable.
    #[error("key: {0}")]
    Key(String),
}

/// Wraps an I/O failure with the path it happened to, since the bare error names neither.
fn io(context: &str, path: &std::path::Path, err: &std::io::Error) -> Error {
    Error::Io(format!("{context} {}: {err}", path.display()))
}
