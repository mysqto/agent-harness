//! Dispatch failures.

use thiserror::Error;

/// Result alias for dispatch operations.
pub type Result<T> = std::result::Result<T, Error>;

/// What can go wrong dispatching.
#[derive(Debug, Error)]
pub enum Error {
    /// No registered agent declares this intent.
    #[error("no agent handles intent `{0}`")]
    Unroutable(String),
    /// Two or more agents claim the same intent, so the choice would be arbitrary.
    #[error("intent `{intent}` is claimed by more than one agent: {agents}")]
    Ambiguous {
        /// The contested intent.
        intent: String,
        /// The competing agents, comma separated.
        agents: String,
    },
    /// Refused because the task mutates and the context was incomplete.
    ///
    /// Carries both halves of the reason. A refusal is the one outcome an operator has to act on,
    /// and "refused" on its own makes them go and reconstruct what was refused and what was missing.
    #[error(
        "refused `{intent}`: cannot act on partial context; omitted: {}",
        reasons(omitted)
    )]
    RefusedDegraded {
        /// The intent that was refused.
        intent: String,
        /// What the context bundle was missing, and why, as the store reported it.
        omitted: Vec<String>,
    },
    /// The agent itself failed.
    #[error(transparent)]
    Agent(#[from] harness_agent::Error),
}

/// The omissions as one phrase.
///
/// A store may report a bundle as partial without saying what it left out, and an empty list would
/// otherwise render as a message that trails off mid-sentence.
fn reasons(omitted: &[String]) -> String {
    if omitted.is_empty() {
        "not stated".to_string()
    } else {
        omitted.join("; ")
    }
}
