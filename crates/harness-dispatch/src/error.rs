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
    #[error("refused: cannot act on partial context")]
    RefusedDegraded,
    /// The agent itself failed.
    #[error(transparent)]
    Agent(#[from] harness_agent::Error),
}
