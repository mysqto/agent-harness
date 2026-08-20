//! Agent-side failures.

use thiserror::Error;

/// Result alias for agent operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Why a task could not be attempted.
///
/// A task that *was* attempted and did not succeed is not an error — it is an [`crate::Outcome`]
/// with a failed status. Keeping them apart is what lets the dispatcher retry the first and record
/// the second.
#[derive(Debug, Error)]
pub enum Error {
    /// The task's arguments do not make sense for this agent. Permanent.
    #[error("malformed task: {0}")]
    Malformed(String),
    /// This agent does not handle this intent — a routing mistake.
    #[error("unsupported intent `{0}`")]
    Unsupported(String),
    /// A dependency was unavailable. Worth retrying.
    #[error("dependency unavailable: {0}")]
    Unavailable(String),
    /// The deadline passed before the agent finished.
    #[error("deadline exceeded")]
    DeadlineExceeded,
    /// Refused on purpose — for example a mutating task on incomplete context.
    #[error("refused: {0}")]
    Refused(String),
}
