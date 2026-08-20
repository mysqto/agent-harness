//! The agent interface.
//!
//! An agent receives a [`Task`] and a [`Context`] and returns an [`Outcome`]. That is the whole
//! contract. It deliberately does not include a way to reach a channel, open a database, or read a
//! clock — everything an agent needs arrives through `Context`, which is what lets an agent be
//! tested with no infrastructure and swapped without touching the dispatcher.
//!
//! Two rules are worth stating because they are easy to violate by accident:
//!
//! - **An agent does not deliver its own messages.** It returns them in [`Outcome::egress`] and the
//!   dispatcher delivers. An agent that could post directly could bypass the egress filter, which
//!   would reduce that filter from a property of the system to a habit.
//! - **An agent does not decide whether it is safe to act on partial context.** It reports what it
//!   needs; [`Task::mutating`] and [`Context::is_degraded`] let the dispatcher refuse first.

#![forbid(unsafe_code)]

pub mod context;
pub mod error;
pub mod outcome;
pub mod task;

pub use context::{Context, MemoryHandle};
pub use error::{Error, Result};
pub use outcome::{ActionDraft, Egress, Outcome, Status};
pub use task::{Actor, AgentId, Capability, Task, TaskId};

/// What every agent implements.
///
/// Implementors should be cheap to clone or share: the dispatcher may hold one instance and call it
/// concurrently for unrelated tasks.
#[async_trait::async_trait]
pub trait Agent: Send + Sync {
    /// Stable identity. Records this agent writes are attributed to it, so it must not change
    /// across restarts or the audit trail splits.
    fn id(&self) -> &AgentId;

    /// What this agent can handle. The dispatcher routes on this rather than on a hardcoded table,
    /// so adding an agent does not mean editing the router.
    fn capabilities(&self) -> &[Capability];

    /// Handles one task.
    ///
    /// Returning `Err` means the task could not be attempted. A task that was attempted and failed
    /// is an `Ok` carrying [`Status::Failed`] — the distinction matters, because one is worth
    /// retrying and the other is worth recording.
    async fn handle(&self, task: Task, ctx: &dyn Context) -> Result<Outcome>;

    /// Whether this agent is ready for work. Default is always ready.
    async fn health(&self) -> Health {
        Health::Ready
    }
}

/// Readiness, as reported by an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// Accepting work.
    Ready,
    /// Temporarily unable to work, with a reason worth logging.
    Degraded(String),
    /// Should receive no work.
    Unavailable(String),
}
