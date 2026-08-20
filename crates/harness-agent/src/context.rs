//! Everything an agent is allowed to reach.
//!
//! This trait is the reason agents are testable: a fake `Context` needs no server, no database and
//! no clock, so an agent's logic can be exercised in a unit test.

use std::collections::BTreeMap;

use crate::outcome::ActionDraft;

/// Read and write access to memory, scoped to the current task.
#[async_trait::async_trait]
pub trait MemoryHandle: Send + Sync {
    /// Recent context for an entity, newest first.
    ///
    /// Returns structure, never sealed content: an agent receives what happened, not the private
    /// detail of what was recorded.
    ///
    /// `deadline_ms` is how long the agent is willing to wait, usually a slice of
    /// [`Context::remaining_ms`]. An implementation may lower it — the dispatcher will not let a
    /// read outlive the task it belongs to — but never raise it, so asking for more than the task
    /// has does not buy any.
    async fn history(
        &self,
        kind: &str,
        id: &str,
        limit: u32,
        deadline_ms: u64,
    ) -> crate::Result<Vec<BTreeMap<String, serde_json::Value>>>;

    /// Queues a record for writing. The dispatcher stamps and submits it.
    async fn record(&self, draft: ActionDraft) -> crate::Result<()>;
}

/// The task's environment.
pub trait Context: Send + Sync {
    /// Correlation identifier, for logging and for stitching an interaction together.
    fn correlation_id(&self) -> &str;

    /// Memory access.
    fn memory(&self) -> &dyn MemoryHandle;

    /// Milliseconds remaining before the dispatcher abandons this task.
    fn remaining_ms(&self) -> u64;

    /// Whether the context supplied is known to be incomplete.
    ///
    /// An agent should let this change its *answer* — saying what it could not see — rather than
    /// its *decision* to act. Refusing to mutate on partial context is the dispatcher's call, made
    /// before the task arrives, because a flag an agent may ignore is not a safeguard.
    fn is_degraded(&self) -> bool;
}
