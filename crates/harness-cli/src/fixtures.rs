//! Test doubles shared across the modules.
//!
//! Kept in one place because the same fake agent proves two different things — that a mutating
//! intent is refused on degraded context, and that records reach the report — and two copies of it
//! would drift.

use std::collections::BTreeMap;

use harness_agent::{
    ActionDraft, Agent, AgentId, Capability, Context, Egress, MemoryHandle, Outcome, Status, Task,
    TaskId,
};
use harness_envelope::Envelope;

/// An envelope carrying `body`, with the fields the shell adapter sets.
pub fn envelope(body: &str) -> Envelope {
    Envelope {
        envelope_id: format!("test-{}", body.len()),
        source: "cli".into(),
        received_at: "2026-08-19T14:30:12Z".into(),
        attempt: 1,
        reply_to: Some("stdout".into()),
        actor: Some("local".into()),
        body: body.into(),
        extra: BTreeMap::new(),
    }
}

/// A task as the dispatcher would build it.
pub fn task(intent: &str, body: &str) -> Task {
    Task {
        task_id: TaskId("t-1".into()),
        correlation_id: "t-1".into(),
        intent: intent.into(),
        args: [("text".to_string(), serde_json::json!(body))]
            .into_iter()
            .collect(),
        mutating: false,
        actor: None,
    }
}

/// An agent whose capability is whatever the test needs it to be.
pub struct Configured {
    id: AgentId,
    capabilities: Vec<Capability>,
    records: Vec<ActionDraft>,
    unavailable: Option<String>,
}

impl Configured {
    /// An agent claiming one intent, mutating or not.
    pub fn new(id: &str, intent: &str, mutating: bool) -> Self {
        Self {
            id: AgentId(id.into()),
            capabilities: vec![Capability {
                intent: intent.into(),
                mutating,
            }],
            records: Vec::new(),
            unavailable: None,
        }
    }

    /// Makes the agent report that it could not attempt the task at all.
    pub fn failing(mut self, why: &str) -> Self {
        self.unavailable = Some(why.into());
        self
    }

    /// Makes the agent ask for a record to be written.
    pub fn writing(mut self, action: &str, entity: (&str, &str)) -> Self {
        self.records.push(ActionDraft {
            action: action.into(),
            outcome: Status::Succeeded,
            attrs: BTreeMap::new(),
            entities: vec![(entity.0.into(), entity.1.into())],
            summary: format!("{action} was applied"),
        });
        self
    }
}

#[async_trait::async_trait]
impl Agent for Configured {
    fn id(&self) -> &AgentId {
        &self.id
    }

    fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    async fn handle(&self, task: Task, ctx: &dyn Context) -> harness_agent::Result<Outcome> {
        if let Some(why) = &self.unavailable {
            return Err(harness_agent::Error::Unavailable(why.clone()));
        }
        Ok(Outcome {
            status: Status::Succeeded,
            egress: vec![Egress {
                target: String::new(),
                text: format!("{} on {}", task.intent, ctx.correlation_id()),
                thread: None,
            }],
            records: self.records.clone(),
        })
    }
}

/// A context that reaches nothing, for exercising an agent on its own.
pub struct StubContext {
    memory: StubMemory,
}

impl StubContext {
    /// A context with empty memory and a generous deadline.
    pub fn new() -> Self {
        Self { memory: StubMemory }
    }
}

impl Context for StubContext {
    fn correlation_id(&self) -> &'static str {
        "t-1"
    }

    fn memory(&self) -> &dyn MemoryHandle {
        &self.memory
    }

    fn remaining_ms(&self) -> u64 {
        1_000
    }

    fn is_degraded(&self) -> bool {
        false
    }
}

/// Memory that holds nothing and accepts everything.
struct StubMemory;

#[async_trait::async_trait]
impl MemoryHandle for StubMemory {
    async fn history(
        &self,
        _kind: &str,
        _id: &str,
        _limit: u32,
        _deadline_ms: u64,
    ) -> harness_agent::Result<Vec<BTreeMap<String, serde_json::Value>>> {
        Ok(Vec::new())
    }

    async fn record(&self, _draft: ActionDraft) -> harness_agent::Result<()> {
        Ok(())
    }
}
