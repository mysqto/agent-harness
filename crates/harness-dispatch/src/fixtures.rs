//! Test doubles.
//!
//! The dispatcher's interesting behaviour is ordering — refuse before invoking, dedupe before
//! anything, filter before posting — and ordering can only be asserted on something that records
//! whether it was reached. These fakes record; nothing here needs a socket, a store or a clock.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use harness_agent::{
    ActionDraft, Agent, AgentId, Capability, Context, Egress, Outcome, Status, Task,
};
use harness_envelope::{Delivery, Envelope};
use harness_memory::Bundle;

use crate::egress::{Adapter, Filter};
use crate::registry::Registry;
use crate::route::ContextStore;

fn guard<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An envelope from a plain-text source.
pub fn envelope(body: &str) -> Envelope {
    Envelope {
        envelope_id: "cli-1".into(),
        source: "cli".into(),
        received_at: "2026-08-19T14:30:12Z".into(),
        attempt: 1,
        reply_to: Some("stdout".into()),
        actor: Some("local".into()),
        body: body.into(),
        extra: BTreeMap::new(),
    }
}

/// A delivery carrying `text`.
pub fn delivery(text: &str) -> Delivery {
    Delivery {
        envelope_id: "cli-1".into(),
        target: "stdout".into(),
        text: text.into(),
        thread: None,
    }
}

/// A record draft naming `action`.
pub fn draft(action: &str) -> ActionDraft {
    ActionDraft {
        action: action.into(),
        outcome: Status::Succeeded,
        attrs: BTreeMap::new(),
        entities: vec![("order_ref".into(), "ord-1".into())],
        summary: format!("{action} ran"),
    }
}

/// Names the filter list's type where an empty `vec![]` would be ambiguous.
pub fn filters(filters: Vec<Box<dyn Filter>>) -> Vec<Box<dyn Filter>> {
    filters
}

/// A registry holding `agents`, which must claim disjoint intents.
pub fn registry(agents: &[Arc<RecordingAgent>]) -> Registry {
    let mut registry = Registry::new();
    for agent in agents {
        registry.register(agent.clone()).expect("register");
    }
    registry
}

/// Appends `suffix`, so filter order is visible in the result.
pub struct Suffix(pub &'static str);

impl Filter for Suffix {
    fn apply(&self, text: &str) -> String {
        format!("{text}{}", self.0)
    }
}

/// Upper-cases, which does not commute with [`Suffix`].
pub struct Upper;

impl Filter for Upper {
    fn apply(&self, text: &str) -> String {
        text.to_uppercase()
    }
}

/// An adapter that remembers what it was asked to send.
pub struct RecordingAdapter {
    sent: Mutex<Vec<Delivery>>,
    error: Option<fn(String) -> harness_envelope::Error>,
    reason: String,
}

impl RecordingAdapter {
    /// Accepts everything.
    pub fn working() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            error: None,
            reason: String::new(),
        }
    }

    /// Fails every send in a way worth retrying.
    pub fn unavailable(reason: &str) -> Self {
        Self {
            error: Some(harness_envelope::Error::Unavailable),
            reason: reason.into(),
            ..Self::working()
        }
    }

    /// Fails every send permanently.
    pub fn malformed(reason: &str) -> Self {
        Self {
            error: Some(harness_envelope::Error::Malformed),
            reason: reason.into(),
            ..Self::working()
        }
    }

    /// The text of everything that reached this adapter, in order.
    pub fn texts(&self) -> Vec<String> {
        guard(&self.sent)
            .iter()
            .map(|d| d.text.clone())
            .collect::<Vec<_>>()
    }
}

#[async_trait::async_trait]
impl Adapter for RecordingAdapter {
    async fn send(&self, delivery: &Delivery) -> std::result::Result<(), harness_envelope::Error> {
        if let Some(error) = self.error {
            return Err(error(self.reason.clone()));
        }
        guard(&self.sent).push(delivery.clone());
        Ok(())
    }
}

#[async_trait::async_trait]
impl<T: Adapter + ?Sized> Adapter for Arc<T> {
    async fn send(&self, delivery: &Delivery) -> std::result::Result<(), harness_envelope::Error> {
        (**self).send(delivery).await
    }
}

/// A store whose answers are fixed and whose calls are recorded.
pub struct FakeStore {
    degraded: bool,
    read_error: Option<String>,
    write_error: Option<String>,
    records: Vec<serde_json::Value>,
    requested: Mutex<Vec<(String, String)>>,
    submitted: Mutex<Vec<String>>,
}

impl FakeStore {
    fn new() -> Self {
        Self {
            degraded: false,
            read_error: None,
            write_error: None,
            records: Vec::new(),
            requested: Mutex::new(Vec::new()),
            submitted: Mutex::new(Vec::new()),
        }
    }

    /// Returns whole context. One record is not an object, so projection has something to drop.
    pub fn healthy() -> Self {
        Self {
            records: vec![
                serde_json::json!({"id": "one"}),
                serde_json::json!("not a record"),
            ],
            ..Self::new()
        }
    }

    /// Answers, but marks the answer partial.
    pub fn degraded() -> Self {
        Self {
            degraded: true,
            ..Self::healthy()
        }
    }

    /// Cannot be read at all.
    pub fn unreachable() -> Self {
        Self {
            read_error: Some("no route to store".into()),
            ..Self::new()
        }
    }

    /// Reads fine, refuses writes.
    pub fn write_only_failure() -> Self {
        Self {
            write_error: Some("store is read-only".into()),
            ..Self::healthy()
        }
    }

    /// Every entity context was asked for, in order.
    pub fn requested(&self) -> Vec<(String, String)> {
        guard(&self.requested).clone()
    }

    /// The action of every record written, in order.
    pub fn submitted(&self) -> Vec<String> {
        guard(&self.submitted).clone()
    }
}

#[async_trait::async_trait]
impl ContextStore for FakeStore {
    async fn bundle(
        &self,
        entities: &[(String, String)],
        _deadline_ms: u64,
    ) -> harness_memory::Result<Bundle> {
        guard(&self.requested).extend_from_slice(entities);
        if let Some(why) = &self.read_error {
            return Err(harness_memory::Error::Unavailable(why.clone()));
        }
        Ok(Bundle {
            records: self.records.clone(),
            degraded: self.degraded,
            omitted: Vec::new(),
        })
    }

    async fn submit(&self, draft: &ActionDraft) -> harness_memory::Result<()> {
        if let Some(why) = &self.write_error {
            return Err(harness_memory::Error::Unavailable(why.clone()));
        }
        guard(&self.submitted).push(draft.action.clone());
        Ok(())
    }
}

/// An agent that records what it was handed, and whether it ran at all.
pub struct RecordingAgent {
    id: AgentId,
    capabilities: Vec<Capability>,
    status: Status,
    egress: Vec<Egress>,
    records: Vec<ActionDraft>,
    queued: Vec<ActionDraft>,
    history_kind: Option<String>,
    fail: Option<String>,
    calls: AtomicUsize,
    degraded: AtomicBool,
    task: Mutex<Option<Task>>,
    correlation_id: Mutex<Option<String>>,
    remaining_ms: Mutex<Option<u64>>,
    history: Mutex<Vec<String>>,
    history_error: Mutex<Option<String>>,
}

impl RecordingAgent {
    /// An agent claiming `capabilities`, given as `(intent, mutating)`.
    pub fn new(id: &str, capabilities: &[(&str, bool)]) -> Self {
        Self {
            id: AgentId(id.into()),
            capabilities: capabilities
                .iter()
                .map(|(intent, mutating)| Capability {
                    intent: (*intent).into(),
                    mutating: *mutating,
                })
                .collect(),
            status: Status::Succeeded,
            egress: Vec::new(),
            records: Vec::new(),
            queued: Vec::new(),
            history_kind: None,
            fail: None,
            calls: AtomicUsize::new(0),
            degraded: AtomicBool::new(false),
            task: Mutex::new(None),
            correlation_id: Mutex::new(None),
            remaining_ms: Mutex::new(None),
            history: Mutex::new(Vec::new()),
            history_error: Mutex::new(None),
        }
    }

    /// Claims one more intent.
    pub fn with_intent(mut self, intent: &str, mutating: bool) -> Self {
        self.capabilities.push(Capability {
            intent: intent.into(),
            mutating,
        });
        self
    }

    /// Replies with `text`, addressed wherever the envelope came from.
    pub fn replying(self, text: &str) -> Self {
        self.with_egress(Egress {
            target: String::new(),
            text: text.into(),
            thread: None,
        })
    }

    /// Replies with exactly this message.
    pub fn with_egress(mut self, egress: Egress) -> Self {
        self.egress.push(egress);
        self
    }

    /// Returns `draft` in its outcome.
    pub fn returning_record(mut self, draft: ActionDraft) -> Self {
        self.records.push(draft);
        self
    }

    /// Queues `draft` through the context while it runs.
    pub fn queueing_record(mut self, draft: ActionDraft) -> Self {
        self.queued.push(draft);
        self
    }

    /// Reads history for one entity of `kind` before answering.
    pub fn reading_history(mut self, kind: &str) -> Self {
        self.history_kind = Some(kind.into());
        self
    }

    /// Reports the task as attempted with this status.
    pub fn with_status(mut self, status: Status) -> Self {
        self.status = status;
        self
    }

    /// Cannot attempt the task at all.
    pub fn failing(mut self, reason: &str) -> Self {
        self.fail = Some(reason.into());
        self
    }

    /// How many times this agent was invoked.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    /// The last task handed over.
    pub fn task(&self) -> Option<Task> {
        guard(&self.task).clone()
    }

    /// Whether the context said its bundle was partial.
    pub fn saw_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// The correlation id the context carried.
    pub fn correlation_id(&self) -> Option<String> {
        guard(&self.correlation_id).clone()
    }

    /// The deadline the context reported.
    pub fn remaining_ms(&self) -> Option<u64> {
        *guard(&self.remaining_ms)
    }

    /// The `id` field of every history row read.
    pub fn history(&self) -> Vec<String> {
        guard(&self.history).clone()
    }

    /// Why history could not be read, if it could not.
    pub fn history_error(&self) -> Option<String> {
        guard(&self.history_error).clone()
    }
}

#[async_trait::async_trait]
impl Agent for RecordingAgent {
    fn id(&self) -> &AgentId {
        &self.id
    }

    fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    async fn handle(&self, task: Task, ctx: &dyn Context) -> harness_agent::Result<Outcome> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        *guard(&self.task) = Some(task);
        *guard(&self.correlation_id) = Some(ctx.correlation_id().to_owned());
        *guard(&self.remaining_ms) = Some(ctx.remaining_ms());
        self.degraded.store(ctx.is_degraded(), Ordering::Relaxed);

        if let Some(kind) = &self.history_kind {
            match ctx.memory().history(kind, "ord-1", 10).await {
                Ok(rows) => {
                    *guard(&self.history) = rows
                        .iter()
                        .filter_map(|row| row.get("id")?.as_str().map(str::to_owned))
                        .collect();
                }
                Err(error) => *guard(&self.history_error) = Some(error.to_string()),
            }
        }
        for draft in &self.queued {
            ctx.memory().record(draft.clone()).await?;
        }
        if let Some(reason) = &self.fail {
            return Err(harness_agent::Error::Unavailable(reason.clone()));
        }
        Ok(Outcome {
            status: self.status,
            egress: self.egress.clone(),
            records: self.records.clone(),
        })
    }
}
