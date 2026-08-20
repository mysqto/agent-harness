//! Turning an envelope into a handled task.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use harness_agent::{ActionDraft, Actor, Context, MemoryHandle, Task, TaskId};
use harness_envelope::{Delivery, Envelope};
use harness_memory::Bundle;

use crate::egress::Courier;

/// Deadline handed to an agent when the source does not name one.
const DEFAULT_DEADLINE_MS: u64 = 5_000;

/// What a dispatch produced.
#[derive(Debug)]
pub struct Dispatched {
    /// Messages to deliver.
    pub deliveries: Vec<harness_envelope::Delivery>,
    /// Records that were submitted.
    pub records_written: usize,
    /// `true` when the envelope had been seen before and nothing was re-run.
    pub duplicate: bool,
}

/// The memory operations dispatch depends on.
///
/// A trait rather than the concrete client because the ordering rules below — degrade rather than
/// fail, refuse a mutation on partial context *before* the agent runs — are the whole point of this
/// module, and they are only testable if the store can be substituted. [`harness_memory::Client`]
/// implements it, so production wiring passes one straight through.
#[async_trait::async_trait]
pub trait ContextStore: Send + Sync {
    /// Composes context for the entities a task touches.
    async fn bundle(
        &self,
        entities: &[(String, String)],
        deadline_ms: u64,
    ) -> harness_memory::Result<Bundle>;

    /// Writes one record.
    async fn submit(&self, draft: &ActionDraft) -> harness_memory::Result<()>;
}

// Pure delegation, and the only part of this crate no test reaches: exercising it would run
// `harness-memory`'s own bodies, which is that crate's job to cover.
#[async_trait::async_trait]
impl ContextStore for harness_memory::Client {
    async fn bundle(
        &self,
        entities: &[(String, String)],
        deadline_ms: u64,
    ) -> harness_memory::Result<Bundle> {
        harness_memory::Client::bundle(self, entities, deadline_ms).await
    }

    async fn submit(&self, draft: &ActionDraft) -> harness_memory::Result<()> {
        harness_memory::Client::submit(self, draft).await
    }
}

/// Envelopes already handled to completion.
///
/// An id is remembered only after everything the envelope implied has happened. A half-finished
/// attempt is worth retrying, and marking it early would make the retry a silent no-op.
///
/// In memory, and so per process and per run: this makes a redelivery cheap, and claims nothing
/// about a redelivery that arrives after a restart. Surviving one needs a durable ledger, which
/// belongs behind the store rather than here.
#[derive(Debug, Default)]
pub struct Seen {
    ids: Mutex<HashSet<String>>,
}

impl Seen {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn contains(&self, id: &str) -> bool {
        self.lock().contains(id)
    }

    fn remember(&self, id: String) {
        self.lock().insert(id);
    }

    fn lock(&self) -> MutexGuard<'_, HashSet<String>> {
        // Recover rather than panic: the record of what has already run is worth more than the
        // guarantee that no thread observed a poisoned lock.
        self.ids.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Handles one envelope end to end.
///
/// Order matters: dedupe first so a redelivery costs nothing, then classify, then load context,
/// then decide whether a mutating task may proceed on what was loaded, and only then invoke the
/// agent. Checking safety after invoking would mean the side effect had already happened.
///
/// `seen` and `courier` hold the two ledgers that make a replay cheap, so a caller keeps them for
/// as long as redeliveries are possible. The returned deliveries are what the agent asked to send;
/// what the adapter received is that text with every filter applied.
pub async fn dispatch(
    registry: &crate::Registry,
    memory: &dyn ContextStore,
    courier: &Courier,
    seen: &Seen,
    envelope: Envelope,
) -> crate::Result<Dispatched> {
    if seen.contains(&envelope.envelope_id) {
        tracing::info!(
            envelope_id = %envelope.envelope_id,
            attempt = envelope.attempt,
            "already handled; nothing re-run"
        );
        return Ok(Dispatched {
            deliveries: Vec::new(),
            records_written: 0,
            duplicate: true,
        });
    }

    let request = classify(&envelope);
    let agent = registry.resolve(&request.intent)?;
    let mutating = agent
        .capabilities()
        .iter()
        .find(|c| c.intent == request.intent)
        .is_some_and(|c| c.mutating);

    let deadline_ms = deadline_ms(&envelope);
    let bundle = load(memory, &request.entities, deadline_ms).await;

    if mutating && bundle.degraded {
        // Before the agent runs, not after: a refusal that arrives once the side effect has
        // happened is not a refusal.
        tracing::warn!(
            envelope_id = %envelope.envelope_id,
            intent = %request.intent,
            omitted = ?bundle.omitted,
            "refusing a mutating task on partial context"
        );
        return Err(crate::Error::RefusedDegraded);
    }

    let task = Task {
        // One envelope is one task: a retry must not mint a second identity, or the audit trail
        // shows two actions where the source sent one message.
        task_id: TaskId(envelope.envelope_id.clone()),
        correlation_id: envelope.envelope_id.clone(),
        intent: request.intent,
        args: request.args,
        mutating,
        actor: envelope.actor.as_ref().map(|id| Actor {
            id: id.clone(),
            source: envelope.source.clone(),
        }),
    };
    let context = Dispatching::new(memory, &envelope.envelope_id, deadline_ms, bundle.degraded);
    let outcome = agent.handle(task, &context).await?;

    let deliveries = deliveries(&envelope, outcome.egress);
    courier.deliver(deliveries.clone()).await?;

    // Delivery is idempotent, so a record that fails to submit can be retried by replaying the
    // whole envelope without the reply going out twice.
    let mut drafts = outcome.records;
    drafts.extend(context.into_drafts());
    let mut records_written = 0;
    for draft in &drafts {
        memory
            .submit(draft)
            .await
            .map_err(|error| unavailable(&error))?;
        records_written += 1;
    }

    seen.remember(envelope.envelope_id);
    Ok(Dispatched {
        deliveries,
        records_written,
        duplicate: false,
    })
}

/// Loads context, treating an unreachable store as context that is merely incomplete.
///
/// Degrading keeps questions answerable when memory is down; the guard above is what keeps actions
/// from being taken on the result. Failing here instead would take both away at once.
async fn load(
    memory: &dyn ContextStore,
    entities: &[(String, String)],
    deadline_ms: u64,
) -> Bundle {
    match memory.bundle(entities, deadline_ms).await {
        Ok(bundle) => bundle,
        Err(error) => {
            tracing::warn!(%error, "context unavailable; continuing degraded");
            Bundle {
                records: Vec::new(),
                degraded: true,
                omitted: vec![error.to_string()],
            }
        }
    }
}

/// An envelope, read as a request.
struct Request {
    intent: String,
    args: BTreeMap<String, serde_json::Value>,
    entities: Vec<(String, String)>,
}

/// Maps an envelope onto an intent, arguments, and the entities worth loading context for.
///
/// An adapter that understands its source states the intent in `extra`; anything else falls back to
/// the first word of the body, which is what makes a plain-text source usable with no schema at all.
fn classify(envelope: &Envelope) -> Request {
    let intent = envelope
        .extra
        .get("intent")
        .and_then(serde_json::Value::as_str)
        .map_or_else(
            || {
                envelope
                    .body
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_lowercase()
            },
            str::to_owned,
        );

    let mut args: BTreeMap<String, serde_json::Value> = envelope
        .extra
        .get("args")
        .and_then(serde_json::Value::as_object)
        .map(|args| {
            args.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default();
    // The body is passed through whole rather than split: what the words mean is the agent's
    // business, and a dispatcher that guesses would be a second parser to keep in step.
    args.insert(
        "text".to_string(),
        serde_json::Value::String(envelope.body.clone()),
    );

    Request {
        intent,
        args,
        entities: entities(envelope),
    }
}

/// Entities named by the adapter, as `(kind, id)`.
///
/// Anything malformed is dropped rather than rejected: a source that cannot name its entities still
/// deserves an answer, and it arrives marked degraded if context is missing.
fn entities(envelope: &Envelope) -> Vec<(String, String)> {
    envelope
        .extra
        .get("entities")
        .and_then(serde_json::Value::as_array)
        .map(|items| items.iter().filter_map(entity).collect())
        .unwrap_or_default()
}

fn entity(value: &serde_json::Value) -> Option<(String, String)> {
    Some((
        value.get("kind")?.as_str()?.to_owned(),
        value.get("id")?.as_str()?.to_owned(),
    ))
}

/// How long the agent has, per the source, or the default.
fn deadline_ms(envelope: &Envelope) -> u64 {
    envelope
        .extra
        .get("deadline_ms")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(DEFAULT_DEADLINE_MS)
}

/// Turns what the agent wants said into addressed deliveries.
///
/// An empty target means "wherever this came from", so an agent that has no opinion about routing
/// does not have to learn what `reply_to` holds for this source.
fn deliveries(envelope: &Envelope, egress: Vec<harness_agent::Egress>) -> Vec<Delivery> {
    egress
        .into_iter()
        .map(|message| Delivery {
            envelope_id: envelope.envelope_id.clone(),
            target: if message.target.is_empty() {
                envelope.reply_to.clone().unwrap_or_default()
            } else {
                message.target
            },
            text: message.text,
            thread: message.thread,
        })
        .collect()
}

/// Maps a store failure onto the dispatch error.
///
/// Dispatch has no memory variant, so a failed write surfaces as the agent-side `Unavailable`:
/// retryable, which is what a caller needs to know.
fn unavailable(error: &harness_memory::Error) -> crate::Error {
    harness_agent::Error::Unavailable(error.to_string()).into()
}

/// The context one task sees.
struct Dispatching<'a> {
    correlation_id: String,
    memory: Queued<'a>,
    deadline_ms: u64,
    started: Instant,
    degraded: bool,
}

impl<'a> Dispatching<'a> {
    fn new(
        store: &'a dyn ContextStore,
        correlation_id: &str,
        deadline_ms: u64,
        degraded: bool,
    ) -> Self {
        Self {
            correlation_id: correlation_id.to_owned(),
            memory: Queued {
                store,
                deadline_ms,
                drafts: Mutex::new(Vec::new()),
            },
            deadline_ms,
            started: Instant::now(),
            degraded,
        }
    }

    /// The records the agent queued while it ran.
    fn into_drafts(self) -> Vec<ActionDraft> {
        self.memory
            .drafts
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl Context for Dispatching<'_> {
    fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    fn memory(&self) -> &dyn MemoryHandle {
        &self.memory
    }

    fn remaining_ms(&self) -> u64 {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.deadline_ms.saturating_sub(elapsed)
    }

    fn is_degraded(&self) -> bool {
        self.degraded
    }
}

/// Memory as an agent sees it: reads pass through, writes queue.
///
/// Writes are queued rather than sent because the dispatcher stamps and submits them. That is what
/// stops an agent attributing an action to someone else.
struct Queued<'a> {
    store: &'a dyn ContextStore,
    deadline_ms: u64,
    drafts: Mutex<Vec<ActionDraft>>,
}

#[async_trait::async_trait]
impl MemoryHandle for Queued<'_> {
    async fn history(
        &self,
        kind: &str,
        id: &str,
        limit: u32,
    ) -> harness_agent::Result<Vec<BTreeMap<String, serde_json::Value>>> {
        let entities = [(kind.to_owned(), id.to_owned())];
        let bundle = self
            .store
            .bundle(&entities, self.deadline_ms)
            .await
            .map_err(|error| harness_agent::Error::Unavailable(error.to_string()))?;
        Ok(bundle
            .records
            .into_iter()
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            // Structure only: anything that is not an object is not something an agent can read as
            // a record, so it is dropped rather than reshaped.
            .filter_map(|record| match record {
                serde_json::Value::Object(fields) => Some(fields.into_iter().collect()),
                _ => None,
            })
            .collect())
    }

    async fn record(&self, draft: ActionDraft) -> harness_agent::Result<()> {
        self.drafts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(draft);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use harness_agent::{Egress, Status};

    use super::{Seen, dispatch};
    use crate::egress::Courier;
    use crate::fixtures::{
        FakeStore, RecordingAdapter, RecordingAgent, Suffix, draft, envelope, filters, registry,
    };

    #[tokio::test]
    async fn a_duplicate_envelope_is_not_re_run() {
        let agent =
            Arc::new(RecordingAgent::new("reader", &[("summarise", false)]).replying("one event"));
        let registry = registry(std::slice::from_ref(&agent));
        let store = FakeStore::healthy();
        let adapter = Arc::new(RecordingAdapter::working());
        let courier = Courier::new(filters(vec![]), Box::new(adapter.clone()));
        let seen = Seen::new();

        let first = dispatch(
            &registry,
            &store,
            &courier,
            &seen,
            envelope("summarise all"),
        )
        .await
        .expect("first dispatch");
        let retry = dispatch(
            &registry,
            &store,
            &courier,
            &seen,
            envelope("summarise all"),
        )
        .await
        .expect("redelivery");

        assert!(!first.duplicate);
        assert!(retry.duplicate);
        assert!(retry.deliveries.is_empty());
        assert_eq!(retry.records_written, 0);
        assert_eq!(agent.calls(), 1, "a redelivery must not re-run the agent");
        assert_eq!(adapter.texts(), vec!["one event"]);
    }

    #[tokio::test]
    async fn a_mutating_task_on_a_degraded_bundle_never_reaches_the_agent() {
        // The assertion that matters: refusal happens before invocation, so the side effect the
        // agent would have performed has not happened.
        let agent = Arc::new(RecordingAgent::new("writer", &[("apply", true)]).replying("applied"));
        let adapter = Arc::new(RecordingAdapter::working());
        let courier = Courier::new(filters(vec![]), Box::new(adapter.clone()));

        let error = dispatch(
            &registry(std::slice::from_ref(&agent)),
            &FakeStore::degraded(),
            &courier,
            &Seen::new(),
            envelope("apply the change"),
        )
        .await
        .expect_err("refused");

        assert!(matches!(error, crate::Error::RefusedDegraded));
        assert_eq!(error.to_string(), "refused: cannot act on partial context");
        assert_eq!(agent.calls(), 0, "the agent must never have been invoked");
        assert!(adapter.texts().is_empty());
    }

    #[tokio::test]
    async fn a_read_only_task_on_a_degraded_bundle_proceeds() {
        let agent =
            Arc::new(RecordingAgent::new("reader", &[("summarise", false)]).replying("partial"));
        let adapter = Arc::new(RecordingAdapter::working());
        let courier = Courier::new(filters(vec![]), Box::new(adapter.clone()));

        let handled = dispatch(
            &registry(std::slice::from_ref(&agent)),
            &FakeStore::degraded(),
            &courier,
            &Seen::new(),
            envelope("summarise all"),
        )
        .await
        .expect("dispatched");

        assert_eq!(agent.calls(), 1);
        assert_eq!(handled.deliveries.len(), 1);
        assert_eq!(adapter.texts(), vec!["partial"]);
        assert!(
            agent.saw_degraded(),
            "the agent should be told the context was partial"
        );
    }

    #[tokio::test]
    async fn a_mutating_task_on_a_whole_bundle_proceeds() {
        let agent = Arc::new(RecordingAgent::new("writer", &[("apply", true)]).replying("applied"));
        let handled = dispatch(
            &registry(std::slice::from_ref(&agent)),
            &FakeStore::healthy(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            envelope("apply the change"),
        )
        .await
        .expect("dispatched");

        assert_eq!(agent.calls(), 1);
        assert!(agent.task().expect("a task").mutating);
        assert!(!handled.duplicate);
    }

    #[tokio::test]
    async fn an_unreachable_store_degrades_rather_than_fails() {
        // A question still gets an answer; the guard is what stops an action being taken on it.
        let reader =
            Arc::new(RecordingAgent::new("reader", &[("summarise", false)]).replying("all I have"));
        dispatch(
            &registry(std::slice::from_ref(&reader)),
            &FakeStore::unreachable(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            envelope("summarise all"),
        )
        .await
        .expect("dispatched degraded");
        assert!(reader.saw_degraded());

        let writer = Arc::new(RecordingAgent::new("writer", &[("apply", true)]));
        let error = dispatch(
            &registry(std::slice::from_ref(&writer)),
            &FakeStore::unreachable(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            envelope("apply the change"),
        )
        .await
        .expect_err("refused");

        assert!(matches!(error, crate::Error::RefusedDegraded));
        assert_eq!(writer.calls(), 0);
    }

    #[tokio::test]
    async fn an_intent_no_agent_claims_is_unroutable() {
        let error = dispatch(
            &registry(&[Arc::new(RecordingAgent::new(
                "reader",
                &[("summarise", false)],
            ))]),
            &FakeStore::healthy(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            envelope("translate all"),
        )
        .await
        .expect_err("unroutable");

        assert!(matches!(error, crate::Error::Unroutable(ref i) if i == "translate"));
    }

    #[tokio::test]
    async fn filters_apply_to_what_the_agent_produced() {
        let agent =
            Arc::new(RecordingAgent::new("reader", &[("summarise", false)]).replying("two events"));
        let adapter = Arc::new(RecordingAdapter::working());
        let courier = Courier::new(
            filters(vec![Box::new(Suffix(" [reviewed]"))]),
            Box::new(adapter.clone()),
        );

        let handled = dispatch(
            &registry(&[agent]),
            &FakeStore::healthy(),
            &courier,
            &Seen::new(),
            envelope("summarise all"),
        )
        .await
        .expect("dispatched");

        assert_eq!(adapter.texts(), vec!["two events [reviewed]"]);
        assert_eq!(
            handled.deliveries[0].text, "two events",
            "the reported delivery is what the agent asked for; the filter is what went out"
        );
    }

    #[tokio::test]
    async fn an_agent_that_names_no_target_replies_where_the_message_came_from() {
        let agent = Arc::new(
            RecordingAgent::new("reader", &[("summarise", false)]).with_egress(Egress {
                target: String::new(),
                text: "here".into(),
                thread: Some("t-7".into()),
            }),
        );
        let adapter = Arc::new(RecordingAdapter::working());

        let handled = dispatch(
            &registry(&[agent]),
            &FakeStore::healthy(),
            &Courier::new(filters(vec![]), Box::new(adapter.clone())),
            &Seen::new(),
            envelope("summarise all"),
        )
        .await
        .expect("dispatched");

        assert_eq!(handled.deliveries[0].target, "stdout");
        assert_eq!(handled.deliveries[0].thread.as_deref(), Some("t-7"));
    }

    #[tokio::test]
    async fn an_agent_that_names_a_target_is_taken_at_its_word() {
        // The target is opaque above the adapter, so the dispatcher passes it through untouched
        // rather than trying to validate something only the adapter understands.
        let agent = Arc::new(
            RecordingAgent::new("reader", &[("summarise", false)]).with_egress(Egress {
                target: "audit-log".into(),
                text: "here".into(),
                thread: None,
            }),
        );

        let handled = dispatch(
            &registry(&[agent]),
            &FakeStore::healthy(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            envelope("summarise all"),
        )
        .await
        .expect("dispatched");

        assert_eq!(handled.deliveries[0].target, "audit-log");
    }

    #[tokio::test]
    async fn records_the_agent_returned_and_queued_are_both_submitted() {
        let agent = Arc::new(
            RecordingAgent::new("reader", &[("summarise", false)])
                .returning_record(draft("summarise"))
                .queueing_record(draft("read")),
        );
        let store = FakeStore::healthy();

        let handled = dispatch(
            &registry(&[agent]),
            &store,
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            envelope("summarise all"),
        )
        .await
        .expect("dispatched");

        assert_eq!(handled.records_written, 2);
        assert_eq!(store.submitted(), vec!["summarise", "read"]);
    }

    #[tokio::test]
    async fn an_envelope_whose_records_failed_to_write_is_retried_in_full() {
        let agent = Arc::new(
            RecordingAgent::new("reader", &[("summarise", false)])
                .replying("one event")
                .returning_record(draft("summarise")),
        );
        let registry = registry(std::slice::from_ref(&agent));
        let adapter = Arc::new(RecordingAdapter::working());
        let courier = Courier::new(filters(vec![]), Box::new(adapter.clone()));
        let seen = Seen::new();

        let error = dispatch(
            &registry,
            &FakeStore::write_only_failure(),
            &courier,
            &seen,
            envelope("summarise all"),
        )
        .await
        .expect_err("submit fails");
        assert_eq!(
            error.to_string(),
            "dependency unavailable: unavailable: store is read-only"
        );

        let handled = dispatch(
            &registry,
            &FakeStore::healthy(),
            &courier,
            &seen,
            envelope("summarise all"),
        )
        .await
        .expect("retry");

        assert!(!handled.duplicate, "a failed attempt is not a handled one");
        assert_eq!(handled.records_written, 1);
        assert_eq!(agent.calls(), 2);
        assert_eq!(
            adapter.texts(),
            vec!["one event"],
            "the reply must not go out twice"
        );
    }

    #[tokio::test]
    async fn an_agent_failure_surfaces_and_leaves_the_envelope_unhandled() {
        let agent =
            Arc::new(RecordingAgent::new("reader", &[("summarise", false)]).failing("upstream"));
        let seen = Seen::new();
        let error = dispatch(
            &registry(std::slice::from_ref(&agent)),
            &FakeStore::healthy(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &seen,
            envelope("summarise all"),
        )
        .await
        .expect_err("agent failed");

        assert!(matches!(error, crate::Error::Agent(_)));
        assert_eq!(error.to_string(), "dependency unavailable: upstream");
        assert!(!seen.contains("cli-1"));
    }

    #[tokio::test]
    async fn an_attempted_task_that_failed_is_still_a_handled_envelope() {
        // A failed outcome is not an error: it is recorded and the envelope is done.
        let agent = Arc::new(
            RecordingAgent::new("reader", &[("summarise", false)])
                .with_status(Status::Failed)
                .returning_record(draft("summarise")),
        );
        let seen = Seen::new();
        let handled = dispatch(
            &registry(&[agent]),
            &FakeStore::healthy(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &seen,
            envelope("summarise all"),
        )
        .await
        .expect("dispatched");

        assert_eq!(handled.records_written, 1);
        assert!(seen.contains("cli-1"));
    }

    #[tokio::test]
    async fn an_adapter_names_the_intent_and_entities_it_understands() {
        let agent = Arc::new(RecordingAgent::new("reader", &[("digest", false)]));
        let mut raw = envelope("anything at all");
        raw.extra
            .insert("intent".into(), serde_json::json!("digest"));
        raw.extra.insert(
            "args".into(),
            serde_json::json!({"window": "1d", "text": "overridden"}),
        );
        raw.extra.insert(
            "entities".into(),
            serde_json::json!([
                {"kind": "order_ref", "id": "ord-1"},
                {"kind": "ticket"},
                "not an entity",
            ]),
        );
        let store = FakeStore::healthy();

        dispatch(
            &registry(std::slice::from_ref(&agent)),
            &store,
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            raw,
        )
        .await
        .expect("dispatched");

        let task = agent.task().expect("a task");
        assert_eq!(task.intent, "digest");
        assert_eq!(task.args["window"], serde_json::json!("1d"));
        assert_eq!(
            task.args["text"],
            serde_json::json!("anything at all"),
            "the body always arrives whole, whatever else the adapter sent"
        );
        assert_eq!(
            store.requested(),
            vec![("order_ref".to_string(), "ord-1".to_string())],
            "entries that do not name a kind and an id are dropped"
        );
    }

    #[tokio::test]
    async fn a_body_with_no_stated_intent_routes_on_its_first_word() {
        let agent = Arc::new(RecordingAgent::new("reader", &[("summarise", false)]));
        dispatch(
            &registry(std::slice::from_ref(&agent)),
            &FakeStore::healthy(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            envelope("  SUMMARISE order ord-1"),
        )
        .await
        .expect("dispatched");

        assert_eq!(agent.task().expect("a task").intent, "summarise");
    }

    #[tokio::test]
    async fn an_empty_body_is_unroutable_rather_than_a_panic() {
        let error = dispatch(
            &registry(&[Arc::new(RecordingAgent::new(
                "reader",
                &[("summarise", false)],
            ))]),
            &FakeStore::healthy(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            envelope("   "),
        )
        .await
        .expect_err("nothing to route on");

        assert!(matches!(error, crate::Error::Unroutable(ref i) if i.is_empty()));
    }

    #[tokio::test]
    async fn an_agent_reads_history_and_the_clock_through_its_context() {
        let agent = Arc::new(
            RecordingAgent::new("reader", &[("summarise", false)]).reading_history("order_ref"),
        );
        let mut raw = envelope("summarise all");
        raw.extra
            .insert("deadline_ms".into(), serde_json::json!(30_000));

        dispatch(
            &registry(std::slice::from_ref(&agent)),
            &FakeStore::healthy(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            raw,
        )
        .await
        .expect("dispatched");

        assert_eq!(
            agent.history(),
            vec!["one".to_string()],
            "history arrives as plain structure, and non-object records are dropped"
        );
        assert_eq!(agent.correlation_id().as_deref(), Some("cli-1"));
        let remaining = agent.remaining_ms().expect("a deadline");
        assert!(remaining > 0 && remaining <= 30_000, "{remaining}");
    }

    #[tokio::test]
    async fn a_store_that_cannot_be_read_reaches_the_agent_as_unavailable() {
        let agent = Arc::new(
            RecordingAgent::new("reader", &[("summarise", false)]).reading_history("order_ref"),
        );
        dispatch(
            &registry(std::slice::from_ref(&agent)),
            &FakeStore::unreachable(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            envelope("summarise all"),
        )
        .await
        .expect("dispatched degraded");

        assert_eq!(
            agent.history_error().as_deref(),
            Some("dependency unavailable: unavailable: no route to store")
        );
    }

    #[tokio::test]
    async fn an_actor_is_carried_through_with_its_source() {
        let agent = Arc::new(RecordingAgent::new("reader", &[("summarise", false)]));
        let mut raw = envelope("summarise all");
        raw.actor = None;
        dispatch(
            &registry(std::slice::from_ref(&agent)),
            &FakeStore::healthy(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            raw,
        )
        .await
        .expect("dispatched");
        assert!(agent.task().expect("a task").actor.is_none());

        let named = Arc::new(RecordingAgent::new("other", &[("digest", false)]));
        let mut raw = envelope("digest all");
        raw.envelope_id = "cli-2".into();
        dispatch(
            &registry(std::slice::from_ref(&named)),
            &FakeStore::healthy(),
            &Courier::new(filters(vec![]), Box::new(RecordingAdapter::working())),
            &Seen::new(),
            raw,
        )
        .await
        .expect("dispatched");

        let actor = named.task().expect("a task").actor.expect("an actor");
        assert_eq!((actor.id.as_str(), actor.source.as_str()), ("local", "cli"));
    }
}
