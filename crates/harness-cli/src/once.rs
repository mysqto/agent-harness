//! One envelope, no daemon.
//!
//! This mode exists because of how development actually goes. Standing up a socket, an adapter and
//! a memory service to find out why an agent answered oddly is a poor trade, so `once` runs the
//! real [`Dispatcher`] against a store that answers from nothing and reports what happened: the
//! intent the envelope resolved to, whether the context bundle was degraded, whether a mutating
//! task was refused, what would have been delivered, and what would have been written.
//!
//! Nothing leaves the process. Deliveries are reported rather than sent and records are captured
//! rather than submitted, which is what makes it safe to point at an envelope from production.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use harness_agent::ActionDraft;
use harness_dispatch::egress::{Adapter, Courier};
use harness_dispatch::{Dispatcher, Registry};
use harness_envelope::{Delivery, Envelope};
use harness_memory::Bundle;

use crate::{Error, Result};

/// What a dry run observed.
#[derive(Debug, PartialEq)]
pub struct Report {
    /// The intent the dispatcher resolved the envelope to.
    pub intent: String,
    /// The agent that handled it.
    pub agent: String,
    /// Whether the matched capability declares that it changes state.
    pub mutating: bool,
    /// Whether the context bundle was incomplete.
    pub degraded: bool,
    /// Why the bundle was incomplete, when it was.
    pub omitted: Vec<String>,
    /// Entities the dispatcher asked for context on.
    pub entities: Vec<(String, String)>,
    /// What would have been delivered, and where.
    pub deliveries: Vec<Delivery>,
    /// What would have been written to memory.
    pub records: Vec<ActionDraft>,
}

impl Report {
    /// The report as a person reads it.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        field(&mut out, "intent", &self.intent);
        field(&mut out, "agent", &self.agent);
        field(&mut out, "mutating", yes_no(self.mutating));
        field(
            &mut out,
            "context",
            &if self.degraded {
                format!("degraded — {}", self.omitted.join("; "))
            } else {
                "complete (a dry run reads nothing from memory)".to_string()
            },
        );
        field(
            &mut out,
            "entities",
            &if self.entities.is_empty() {
                "none named by the adapter".to_string()
            } else {
                self.entities
                    .iter()
                    .map(|(kind, id)| format!("{kind}/{id}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        );

        field(&mut out, "deliveries", &count(self.deliveries.len()));
        for delivery in &self.deliveries {
            let thread = delivery
                .thread
                .as_deref()
                .map_or_else(String::new, |t| format!(" [thread {t}]"));
            indented(
                &mut out,
                &format!("→ {}{}: {}", delivery.target, thread, delivery.text),
            );
        }

        field(&mut out, "records", &count(self.records.len()));
        for record in &self.records {
            let entities = record
                .entities
                .iter()
                .map(|(kind, id)| format!("{kind}/{id}"))
                .collect::<Vec<_>>()
                .join(", ");
            indented(
                &mut out,
                &format!(
                    "+ {} ({}) on {entities}: {}",
                    record.action,
                    status(record.outcome),
                    record.summary
                ),
            );
        }
        out
    }
}

/// Runs one envelope through a dispatcher built on `registry`.
///
/// `degraded` reports the context bundle as incomplete. It defaults off because a dry run that
/// always looked degraded would refuse every mutating intent, which is the one path worth
/// exercising; turning it on is how that refusal gets checked.
pub async fn once(registry: Registry, envelope: Envelope, degraded: bool) -> Result<Report> {
    let intent = resolved_intent(&envelope).await;
    let store = Arc::new(DryRun::new(degraded));
    let dispatcher = Dispatcher::new(
        registry,
        store.clone(),
        Courier::new(Vec::new(), Box::new(Discard)),
    );

    // Read off the registry rather than from the outcome: for a refusal the agent never runs, and
    // "which agent, and does it mutate" is exactly what makes the refusal understandable.
    let (agent, mutating) = match dispatcher.registry().resolve(&intent) {
        Ok(agent) => (
            agent.id().0.clone(),
            agent
                .capabilities()
                .iter()
                .find(|capability| capability.intent == intent)
                .is_some_and(|capability| capability.mutating),
        ),
        Err(_) => (String::new(), false),
    };

    match dispatcher.dispatch(envelope).await {
        Ok(handled) => Ok(Report {
            intent,
            agent,
            mutating,
            degraded: store.degraded,
            omitted: store.omitted(),
            entities: store.requested(),
            deliveries: handled.deliveries,
            records: store.written(),
        }),
        Err(harness_dispatch::Error::Unroutable(intent)) => Err(Error::Unroutable(intent)),
        Err(harness_dispatch::Error::RefusedDegraded) => Err(Error::Refused(format!(
            "refused `{intent}`: agent `{agent}` declares it mutating and the context bundle was \
             degraded — {}",
            store.omitted().join("; ")
        ))),
        // Ambiguity cannot arrive here — `Registry::register` refuses a second claimant, so routing
        // has nothing arbitrary left to do — which leaves the agent's own failure.
        Err(other) => Err(Error::Failed(other.to_string())),
    }
}

/// Reads stdin as an envelope.
///
/// Either shape is accepted. Anything starting with `{` is an envelope as JSON, and a failure to
/// parse it is the caller's mistake rather than a body that happened to look structured; anything
/// else is a plain message, wrapped in an envelope here. That is what makes
/// `echo 'echo hi' | harness once` work, which is the shortest path from a change to seeing it run.
pub fn read_envelope(input: &str) -> Result<Envelope> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::Usage(
            "nothing on stdin; expected an envelope as JSON or one line of text".to_string(),
        ));
    }
    if trimmed.starts_with('{') {
        return serde_json::from_str(trimmed)
            .map_err(|err| Error::Usage(format!("malformed envelope: {err}")));
    }
    Ok(synthesised(trimmed, SystemTime::now()))
}

/// Wraps plain text in the envelope an adapter would have sent.
///
/// The id is content-addressed, for the same reason `adapters/cli` derives its own that way: the
/// same input is the same message, so replaying it is a redelivery rather than new work.
fn synthesised(body: &str, at: SystemTime) -> Envelope {
    Envelope {
        envelope_id: format!("once-{:08x}", digest(body)),
        source: "once".to_string(),
        received_at: rfc3339(at),
        attempt: 1,
        reply_to: Some("stdout".to_string()),
        actor: Some("local".to_string()),
        body: body.to_string(),
        extra: std::collections::BTreeMap::new(),
    }
}

/// FNV-1a over the body. Not a checksum anyone depends on — just a stable name for one input.
fn digest(body: &str) -> u32 {
    body.bytes().fold(0x811c_9dc5_u32, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
    })
}

/// Formats an instant as RFC 3339 in UTC, to the second.
///
/// Hand-rolled because a date library would be the largest dependency in this crate's tree, bought
/// for one timestamp on a synthesised envelope.
fn rfc3339(at: SystemTime) -> String {
    let seconds = at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(0));
    let (hour, minute, second) = (rest / 3_600, (rest % 3_600) / 60, rest % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Days since the epoch to a calendar date, by Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// The intent the dispatcher would classify an envelope as.
///
/// Asked of a dispatcher with no agents, whose only possible answer is `Unroutable` naming the
/// intent. Roundabout, but the alternative is a second copy of the classification rules living in
/// this crate, and a copy drifts — which is the class of bug this crate exists to catch. Nothing is
/// loaded, invoked or delivered on the way: routing is resolved before any of that happens.
async fn resolved_intent(envelope: &Envelope) -> String {
    let probe = Dispatcher::new(
        Registry::new(),
        Arc::new(DryRun::new(false)),
        Courier::new(Vec::new(), Box::new(Discard)),
    );
    match probe.dispatch(envelope.clone()).await {
        Err(harness_dispatch::Error::Unroutable(intent)) => intent,
        _ => String::new(),
    }
}

/// A store that answers from nothing and keeps what it was asked to write.
///
/// This is what makes a dry run safe to point at a real envelope: reads return an empty bundle and
/// writes never leave the process.
#[derive(Debug)]
pub struct DryRun {
    degraded: bool,
    requested: Mutex<Vec<(String, String)>>,
    written: Mutex<Vec<ActionDraft>>,
}

impl DryRun {
    /// A store reporting bundles as complete, or as degraded when `degraded` is set.
    #[must_use]
    pub fn new(degraded: bool) -> Self {
        Self {
            degraded,
            requested: Mutex::new(Vec::new()),
            written: Mutex::new(Vec::new()),
        }
    }

    /// Entities context was asked for.
    #[must_use]
    pub fn requested(&self) -> Vec<(String, String)> {
        guard(&self.requested).clone()
    }

    /// Records that would have been submitted.
    #[must_use]
    pub fn written(&self) -> Vec<ActionDraft> {
        guard(&self.written).clone()
    }

    /// Why the bundle was incomplete, in the words a real store would have used.
    fn omitted(&self) -> Vec<String> {
        if self.degraded {
            vec!["dry run asked to report the store unreachable".to_string()]
        } else {
            Vec::new()
        }
    }
}

#[async_trait::async_trait]
impl harness_dispatch::ContextStore for DryRun {
    async fn bundle(
        &self,
        entities: &[(String, String)],
        _deadline_ms: u64,
    ) -> harness_memory::Result<Bundle> {
        guard(&self.requested).extend_from_slice(entities);
        Ok(Bundle {
            records: Vec::new(),
            degraded: self.degraded,
            omitted: self.omitted(),
        })
    }

    async fn submit(&self, draft: &ActionDraft) -> harness_memory::Result<()> {
        guard(&self.written).push(draft.clone());
        Ok(())
    }
}

/// An adapter with nowhere to send.
///
/// A dry run reports deliveries instead of making them, and the dispatcher hands back what it
/// tried to deliver, so accepting and dropping loses nothing.
pub struct Discard;

#[async_trait::async_trait]
impl Adapter for Discard {
    async fn send(&self, delivery: &Delivery) -> std::result::Result<(), harness_envelope::Error> {
        tracing::debug!(envelope_id = %delivery.envelope_id, "dry run: not delivering");
        Ok(())
    }
}

/// Takes a lock, keeping what is behind it if a previous holder panicked.
fn guard<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Writes one `label  value` line.
fn field(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "{label:<11}{value}");
}

/// Writes one indented continuation line.
fn indented(out: &mut String, value: &str) {
    let _ = writeln!(out, "           {value}");
}

/// `n` as a count, or `none`.
fn count(total: usize) -> String {
    if total == 0 {
        "none".to_string()
    } else {
        total.to_string()
    }
}

fn yes_no(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}

/// A status as it appears on the wire, so the report and a record agree on the word.
fn status(status: harness_agent::Status) -> String {
    serde_json::to_string(&status)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    use harness_dispatch::Registry;

    use super::{once, read_envelope, rfc3339, synthesised};
    use crate::fixtures::{Configured, envelope};
    use crate::{Error, exit, registry};

    fn echo() -> Registry {
        registry(&["echo".to_string()]).expect("registry")
    }

    fn only(agent: Configured) -> Registry {
        let mut registry = Registry::new();
        registry.register(Arc::new(agent)).expect("register");
        registry
    }

    #[tokio::test]
    async fn a_valid_envelope_reports_the_intent_and_the_would_be_deliveries() {
        let report = once(echo(), envelope("echo hello"), false)
            .await
            .expect("dispatch");

        assert_eq!(report.intent, "echo");
        assert_eq!(report.agent, "echo");
        assert!(!report.mutating);
        assert!(!report.degraded);
        assert_eq!(report.deliveries.len(), 1);
        assert_eq!(report.deliveries[0].text, "hello");
        assert_eq!(
            report.deliveries[0].target, "stdout",
            "an empty egress target resolves to the envelope's reply_to"
        );
        assert!(report.records.is_empty());

        let rendered = report.render();
        for expected in [
            "intent     echo",
            "agent      echo",
            "mutating   no",
            "deliveries 1",
            "→ stdout: hello",
            "records    none",
        ] {
            assert!(
                rendered.contains(expected),
                "missing `{expected}`:\n{rendered}"
            );
        }
    }

    #[tokio::test]
    async fn the_echo_agent_round_trips_a_body_through_the_dispatcher() {
        // The plumbing test: adapter shape in, agent, courier, delivery out.
        let report = once(echo(), envelope("echo order ord-91h2"), false)
            .await
            .expect("dispatch");
        assert_eq!(report.deliveries[0].text, "order ord-91h2");
        assert_eq!(report.deliveries[0].envelope_id, "test-19");
    }

    #[tokio::test]
    async fn an_unroutable_intent_reports_the_unroutable_code() {
        let error = once(echo(), envelope("summarise order ord-91h2"), false)
            .await
            .expect_err("no agent claims summarise");
        assert_eq!(error.code(), exit::UNROUTABLE);
        assert!(matches!(error, Error::Unroutable(ref intent) if intent == "summarise"));
    }

    #[tokio::test]
    async fn a_mutating_intent_on_a_degraded_bundle_is_refused_and_says_why() {
        let error = once(
            only(Configured::new("deployer", "deploy", true)),
            envelope("deploy service"),
            true,
        )
        .await
        .expect_err("refused");

        assert_eq!(error.code(), exit::REFUSED);
        let why = error.to_string();
        for expected in ["deploy", "deployer", "mutating", "degraded"] {
            assert!(why.contains(expected), "missing `{expected}` in: {why}");
        }
    }

    #[tokio::test]
    async fn the_same_intent_is_allowed_when_the_bundle_is_intact() {
        // The refusal is about the bundle, not about the intent: with context intact it proceeds.
        let report = once(
            only(Configured::new("deployer", "deploy", true).writing("deploy", ("deploy", "d-7"))),
            envelope("deploy service"),
            false,
        )
        .await
        .expect("dispatch");

        assert!(report.mutating);
        assert_eq!(report.records.len(), 1);
        let rendered = report.render();
        assert!(rendered.contains("mutating   yes"), "{rendered}");
        assert!(
            rendered.contains("+ deploy (succeeded) on deploy/d-7: deploy was applied"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn a_degraded_bundle_is_reported_for_a_read() {
        let report = once(echo(), envelope("echo hello"), true)
            .await
            .expect("dispatch");
        assert!(report.degraded);
        assert!(report.render().contains("context    degraded — dry run"));
    }

    #[tokio::test]
    async fn entities_named_by_the_adapter_are_reported() {
        let mut envelope = envelope("echo hello");
        envelope.extra.insert(
            "entities".to_string(),
            serde_json::json!([{"kind": "order_ref", "id": "ord-91h2"}]),
        );
        let report = once(echo(), envelope, false).await.expect("dispatch");

        assert_eq!(
            report.entities,
            vec![("order_ref".to_string(), "ord-91h2".to_string())]
        );
        assert!(report.render().contains("entities   order_ref/ord-91h2"));
    }

    #[tokio::test]
    async fn an_agent_that_could_not_attempt_the_task_reports_a_plain_failure() {
        // Distinct from a refusal: nothing was decided against, something was unreachable.
        let error = once(
            only(Configured::new("reader", "summarise", false).failing("no memory")),
            envelope("summarise order ord-91h2"),
            false,
        )
        .await
        .expect_err("the agent could not attempt it");

        assert_eq!(error.code(), exit::FAILED);
        assert!(error.to_string().contains("no memory"), "{error}");
    }

    #[test]
    fn plain_text_becomes_an_envelope_with_a_content_addressed_id() {
        let first = read_envelope("echo hello\n").expect("wrap");
        let again = read_envelope("  echo hello  ").expect("wrap");

        assert_eq!(first.envelope_id, again.envelope_id);
        assert_ne!(
            first.envelope_id,
            read_envelope("echo goodbye").unwrap().envelope_id
        );
        assert_eq!(first.body, "echo hello");
        assert_eq!(first.source, "once");
        assert_eq!(first.attempt, 1);
        assert_eq!(first.reply_to.as_deref(), Some("stdout"));
    }

    #[test]
    fn an_envelope_as_json_is_taken_as_it_stands() {
        let raw = r#"{"envelope_id":"cli-123","source":"cli","received_at":"2026-08-19T14:30:12Z",
            "attempt":2,"reply_to":"stdout","actor":"local","body":"echo hi","extra":{}}"#;
        let parsed = read_envelope(raw).expect("parse");
        assert_eq!(parsed.envelope_id, "cli-123");
        assert_eq!(parsed.attempt, 2);
    }

    #[test]
    fn a_malformed_envelope_is_a_usage_error_rather_than_a_panic() {
        for input in [
            r#"{"envelope_id": "cli-1", "source":"#,
            r#"{"source":"cli","body":"echo hi"}"#,
            "{}",
        ] {
            let error = read_envelope(input).expect_err("malformed");
            assert_eq!(error.code(), exit::USAGE, "for {input}");
            assert!(error.to_string().contains("malformed envelope"));
        }
    }

    #[test]
    fn empty_input_is_a_usage_error() {
        let error = read_envelope("  \n ").expect_err("empty");
        assert_eq!(error.code(), exit::USAGE);
        assert!(error.to_string().contains("nothing on stdin"));
    }

    #[test]
    fn a_synthesised_envelope_is_stamped_in_rfc_3339() {
        let at = UNIX_EPOCH + Duration::new(1_755_612_000, 0);
        assert_eq!(
            synthesised("echo hi", at).received_at,
            "2025-08-19T14:00:00Z"
        );
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // A leap day, which is where a hand-rolled calendar goes wrong if it is going to.
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::new(1_709_164_800, 0)),
            "2024-02-29T00:00:00Z"
        );
    }
}
