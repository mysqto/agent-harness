//! The route decision, the bundle it names, and the worker that runs from both.
//!
//! A worker is not a smaller agent. The difference is what it can reach: an [`harness_agent::Agent`] holds a
//! `Context` whose memory handle goes to the store, so it can fetch whatever it decides it needs,
//! while a [`Worker`] holds only what the dispatcher composed for it. That is the property §5.5 of
//! the plan asks for, and stating it as a trait is what makes it a property of the code rather than
//! an instruction in a prompt: there is no read method on [`Handed`], so a worker that wanted to go
//! and look has nothing to look with.
//!
//! Two ids carry that: a [`Route`] names the decision and a [`Handout`] names the context it was
//! decided against. Both are **content addresses** — a hash over the thing itself — rather than
//! fresh ULIDs, which is the one difference from §5.4 worth understanding. A minted id says only
//! "somebody named this"; nothing can check it, and nothing fails when a composer hands over the
//! wrong context under a right-looking name. An address is recomputable, so [`Route::verify`] can
//! refuse a bundle that is not the one the decision was taken against, and an auditor holding a
//! record and a bundle can tell whether they belong together. That refusal is what this module is
//! for: the pilot that ran a worker from handed context reported that its handout was "prose in a
//! chat message — no version, no schema, nothing that fails when the composer gets it wrong".
//! This is the thing that fails.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use harness_agent::{ActionDraft, AgentId, Capability, Health, Outcome};
use harness_memory::Bundle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version of the route decision shape, carried on every decision.
///
/// A worker in another language matches on this before it reads anything else, so a shape change
/// that kept the old version would be indistinguishable from a worker parsing the new shape wrong.
pub const ROUTE_VER: &str = "1.0";

/// Version of the handout shape.
pub const BUNDLE_VER: &str = "1.0";

/// How many bytes of the digest an id carries.
///
/// 16 bytes, so two distinct decisions colliding is not something that happens to a deployment.
/// The full 32 would double the length of every id in every log line for no reachable gain.
const ID_BYTES: usize = 16;

/// Context composed for one worker, handed over whole.
///
/// **By value, not by reference**, and that is a decision rather than a transcription of §5.3.
/// Passing a `bundle_id` for the worker to fetch would need two things this system does not have: a
/// store that keeps composed bundles (`GET /bundle` composes fresh per call and keeps nothing), and
/// a worker holding a credential for that store — which is exactly the reach the [`Worker`] trait
/// exists to remove. It would also be wrong later rather than merely unimplemented: a worker that
/// ran an hour after the decision would fetch context the store had moved on to, and get *different*
/// context under the *same* id, which is worse than getting none.
///
/// So the bundle travels with the decision and the id travels with the bundle. The id still earns
/// its place, because it is an address: [`Handout::is_intact`] recomputes it, so a handout that was
/// edited between composition and receipt stops being anonymous.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Handout {
    /// Address of everything below.
    pub bundle_id: String,
    /// Shape version. See [`BUNDLE_VER`].
    pub bundle_ver: String,
    /// The envelope this was composed for.
    pub for_envelope: String,
    /// Entities the composer asked the store about, as `(kind, id)`.
    ///
    /// Kept because "the bundle is thin" and "the bundle was never asked about this" are different
    /// failures with different owners: the first is the store's, the second is the composer's, and
    /// a worker that cannot tell them apart reports the wrong one.
    pub covers: Vec<(String, String)>,
    /// Records the store judged relevant, exactly as it put them on the wire.
    pub records: Vec<serde_json::Value>,
    /// `true` when the composition was known to be incomplete.
    pub degraded: bool,
    /// What was left out, and why.
    pub omitted: Vec<String>,
}

impl Handout {
    /// Composes a handout from what the store returned.
    ///
    /// `covers` is what was asked for rather than what came back, so an entity the store had
    /// nothing for is still visibly *covered* — otherwise a worker cannot distinguish an entity
    /// with no history from one nobody asked about.
    #[must_use]
    pub fn compose(envelope_id: &str, covers: &[(String, String)], bundle: Bundle) -> Self {
        let mut handout = Self {
            bundle_id: String::new(),
            bundle_ver: BUNDLE_VER.to_owned(),
            for_envelope: envelope_id.to_owned(),
            covers: covers.to_vec(),
            records: bundle.records,
            degraded: bundle.degraded,
            omitted: bundle.omitted,
        };
        handout.bundle_id = handout.address();
        handout
    }

    /// The address of this handout's contents.
    #[must_use]
    pub fn address(&self) -> String {
        let mut hasher = Sha256::new();
        field(&mut hasher, self.bundle_ver.as_bytes());
        field(&mut hasher, self.for_envelope.as_bytes());
        for (kind, id) in &self.covers {
            field(&mut hasher, kind.as_bytes());
            field(&mut hasher, id.as_bytes());
        }
        for record in &self.records {
            field(&mut hasher, record.to_string().as_bytes());
        }
        field(&mut hasher, &[u8::from(self.degraded)]);
        for reason in &self.omitted {
            field(&mut hasher, reason.as_bytes());
        }
        id_from("b-", hasher)
    }

    /// Whether the id still describes the contents.
    ///
    /// False means the bundle was changed after it was composed. Nothing in this process does that;
    /// the check is here because a handout crossing a process boundary is the case this shape was
    /// designed for, and an id nobody verifies is decoration.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.address() == self.bundle_id
    }

    /// Whether the composer asked the store about this entity.
    #[must_use]
    pub fn asked_about(&self, kind: &str, id: &str) -> bool {
        self.covers
            .iter()
            .any(|(covered, about)| covered == kind && about == id)
    }
}

/// The decision to run one worker on one envelope against one handout.
///
/// §5.4's fields, with `route_id` and `bundle_id` as addresses rather than minted ids, and with
/// `intent` added: the dispatcher routes on intent, so a decision that did not carry the intent it
/// resolved could not be checked against the worker that received it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Route {
    /// Address of the decision: every field below, this one excepted.
    ///
    /// Two dispatches that decided the same thing about the same envelope against the same context
    /// therefore share a route id, and anything that changed the decision — a different worker, a
    /// re-composed bundle, an argument the adapter added — changes it. That is what makes it worth
    /// having beside `envelope_id`, which names the message and cannot distinguish two decisions
    /// taken about it.
    pub route_id: String,
    /// Shape version. See [`ROUTE_VER`].
    pub route_ver: String,
    /// The message that caused this.
    pub envelope_id: String,
    /// Who was routed to.
    pub worker: AgentId,
    /// The handout this decision was taken against.
    pub bundle_id: String,
    /// What the envelope was classified as.
    pub intent: String,
    /// Arguments, as the dispatcher normalised them.
    ///
    /// The one part of the decision with no schema behind it: the adapter fills it and nothing
    /// validates it. What keeps that from being a free-for-all is that it is *addressed* — a worker
    /// that ran different arguments ran a different route — and that a worker may declare the keys
    /// it will not run without (see [`Worker::requires`]).
    pub args: BTreeMap<String, serde_json::Value>,
    /// How long the worker has.
    pub deadline_ms: u64,
    /// Whether this changes state somewhere.
    ///
    /// Load-bearing, not decoration: it is what selects fail-open against fail-closed on a degraded
    /// handout, and the dispatcher has already applied it before the worker sees it.
    pub mutating: bool,
}

impl Route {
    /// Takes the decision, addressing it.
    ///
    /// The envelope id comes from the handout rather than from the caller, so a decision cannot
    /// name one envelope while carrying context composed for another.
    #[must_use]
    pub fn decide(
        handout: &Handout,
        worker: &AgentId,
        intent: &str,
        args: BTreeMap<String, serde_json::Value>,
        deadline_ms: u64,
        mutating: bool,
    ) -> Self {
        let mut route = Self {
            route_id: String::new(),
            route_ver: ROUTE_VER.to_owned(),
            envelope_id: handout.for_envelope.clone(),
            worker: worker.clone(),
            bundle_id: handout.bundle_id.clone(),
            intent: intent.to_owned(),
            args,
            deadline_ms,
            mutating,
        };
        route.route_id = route.address();
        route
    }

    /// The address of this decision's contents.
    #[must_use]
    pub fn address(&self) -> String {
        let mut hasher = Sha256::new();
        field(&mut hasher, self.route_ver.as_bytes());
        field(&mut hasher, self.envelope_id.as_bytes());
        field(&mut hasher, self.worker.0.as_bytes());
        field(&mut hasher, self.bundle_id.as_bytes());
        field(&mut hasher, self.intent.as_bytes());
        for (key, value) in &self.args {
            field(&mut hasher, key.as_bytes());
            field(&mut hasher, value.to_string().as_bytes());
        }
        field(&mut hasher, &self.deadline_ms.to_le_bytes());
        field(&mut hasher, &[u8::from(self.mutating)]);
        id_from("r-", hasher)
    }

    /// Whether the id still describes the decision.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.address() == self.route_id
    }

    /// Refuses a handout that is not the one this decision was taken against.
    ///
    /// Every way the pair can be wrong is one failure: a worker running the right decision over the
    /// wrong context. It is checked where the worker receives them rather than where they are
    /// composed, because in-process they were composed together and cannot disagree — the crossing
    /// is where a composer's mistake becomes invisible.
    pub fn verify(&self, handout: &Handout) -> crate::Result<()> {
        let detail = if !self.is_intact() {
            "the decision does not match its own id"
        } else if !handout.is_intact() {
            "the handout does not match its own id"
        } else if handout.bundle_id != self.bundle_id {
            "the handout is a different bundle"
        } else if handout.for_envelope != self.envelope_id {
            "the handout was composed for another envelope"
        } else {
            return Ok(());
        };
        Err(crate::Error::Mismatched {
            route_id: self.route_id.clone(),
            bundle_id: handout.bundle_id.clone(),
            detail: detail.to_owned(),
        })
    }
}

/// Everything a worker is given, and everything it can reach.
///
/// There is deliberately no read here. An agent's `Context` offers `memory()`, and a worker holding
/// one could fetch context nobody composed for it — which is the difference between a stateless
/// worker and an agent with a shorter prompt. A worker handed too little refuses and says so; it
/// does not go and complete the handout, because a worker that completes its own context produces
/// an answer nobody can reconstruct.
#[async_trait::async_trait]
pub trait Handed: Send + Sync {
    /// The decision this run is executing.
    fn route(&self) -> &Route;

    /// The context composed for it.
    fn bundle(&self) -> &Handout;

    /// Milliseconds left before the dispatcher abandons this run.
    fn remaining_ms(&self) -> u64;

    /// Queues a record. The dispatcher stamps and submits it, so a worker cannot attribute an
    /// action to someone else or backdate one.
    async fn record(&self, draft: ActionDraft) -> harness_agent::Result<()>;
}

/// A stateless unit of work, addressed by name.
///
/// The Rust spelling of §5.5's `worker.<name>.run(route_id, envelope_id, bundle_id, args)`: all
/// four arrive through [`Handed::route`], and the bundle those ids name arrives with them rather
/// than being fetched.
#[async_trait::async_trait]
pub trait Worker: Send + Sync {
    /// Stable identity. Records are attributed to it, so it must not change across restarts or the
    /// audit trail splits.
    fn id(&self) -> &AgentId;

    /// What this worker can handle. The dispatcher routes on this rather than on a table.
    fn capabilities(&self) -> &[Capability];

    /// Argument keys this worker will not run without, for one intent.
    ///
    /// The dispatcher refuses the route rather than invoking a worker that will fail on the first
    /// line, which turns a composer's omission into a refusal naming the missing key instead of a
    /// worker's error naming nothing. Empty by default: a worker that reads the whole handout and
    /// no arguments has nothing to declare.
    fn requires(&self, intent: &str) -> &[&str] {
        let _ = intent;
        &[]
    }

    /// Runs one decision.
    ///
    /// `Err` means the run could not be attempted; a run that was attempted and failed is `Ok`
    /// carrying [`harness_agent::Status::Failed`]. One is worth retrying and the other is worth
    /// recording.
    async fn run(&self, given: &dyn Handed) -> harness_agent::Result<Outcome>;

    /// Whether this worker is ready for work.
    ///
    /// Checked before a bundle is composed. A worker that cannot work is a refusal rather than a
    /// degrade — see [`crate::Error::Unreachable`].
    async fn health(&self) -> Health {
        Health::Ready
    }
}

// Routing needs an identity and a claim, and neither trait's own methods are named for routing.
// One rule, applied to both, so a worker registry cannot resolve by a different rule than an agent
// registry does.
impl crate::registry::Routable for dyn Worker {
    fn handler_id(&self) -> &AgentId {
        Worker::id(self)
    }

    fn claims(&self) -> &[Capability] {
        Worker::capabilities(self)
    }
}

/// The workers a dispatcher can hand off to.
pub type Workers = crate::Registry<dyn Worker>;

/// One worker's run, in progress.
///
/// Public because a host that runs workers out of process — over the MCP tool or the HTTP route
/// §5.5 names — needs to rebuild this on the receiving side, and [`Handing::new`] is where the
/// route and the handout are checked against each other.
#[derive(Debug)]
pub struct Handing {
    route: Route,
    handout: Handout,
    started: Instant,
    drafts: Mutex<Vec<ActionDraft>>,
}

impl Handing {
    /// Binds a decision to the handout it names, refusing a pair that does not belong together.
    pub fn new(route: Route, handout: Handout) -> crate::Result<Self> {
        route.verify(&handout)?;
        Ok(Self {
            route,
            handout,
            started: Instant::now(),
            drafts: Mutex::new(Vec::new()),
        })
    }

    /// The decision, and everything the worker queued while it ran.
    #[must_use]
    pub fn finish(self) -> (Route, Vec<ActionDraft>) {
        (
            self.route,
            self.drafts
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }
}

#[async_trait::async_trait]
impl Handed for Handing {
    fn route(&self) -> &Route {
        &self.route
    }

    fn bundle(&self) -> &Handout {
        &self.handout
    }

    fn remaining_ms(&self) -> u64 {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.route.deadline_ms.saturating_sub(elapsed)
    }

    async fn record(&self, draft: ActionDraft) -> harness_agent::Result<()> {
        self.drafts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(draft);
        Ok(())
    }
}

/// Feeds one field into a digest, its length first.
///
/// Length prefixing is what keeps the address unambiguous: without it a worker called `ab` handling
/// `c` and a worker called `a` handling `bc` feed the hasher the same bytes, and two decisions
/// sharing an id is the single failure an id exists to prevent.
fn field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

/// Renders a finished digest as a prefixed id.
fn id_from(prefix: &str, hasher: Sha256) -> String {
    let digest = hasher.finalize();
    let mut out = String::with_capacity(prefix.len() + ID_BYTES * 2);
    out.push_str(prefix);
    for byte in &digest[..ID_BYTES] {
        // Infallible: the target is a String, whose `fmt::Write` never errors.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};

    use harness_agent::{AgentId, Status};
    use harness_memory::Bundle;

    use super::{BUNDLE_VER, Handed, Handing, Handout, ROUTE_VER, Route};
    use crate::Error;
    use crate::fixtures::draft;

    fn bundle() -> Bundle {
        Bundle {
            records: vec![serde_json::json!({"id": "one"})],
            degraded: false,
            omitted: Vec::new(),
        }
    }

    fn covers() -> Vec<(String, String)> {
        vec![("order_ref".into(), "ord-1".into())]
    }

    fn handout() -> Handout {
        Handout::compose("env-1", &covers(), bundle())
    }

    fn args() -> BTreeMap<String, serde_json::Value> {
        [("text".to_string(), serde_json::json!("summarise ord-1"))]
            .into_iter()
            .collect()
    }

    fn route(handout: &Handout) -> Route {
        Route::decide(
            handout,
            &AgentId("lookup".into()),
            "summarise",
            args(),
            5_000,
            false,
        )
    }

    #[test]
    fn composing_the_same_context_twice_addresses_it_the_same() {
        // The property an address buys over a minted id: two composers that did the same work agree
        // on what to call it, without a ledger between them.
        let first = handout();
        let second = Handout::compose("env-1", &covers(), bundle());

        assert_eq!(first.bundle_id, second.bundle_id);
        assert!(first.bundle_id.starts_with("b-"));
        assert_eq!(first.bundle_ver, BUNDLE_VER);
        assert!(first.is_intact());
    }

    #[test]
    fn every_part_of_a_handout_moves_its_id() {
        // Anything not covered here is something a composer could get wrong without the id
        // changing, which is the one failure this id exists to make visible.
        let base = handout();
        let mut edits = Vec::new();

        let mut other_envelope = base.clone();
        other_envelope.for_envelope = "env-2".into();
        edits.push(other_envelope);

        let mut other_entity = base.clone();
        other_entity.covers = vec![("order_ref".into(), "ord-2".into())];
        edits.push(other_entity);

        let mut other_records = base.clone();
        other_records.records = vec![serde_json::json!({"id": "two"})];
        edits.push(other_records);

        let mut fewer_records = base.clone();
        fewer_records.records.clear();
        edits.push(fewer_records);

        let mut degraded = base.clone();
        degraded.degraded = true;
        edits.push(degraded);

        let mut omitted = base.clone();
        omitted.omitted = vec!["knowledge: timeout".into()];
        edits.push(omitted);

        let mut versioned = base.clone();
        versioned.bundle_ver = "2.0".into();
        edits.push(versioned);

        let addresses: HashSet<String> = std::iter::once(base.address())
            .chain(edits.iter().map(Handout::address))
            .collect();
        assert_eq!(
            addresses.len(),
            edits.len() + 1,
            "two different handouts share an address"
        );
        for edited in &edits {
            assert!(
                !edited.is_intact(),
                "an edited handout still matches its id"
            );
        }
    }

    #[test]
    fn every_part_of_a_decision_moves_its_route_id() {
        let handout = handout();
        let base = route(&handout);
        let mut edits = Vec::new();

        let mut other_worker = base.clone();
        other_worker.worker = AgentId("other".into());
        edits.push(other_worker);

        let mut other_intent = base.clone();
        other_intent.intent = "explain".into();
        edits.push(other_intent);

        let mut other_envelope = base.clone();
        other_envelope.envelope_id = "env-2".into();
        edits.push(other_envelope);

        let mut other_bundle = base.clone();
        other_bundle.bundle_id = "b-0000".into();
        edits.push(other_bundle);

        let mut other_args = base.clone();
        other_args.args.insert("limit".into(), serde_json::json!(5));
        edits.push(other_args);

        let mut other_deadline = base.clone();
        other_deadline.deadline_ms = 20_000;
        edits.push(other_deadline);

        let mut mutating = base.clone();
        mutating.mutating = true;
        edits.push(mutating);

        let mut versioned = base.clone();
        versioned.route_ver = "2.0".into();
        edits.push(versioned);

        let addresses: HashSet<String> = std::iter::once(base.address())
            .chain(edits.iter().map(Route::address))
            .collect();
        assert_eq!(
            addresses.len(),
            edits.len() + 1,
            "two different decisions share a route id"
        );
        assert!(base.is_intact());
        assert!(base.route_id.starts_with("r-"));
        assert_eq!(base.route_ver, ROUTE_VER);
        assert_eq!(base.envelope_id, handout.for_envelope);
        assert_eq!(base.bundle_id, handout.bundle_id);
    }

    #[test]
    fn an_id_cannot_be_moved_from_one_field_into_its_neighbour() {
        // Length prefixing, asserted rather than assumed: without it a worker called `ab` handling
        // `c` and one called `a` handling `bc` feed the digest identical bytes.
        let handout = handout();
        let one = Route::decide(
            &handout,
            &AgentId("ab".into()),
            "c",
            BTreeMap::new(),
            5_000,
            false,
        );
        let other = Route::decide(
            &handout,
            &AgentId("a".into()),
            "bc",
            BTreeMap::new(),
            5_000,
            false,
        );

        assert_ne!(one.route_id, other.route_id);
    }

    #[test]
    fn a_decision_refuses_a_handout_it_does_not_name() {
        // The whole point of the pair: a worker running the right decision over another decision's
        // context writes records citing a bundle that never reached it.
        let handout = handout();
        let route = route(&handout);
        let elsewhere = Handout::compose("env-2", &covers(), bundle());

        let error = route
            .verify(&elsewhere)
            .expect_err("a handout composed for another envelope");
        assert!(matches!(error, Error::Mismatched { ref detail, .. }
            if detail == "the handout is a different bundle"));
        assert!(error.to_string().contains(&route.route_id));
    }

    #[test]
    fn a_handout_edited_after_composition_is_refused() {
        let mut handout = handout();
        let route = route(&handout);
        handout.records.push(serde_json::json!({"id": "smuggled"}));

        let error = route.verify(&handout).expect_err("an edited handout");
        assert!(matches!(error, Error::Mismatched { ref detail, .. }
            if detail == "the handout does not match its own id"));
    }

    #[test]
    fn a_decision_edited_after_it_was_taken_is_refused() {
        let handout = handout();
        let mut route = route(&handout);
        route.mutating = true;

        let error = route.verify(&handout).expect_err("an edited decision");
        assert!(matches!(error, Error::Mismatched { ref detail, .. }
            if detail == "the decision does not match its own id"));
    }

    #[test]
    fn a_handout_names_what_the_composer_asked_about_rather_than_what_came_back() {
        // An entity the store had nothing for is still covered. A worker that could not tell that
        // apart from an entity nobody asked about would report the wrong party's failure.
        let handout = Handout::compose(
            "env-1",
            &[
                ("order_ref".into(), "ord-1".into()),
                ("ticket".into(), "T-9".into()),
            ],
            Bundle::default(),
        );

        assert!(handout.asked_about("order_ref", "ord-1"));
        assert!(handout.asked_about("ticket", "T-9"));
        assert!(!handout.asked_about("ticket", "T-8"));
        assert!(!handout.asked_about("order_ref", "ord-2"));
        assert!(handout.records.is_empty());
    }

    #[test]
    fn a_route_and_a_handout_survive_a_json_round_trip() {
        // §5.5 puts a worker behind an MCP tool or an HTTP route, so both shapes cross a process
        // boundary as JSON and a field lost there is a field lost at the boundary.
        let handout = handout();
        let route = route(&handout);

        let parsed: Route =
            serde_json::from_str(&serde_json::to_string(&route).expect("serialise"))
                .expect("parse");
        assert_eq!(parsed, route);
        assert!(parsed.is_intact());

        let parsed: Handout =
            serde_json::from_str(&serde_json::to_string(&handout).expect("serialise"))
                .expect("parse");
        assert_eq!(parsed, handout);
        assert!(parsed.is_intact());
    }

    #[tokio::test]
    async fn a_worker_run_holds_the_records_it_queued_until_the_dispatcher_takes_them() {
        // Queued rather than written: the dispatcher stamps and submits, which is what stops a
        // worker attributing an action to someone else.
        let handout = handout();
        let route = route(&handout);
        let given = Handing::new(route.clone(), handout).expect("a matching pair");

        given.record(draft("review")).await.expect("queue");
        given.record(draft("comment")).await.expect("queue");

        assert_eq!(given.route(), &route);
        assert_eq!(given.bundle().records.len(), 1);
        assert!(given.remaining_ms() <= 5_000);
        let (taken, drafts) = given.finish();
        assert_eq!(taken, route);
        assert_eq!(
            drafts.iter().map(|d| d.action.clone()).collect::<Vec<_>>(),
            vec!["review".to_string(), "comment".to_string()]
        );
        assert_eq!(drafts[0].outcome, Status::Succeeded);
    }

    #[test]
    fn a_run_cannot_be_bound_to_a_bundle_the_decision_does_not_name() {
        let handout = handout();
        let route = route(&handout);
        let elsewhere = Handout::compose("env-1", &[], bundle());

        assert!(matches!(
            Handing::new(route, elsewhere),
            Err(Error::Mismatched { .. })
        ));
    }
}
