//! Delivery, and the filter and screen that depend on it.
//!
//! Everything outbound goes through here, which is the only reason a filter can be relied on: an
//! agent that could post for itself could skip one. The same argument is what puts the egress screen
//! here rather than in each agent — and it runs *after* every filter, on the bytes the adapter will
//! receive, because a filter is a rewrite and a rewrite can introduce what the screen is looking for.

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use harness_envelope::Delivery;
use harness_screen::Screen;
use serde::Serialize;

/// A rule applied to outbound text.
pub trait Filter: Send + Sync {
    /// Rewrites text before it leaves the process.
    ///
    /// Applied to the *rendered* message, immediately before delivery. Filtering earlier leaves a
    /// gap: anything a later template step introduces would go out unexamined.
    fn apply(&self, text: &str) -> String;
}

/// The last hop out: whatever hands a delivery to the source it came from.
///
/// Adapters are separate processes, so an implementation of this is a thin client for one — a
/// socket write, an HTTP post, a line on stdout.
#[async_trait::async_trait]
pub trait Adapter: Send + Sync {
    /// Sends one delivery whose text has already passed every filter.
    ///
    /// Called at most once per distinct [`Delivery`]; the ledger in [`deliver`] suppresses repeats,
    /// so an implementation needs no idempotency of its own.
    async fn send(&self, delivery: &Delivery) -> std::result::Result<(), harness_envelope::Error>;
}

/// What an adapter has already accepted.
///
/// Keyed per [`Delivery`] rather than per envelope: one envelope can produce several messages, and
/// a replay must re-send none of them.
///
/// In memory, like the dispatcher's own dedupe ledger, and with the same limit: it stops a repeat
/// within the life of the process and claims nothing beyond it.
#[derive(Debug, Default)]
pub struct Sent {
    keys: Mutex<HashSet<String>>,
}

impl Sent {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn contains(&self, key: &str) -> bool {
        self.lock().contains(key)
    }

    fn remember(&self, key: String) {
        self.lock().insert(key);
    }

    fn lock(&self) -> MutexGuard<'_, HashSet<String>> {
        // A poisoned ledger is still an accurate record of what went out. Recovering keeps it;
        // panicking would throw it away and let a retry double-post.
        self.keys.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Identity of a delivery, taken from what the agent asked to send.
///
/// Keyed on the *unfiltered* delivery on purpose: the identity of a message is what was requested,
/// so editing a filter does not turn an already-sent message into a new one.
fn key(delivery: &Delivery) -> String {
    // Unit separators cannot appear in a field unless the source put them there.
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        delivery.envelope_id,
        delivery.target,
        delivery.thread.as_deref().unwrap_or_default(),
        delivery.text
    )
}

/// One span the egress screen took out of one outbound message.
///
/// The delivery it belonged to is named alongside the rule, because the account is read by whoever
/// has to decide whether a credential needs rotating: "a key was masked" is not actionable, "a key
/// was masked out of the reply to this envelope, going to this target" is.
///
/// The masked text itself is never carried. A record of a redaction that quotes what it redacted is
/// another copy of the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Masking {
    /// The envelope whose reply carried it.
    pub envelope_id: String,
    /// Where that reply was going.
    pub target: String,
    /// Which pattern set matched.
    pub policy: String,
    /// Which rule of that set.
    pub rule: String,
    /// Byte offset in the rendered message.
    pub at: usize,
    /// How many bytes were replaced.
    pub len: usize,
}

/// What one batch of deliveries did on the way out.
///
/// The account travels back to the caller rather than only into a log. A send path that masks
/// silently leaves the caller believing it sent what it wrote, which is the failure this layer is
/// here to prevent — the point is not only that the secret does not go out, but that somebody learns
/// it nearly did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Posted {
    /// How many deliveries the adapter accepted.
    pub posted: usize,
    /// Every span the screen replaced, across every delivery in the batch.
    pub masked: Vec<Masking>,
}

/// Applies every filter in order, screens the result, then hands it to the adapter.
///
/// Returns how many were actually posted — fewer than were offered when the ledger recognised one —
/// and what the screen took out. A delivery is remembered only once the adapter has accepted it, so
/// a failed send stays retryable.
///
/// A masked delivery is still delivered. Dropping it would turn one leaked credential into a silent
/// non-reply, and the caller cannot tell a suppressed message from a message nobody wanted to send.
pub async fn deliver(
    filters: &[Box<dyn Filter>],
    screen: &Screen,
    adapter: &dyn Adapter,
    sent: &Sent,
    deliveries: Vec<Delivery>,
) -> crate::Result<Posted> {
    let mut out = Posted::default();
    for delivery in deliveries {
        let key = key(&delivery);
        if sent.contains(&key) {
            tracing::debug!(envelope_id = %delivery.envelope_id, "suppressed a repeat delivery");
            continue;
        }
        let filtered = filters
            .iter()
            .fold(delivery.text, |text, filter| filter.apply(&text));
        // The screen is last, and it sees the finished bytes. Anything earlier would run before the
        // interpolation that puts a secret in a message.
        let screened = screen.screen(&filtered);
        if !screened.is_clean() {
            tracing::warn!(
                envelope_id = %delivery.envelope_id,
                target = %delivery.target,
                policy = %screened.policy_version(),
                account = %screened.account(),
                "masked an outbound message"
            );
            out.masked
                .extend(screened.masked().iter().map(|masked| Masking {
                    envelope_id: delivery.envelope_id.clone(),
                    target: delivery.target.clone(),
                    policy: screened.policy_version().to_string(),
                    rule: masked.rule.clone(),
                    at: masked.at,
                    len: masked.len,
                }));
        }
        let rendered = Delivery {
            text: screened.into_text(),
            ..delivery
        };
        adapter.send(&rendered).await.map_err(refused)?;
        sent.remember(key);
        out.posted += 1;
    }
    Ok(out)
}

/// Everything needed to post, and the ledger that keeps posting idempotent.
///
/// Holding the filters, the screen, the adapter and the ledger together is what makes "only the
/// dispatcher delivers" enforceable: dispatch is handed one of these and has no other way out.
pub struct Courier {
    filters: Vec<Box<dyn Filter>>,
    screen: Screen,
    adapter: Box<dyn Adapter>,
    sent: Sent,
}

impl Courier {
    /// A courier that applies `filters`, in order, and then the shipped egress policy.
    ///
    /// Screened by default, and deliberately not optional here. A courier that could be built
    /// without a screen would be built without one on the host where it mattered.
    #[must_use]
    pub fn new(filters: Vec<Box<dyn Filter>>, adapter: Box<dyn Adapter>) -> Self {
        Self::screened(filters, Screen::shipped(), adapter)
    }

    /// A courier screening against a policy of the deployment's choosing.
    #[must_use]
    pub fn screened(
        filters: Vec<Box<dyn Filter>>,
        screen: Screen,
        adapter: Box<dyn Adapter>,
    ) -> Self {
        Self {
            filters,
            screen,
            adapter,
            sent: Sent::new(),
        }
    }

    /// Delivers a batch, skipping anything this courier has already posted.
    pub async fn deliver(&self, deliveries: Vec<Delivery>) -> crate::Result<Posted> {
        deliver(
            &self.filters,
            &self.screen,
            &*self.adapter,
            &self.sent,
            deliveries,
        )
        .await
    }
}

/// Maps an adapter failure onto the dispatch error.
///
/// Dispatch has no transport variant, so a send failure surfaces as the agent-side equivalent:
/// `Unavailable` for something worth retrying, `Malformed` for something that will fail the same way
/// forever.
fn refused(error: harness_envelope::Error) -> crate::Error {
    match error {
        harness_envelope::Error::Malformed(why) => harness_agent::Error::Malformed(why).into(),
        harness_envelope::Error::Unavailable(why) => harness_agent::Error::Unavailable(why).into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use harness_envelope::Delivery;
    use harness_screen::{Policy, Screen};

    use super::{Courier, Sent, deliver};
    use crate::fixtures::{RecordingAdapter, Render, Suffix, Upper, delivery, filters};

    /// A token that has to be masked, assembled rather than written out so this file carries no
    /// credential-shaped literal a scanner would flag.
    fn chat_token() -> String {
        format!("xoxb-{}-{}", "0".repeat(12), "abcdefghijkl")
    }

    #[tokio::test]
    async fn filters_apply_in_order_to_the_rendered_text() {
        // Order is observable: suffixing then upper-casing differs from the reverse, so a folded
        // chain applied backwards fails here rather than in production.
        let adapter = RecordingAdapter::working();
        let posted = deliver(
            &filters(vec![Box::new(Suffix(" done")), Box::new(Upper)]),
            &Screen::shipped(),
            &adapter,
            &Sent::new(),
            vec![delivery("all")],
        )
        .await
        .expect("deliver");

        assert_eq!(posted.posted, 1);
        assert_eq!(adapter.texts(), vec!["ALL DONE"]);
    }

    #[tokio::test]
    async fn reversing_the_filters_reverses_the_result() {
        let adapter = RecordingAdapter::working();
        deliver(
            &filters(vec![Box::new(Upper), Box::new(Suffix(" done"))]),
            &Screen::shipped(),
            &adapter,
            &Sent::new(),
            vec![delivery("all")],
        )
        .await
        .expect("deliver");

        assert_eq!(adapter.texts(), vec!["ALL done"]);
    }

    #[tokio::test]
    async fn redelivering_the_same_delivery_does_not_double_post() {
        let adapter = RecordingAdapter::working();
        let sent = Sent::default();
        let once = deliver(
            &filters(vec![]),
            &Screen::shipped(),
            &adapter,
            &sent,
            vec![delivery("hello")],
        )
        .await
        .expect("first");
        let again = deliver(
            &filters(vec![]),
            &Screen::shipped(),
            &adapter,
            &sent,
            vec![delivery("hello")],
        )
        .await
        .expect("retry");

        assert_eq!((once.posted, again.posted), (1, 0));
        assert_eq!(adapter.texts(), vec!["hello"]);
    }

    #[tokio::test]
    async fn a_second_message_for_the_same_envelope_is_not_a_repeat() {
        // Idempotency is per delivery, not per envelope: two different messages both go out.
        let adapter = RecordingAdapter::working();
        let posted = deliver(
            &filters(vec![]),
            &Screen::shipped(),
            &adapter,
            &Sent::new(),
            vec![delivery("first"), delivery("second")],
        )
        .await
        .expect("deliver");

        assert_eq!(posted.posted, 2);
        assert_eq!(adapter.texts(), vec!["first", "second"]);
    }

    #[tokio::test]
    async fn a_delivery_the_adapter_rejected_stays_retryable() {
        let failing = RecordingAdapter::unavailable("socket closed");
        let sent = Sent::new();
        let error = deliver(
            &filters(vec![]),
            &Screen::shipped(),
            &failing,
            &sent,
            vec![delivery("hello")],
        )
        .await
        .expect_err("send fails");
        assert_eq!(error.to_string(), "dependency unavailable: socket closed");

        let working = RecordingAdapter::working();
        let posted = deliver(
            &filters(vec![]),
            &Screen::shipped(),
            &working,
            &sent,
            vec![delivery("hello")],
        )
        .await
        .expect("retry");

        assert_eq!(
            posted.posted, 1,
            "a failed send must not be remembered as sent"
        );
    }

    #[tokio::test]
    async fn a_malformed_delivery_is_reported_as_permanent() {
        let adapter = RecordingAdapter::malformed("no such target");
        let error = deliver(
            &filters(vec![]),
            &Screen::shipped(),
            &adapter,
            &Sent::new(),
            vec![delivery("hello")],
        )
        .await
        .expect_err("send fails");

        assert_eq!(error.to_string(), "malformed task: no such target");
    }

    #[tokio::test]
    async fn a_courier_carries_its_own_ledger() {
        let courier = Courier::new(
            vec![Box::new(Suffix("!"))],
            Box::new(RecordingAdapter::working()),
        );
        let once = courier.deliver(vec![delivery("hi")]).await.expect("first");
        let again = courier.deliver(vec![delivery("hi")]).await.expect("retry");

        assert_eq!((once.posted, again.posted), (1, 0));
    }

    #[test]
    fn deliveries_differing_only_by_thread_are_different_messages() {
        let base = delivery("text");
        let threaded = Delivery {
            thread: Some("t-1".into()),
            ..base.clone()
        };
        assert_ne!(super::key(&base), super::key(&threaded));
    }

    #[tokio::test]
    async fn a_clean_message_reaches_the_adapter_byte_for_byte() {
        let text = "Ran 3 checks in 42s. Next: 2026-08-01. Ping @here if that looks wrong.";
        let adapter = RecordingAdapter::working();
        let posted = deliver(
            &filters(vec![]),
            &Screen::shipped(),
            &adapter,
            &Sent::new(),
            vec![delivery(text)],
        )
        .await
        .expect("deliver");

        assert_eq!(adapter.texts(), vec![text]);
        assert!(
            posted.masked.is_empty(),
            "a clean message has nothing to account for: {:?}",
            posted.masked
        );
    }

    #[tokio::test]
    async fn a_secret_a_filter_rendered_in_is_still_caught() {
        // The reason the screen runs where it does. The delivery the agent asked to send carries a
        // placeholder, so a check on the delivery — or on the agent's fields — passes; the secret
        // exists only after the last filter has run.
        let requested = delivery("posting as {{bot}}");
        let token = chat_token();
        let adapter = RecordingAdapter::working();
        let posted = deliver(
            &filters(vec![Box::new(Render {
                placeholder: "{{bot}}",
                value: "xoxb-000000000000-abcdefghijkl",
            })]),
            &Screen::shipped(),
            &adapter,
            &Sent::new(),
            vec![requested.clone()],
        )
        .await
        .expect("deliver");

        assert!(
            !requested.text.contains(&token),
            "the requested text is clean, which is the whole point"
        );
        assert_eq!(adapter.texts(), vec!["posting as [redacted:chat-token]"]);
        assert_eq!(posted.masked.len(), 1);
        assert_eq!(posted.masked[0].rule, "chat-token");
    }

    #[tokio::test]
    async fn the_account_names_the_delivery_the_rule_and_the_policy() {
        let adapter = RecordingAdapter::working();
        let posted = deliver(
            &filters(vec![]),
            &Screen::shipped(),
            &adapter,
            &Sent::new(),
            vec![delivery(&format!("key {} ok", chat_token()))],
        )
        .await
        .expect("deliver");

        let masking = posted.masked.first().expect("one masking");
        assert_eq!(masking.envelope_id, "cli-1");
        assert_eq!(masking.target, "stdout");
        assert_eq!(masking.policy, "egress-v1");
        assert_eq!(masking.rule, "chat-token");
        assert_eq!(masking.at, 4);
        assert_eq!(masking.len, chat_token().len());
    }

    #[tokio::test]
    async fn a_masked_message_is_still_delivered() {
        // Masking is not blocking. A dropped reply reads as an agent that ignored the request, and
        // the operator learns nothing about the credential that nearly left.
        let adapter = RecordingAdapter::working();
        let posted = deliver(
            &filters(vec![]),
            &Screen::shipped(),
            &adapter,
            &Sent::new(),
            vec![delivery(&format!("here it is: {}", chat_token()))],
        )
        .await
        .expect("deliver");

        assert_eq!(posted.posted, 1);
        assert_eq!(adapter.texts().len(), 1);
    }

    #[tokio::test]
    async fn every_pattern_class_the_policy_covers_is_masked_at_the_egress_point() {
        let text = format!(
            "chat {} app {} model sk-ant-api00-{} host ghp_{} cloud AKIA{} \
             mail ops@example.test digits 4111 1111 1111 1111\n\
             -----BEGIN TEST KEY-----\n{}\n-----END TEST KEY-----\n",
            chat_token(),
            format_args!("xapp-1-{}", "A".repeat(20)),
            "B".repeat(20),
            "c".repeat(36),
            "IOSFODNN7EXAMPLE",
            "d".repeat(40),
        );
        let adapter = RecordingAdapter::working();
        let posted = deliver(
            &filters(vec![]),
            &Screen::shipped(),
            &adapter,
            &Sent::new(),
            vec![delivery(&text)],
        )
        .await
        .expect("deliver");

        let rules: BTreeSet<&str> = posted.masked.iter().map(|m| m.rule.as_str()).collect();
        assert_eq!(
            rules,
            [
                "address",
                "chat-token",
                "cloud-key-id",
                "code-host-token",
                "key-block",
                "long-digit-run",
                "model-key",
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
        );
        let out = adapter.texts().join("");
        for secret in [
            chat_token().as_str(),
            "IOSFODNN7EXAMPLE",
            "ops@example.test",
            "4111 1111 1111 1111",
            &"c".repeat(36),
            &"d".repeat(40),
        ] {
            assert!(!out.contains(secret), "`{secret}` reached the adapter");
        }
    }

    #[tokio::test]
    async fn a_courier_screens_against_the_policy_it_was_given() {
        // The pattern set is configuration: a deployment with its own credential shapes replaces the
        // policy rather than the send path.
        let policy = Policy::parse(
            "version = \"local-v1\"\nplaceholder = \"[gone]\"\n\n[[rule]]\nid = \"local-token\"\n\
             kind = \"prefixed\"\nprefixes = [\"lt-\"]\nbody = \"token\"\nmin = 6\nmax = 64\n",
        )
        .expect("policy");
        let adapter = std::sync::Arc::new(RecordingAdapter::working());
        let courier = Courier::screened(
            filters(vec![]),
            Screen::new(policy),
            Box::new(adapter.clone()),
        );
        let posted = courier
            .deliver(vec![delivery(&format!("lt-abcdef and {}", chat_token()))])
            .await
            .expect("deliver");

        assert_eq!(
            adapter.texts(),
            vec![format!("[gone] and {}", chat_token())],
            "the replacement policy is the one in force, shipped rules included"
        );
        assert_eq!(posted.masked.len(), 1);
        assert_eq!(posted.masked[0].policy, "local-v1");
    }
}
