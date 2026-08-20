//! Delivery, and the filter that depends on it.
//!
//! Everything outbound goes through here, which is the only reason a filter can be relied on: an
//! agent that could post for itself could skip one.

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use harness_envelope::Delivery;

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
/// In memory, like [`crate::Seen`], and with the same limit: it stops a repeat within the life of
/// the process and claims nothing beyond it.
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

/// Applies every filter in order, then hands the result to the adapter.
///
/// Returns how many were actually posted, which is fewer than were offered when the ledger
/// recognised one. A delivery is remembered only once the adapter has accepted it, so a failed send
/// stays retryable.
pub async fn deliver(
    filters: &[Box<dyn Filter>],
    adapter: &dyn Adapter,
    sent: &Sent,
    deliveries: Vec<Delivery>,
) -> crate::Result<usize> {
    let mut posted = 0;
    for delivery in deliveries {
        let key = key(&delivery);
        if sent.contains(&key) {
            tracing::debug!(envelope_id = %delivery.envelope_id, "suppressed a repeat delivery");
            continue;
        }
        let rendered = Delivery {
            text: filters
                .iter()
                .fold(delivery.text, |text, filter| filter.apply(&text)),
            ..delivery
        };
        adapter.send(&rendered).await.map_err(refused)?;
        sent.remember(key);
        posted += 1;
    }
    Ok(posted)
}

/// Everything needed to post, and the ledger that keeps posting idempotent.
///
/// Holding the filters, the adapter and the ledger together is what makes "only the dispatcher
/// delivers" enforceable: dispatch is handed one of these and has no other way out.
pub struct Courier {
    filters: Vec<Box<dyn Filter>>,
    adapter: Box<dyn Adapter>,
    sent: Sent,
}

impl Courier {
    /// A courier that applies `filters`, in order, before handing anything to `adapter`.
    #[must_use]
    pub fn new(filters: Vec<Box<dyn Filter>>, adapter: Box<dyn Adapter>) -> Self {
        Self {
            filters,
            adapter,
            sent: Sent::new(),
        }
    }

    /// Delivers a batch, skipping anything this courier has already posted.
    pub async fn deliver(&self, deliveries: Vec<Delivery>) -> crate::Result<usize> {
        deliver(&self.filters, &*self.adapter, &self.sent, deliveries).await
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
    use harness_envelope::Delivery;

    use super::{Courier, Sent, deliver};
    use crate::fixtures::{RecordingAdapter, Suffix, Upper, delivery, filters};

    #[tokio::test]
    async fn filters_apply_in_order_to_the_rendered_text() {
        // Order is observable: suffixing then upper-casing differs from the reverse, so a folded
        // chain applied backwards fails here rather than in production.
        let adapter = RecordingAdapter::working();
        let posted = deliver(
            &filters(vec![Box::new(Suffix(" done")), Box::new(Upper)]),
            &adapter,
            &Sent::new(),
            vec![delivery("all")],
        )
        .await
        .expect("deliver");

        assert_eq!(posted, 1);
        assert_eq!(adapter.texts(), vec!["ALL DONE"]);
    }

    #[tokio::test]
    async fn reversing_the_filters_reverses_the_result() {
        let adapter = RecordingAdapter::working();
        deliver(
            &filters(vec![Box::new(Upper), Box::new(Suffix(" done"))]),
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
        let once = deliver(&filters(vec![]), &adapter, &sent, vec![delivery("hello")])
            .await
            .expect("first");
        let again = deliver(&filters(vec![]), &adapter, &sent, vec![delivery("hello")])
            .await
            .expect("retry");

        assert_eq!((once, again), (1, 0));
        assert_eq!(adapter.texts(), vec!["hello"]);
    }

    #[tokio::test]
    async fn a_second_message_for_the_same_envelope_is_not_a_repeat() {
        // Idempotency is per delivery, not per envelope: two different messages both go out.
        let adapter = RecordingAdapter::working();
        let posted = deliver(
            &filters(vec![]),
            &adapter,
            &Sent::new(),
            vec![delivery("first"), delivery("second")],
        )
        .await
        .expect("deliver");

        assert_eq!(posted, 2);
        assert_eq!(adapter.texts(), vec!["first", "second"]);
    }

    #[tokio::test]
    async fn a_delivery_the_adapter_rejected_stays_retryable() {
        let failing = RecordingAdapter::unavailable("socket closed");
        let sent = Sent::new();
        let error = deliver(&filters(vec![]), &failing, &sent, vec![delivery("hello")])
            .await
            .expect_err("send fails");
        assert_eq!(error.to_string(), "dependency unavailable: socket closed");

        let working = RecordingAdapter::working();
        let posted = deliver(&filters(vec![]), &working, &sent, vec![delivery("hello")])
            .await
            .expect("retry");

        assert_eq!(posted, 1, "a failed send must not be remembered as sent");
    }

    #[tokio::test]
    async fn a_malformed_delivery_is_reported_as_permanent() {
        let adapter = RecordingAdapter::malformed("no such target");
        let error = deliver(
            &filters(vec![]),
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

        assert_eq!((once, again), (1, 0));
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
}
