//! Delivery, and the filter that depends on it.

use harness_envelope::Delivery;

/// A rule applied to outbound text.
pub trait Filter: Send + Sync {
    /// Rewrites text before it leaves the process.
    ///
    /// Applied to the *rendered* message, immediately before delivery. Filtering earlier leaves a
    /// gap: anything a later template step introduces would go out unexamined.
    fn apply(&self, _text: &str) -> String;
}

/// Applies every filter in order, then hands the result to the adapter.
pub async fn deliver(
    _filters: &[Box<dyn Filter>],
    _deliveries: Vec<Delivery>,
) -> crate::Result<usize> {
    todo!("filter then hand to the adapter, idempotent per delivery")
}
