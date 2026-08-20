//! Turning an envelope into a handled task.

use harness_envelope::Envelope;

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

/// Handles one envelope end to end.
///
/// Order matters: dedupe first so a redelivery costs nothing, then classify, then load context,
/// then decide whether a mutating task may proceed on what was loaded, and only then invoke the
/// agent. Checking safety after invoking would mean the side effect had already happened.
pub async fn dispatch(
    _registry: &crate::Registry,
    _memory: &harness_memory::Client,
    _envelope: Envelope,
) -> crate::Result<Dispatched> {
    todo!("dedupe, classify, bundle, guard, invoke, deliver, record")
}
