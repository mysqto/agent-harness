//! What crosses the boundary between a source and the orchestrator.
//!
//! This is the seam that makes adapters portable. An adapter's whole job is to turn whatever its
//! source speaks into an [`Envelope`], and to deliver a [`Delivery`] back. Nothing above this line
//! knows what a source is; nothing below it knows what an agent is.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// An inbound message, normalised.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Unique per inbound message, and the key that makes redelivery harmless.
    ///
    /// Sources retry. An adapter that mints a fresh id per attempt turns one message into several
    /// tasks, so this must be derived from the source's own identifier for the message.
    pub envelope_id: String,
    /// Which adapter produced this.
    pub source: String,
    /// Stamped by the adapter on receipt, RFC 3339.
    ///
    /// Adapters may run on different hosts with different clocks, so this is the adapter's view and
    /// not a global ordering. Anything that needs ordering uses the orchestrator's own stamp.
    pub received_at: String,
    /// Attempt number, when the source reports one. Greater than 1 means dedupe has to work.
    pub attempt: u32,
    /// Where a reply should go, opaque above the adapter.
    pub reply_to: Option<String>,
    /// Who sent it, when the source knows.
    pub actor: Option<String>,
    /// The message itself.
    pub body: String,
    /// Anything source-specific the adapter wants to preserve.
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// An outbound message handed back to an adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    /// Correlates with the envelope that caused it.
    pub envelope_id: String,
    /// Destination, meaningful only to the delivering adapter.
    pub target: String,
    /// Text to send.
    pub text: String,
    /// Conversation to attach to, where the source has them.
    pub thread: Option<String>,
}

/// Failures an adapter can report.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The payload did not parse.
    #[error("malformed envelope: {0}")]
    Malformed(String),
    /// The source is unreachable. Retry.
    #[error("source unavailable: {0}")]
    Unavailable(String),
}
