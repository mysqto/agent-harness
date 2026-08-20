//! Memory access, over the wire.
//!
//! This deliberately speaks HTTP rather than linking the memory implementation. The orchestrator
//! should be able to run against any store that honours the contract — including one written in
//! another language — and a code dependency would quietly make that untrue.

#![forbid(unsafe_code)]

use harness_agent::{ActionDraft, MemoryHandle};

/// Where the memory service lives, and who we are to it.
#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL of the service.
    pub base_url: String,
    /// Path to the local sidecar socket, when one is present.
    ///
    /// Preferred over a direct connection: the sidecar holds the signing key and seals on our
    /// behalf, so this process needs no key material of its own.
    pub sidecar_socket: Option<std::path::PathBuf>,
    /// Identity records are attributed to.
    pub agent: String,
}

/// A handle bound to one task.
#[derive(Debug)]
pub struct Client {
    #[expect(dead_code, reason = "read once the implementation lands")]
    config: Config,
}

impl Client {
    /// Builds a client.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Composes context for a request, degrading rather than failing when the store is slow.
    ///
    /// A partial answer marked degraded is safe for a question and unsafe for an action, so the
    /// caller is told which it got rather than being handed an empty result to interpret.
    pub async fn bundle(
        &self,
        _entities: &[(String, String)],
        _deadline_ms: u64,
    ) -> Result<Bundle> {
        todo!("GET /bundle via sidecar or direct")
    }

    /// Submits a record.
    pub async fn submit(&self, _draft: &ActionDraft) -> Result<()> {
        todo!("POST /records via sidecar")
    }
}

/// Context returned by the store.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Bundle {
    /// Records judged relevant, newest first.
    pub records: Vec<serde_json::Value>,
    /// `true` when a source was unavailable, so the caller knows this is partial.
    pub degraded: bool,
    /// What was left out, and why.
    pub omitted: Vec<String>,
}

/// Result alias for memory operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Failures talking to the store.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The store rejected the request permanently.
    #[error("rejected: {0}")]
    Rejected(String),
    /// The store is briefly unavailable. Retry, or degrade.
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// Transport failure.
    #[error("transport: {0}")]
    Transport(String),
}

/// Adapts a [`Client`] to the trait agents see.
#[derive(Debug)]
#[expect(dead_code, reason = "read once the implementation lands")]
pub struct Handle {
    client: Client,
    correlation_id: String,
}

#[async_trait::async_trait]
impl MemoryHandle for Handle {
    async fn history(
        &self,
        _kind: &str,
        _id: &str,
        _limit: u32,
    ) -> harness_agent::Result<Vec<std::collections::BTreeMap<String, serde_json::Value>>> {
        todo!("bundle, then project to plain maps")
    }

    async fn record(&self, _draft: ActionDraft) -> harness_agent::Result<()> {
        todo!("submit, mapping transport failure to Unavailable")
    }
}
