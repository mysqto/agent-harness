//! Memory access, over the wire.
//!
//! This deliberately speaks HTTP rather than linking the memory implementation. The orchestrator
//! should be able to run against any store that honours the contract — including one written in
//! another language — and a code dependency would quietly make that untrue.
//!
//! Two shapes of failure are kept apart everywhere below, because confusing them is expensive:
//! a rejected request is permanent and the caller must fix it, while an unavailable store is
//! transient and the caller should retry or degrade. And a [`Bundle`] that could not be composed in
//! full comes back marked, never quietly short — a partial answer is safe for a question and unsafe
//! for an action, and the caller can only tell if we say so.
//!
//! # The contract
//!
//! Since the point is that any store can implement this, the wire side is stated rather than left
//! to be read out of the code:
//!
//! - `GET /bundle?entity=<kind>:<id>` → `{"records": [...], "degraded": bool, "omitted": [...]}`.
//!   One request per entity; missing fields default. Served over the sidecar's *read* socket when
//!   one is configured, otherwise over `base_url`. The store refuses a parameter it does not
//!   declare, so the spelling here is a requirement rather than a preference.
//! - The sidecar serves reads on a second socket, `<agent>.read.sock` beside the record socket, and
//!   it is `GET` only: it signs the request as its caller and forwards it, so this process needs no
//!   key material to read either. A read is never queued — unreachable comes back `503` — because
//!   a caller cannot tell stale data from fresh, and a write laundered through it is refused `405`.
//! - `POST /records` with a complete record as the body → any `2xx`. The direct path only. A
//!   record is not a draft: an agent describes what it did, and this client adds the identity, the
//!   timing and the attribution the store requires. [`record`] holds the shape and the reason for
//!   every value it fills in. `correlation_id` ties the record to the interaction that caused it,
//!   is a field of the record rather than one of its attributes — so it cannot collide with an
//!   attribute of the same name — and is left off the wire when the caller has none to name.
//! - The sidecar takes the same record body as one JSON line on its unix socket and answers with
//!   one line, `{"status": "...", "detail": "..."}`, where status is `accepted`, `spooled`,
//!   `rejected`, `spool_full` or `error`.
//!
//! `4xx` means the request was wrong and `429`, `5xx` or a timeout means the store was busy; that
//! split is the whole basis for deciding whether to retry.

#![forbid(unsafe_code)]

mod http;
mod record;
mod sidecar;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use harness_agent::{ActionDraft, MemoryHandle};
use hyper::Method;
use serde::Deserialize;

/// Where the memory service lives, and who we are to it.
#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL of the service.
    pub base_url: String,
    /// Path to the local sidecar's *record* socket, when one is present.
    ///
    /// Preferred over a direct connection: the sidecar holds the signing key, seals records and
    /// signs reads on our behalf, so this process needs no key material of its own.
    ///
    /// One path, both sockets. The read socket is derived from this one by [`read_socket`], by the
    /// same rule the sidecar derives it, so a deployment has nothing second to get wrong.
    pub sidecar_socket: Option<PathBuf>,
    /// Identity records are attributed to.
    pub agent: String,
}

/// A client for the memory service.
///
/// Every call carries its own deadline. Nothing here holds one of its own, because a ceiling only
/// this module can see is one the caller cannot reason about when a request is slow.
#[derive(Debug)]
pub struct Client {
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
    ///
    /// Entities are fetched one at a time against a single shared deadline: whatever arrives in
    /// time is kept, and everything else is named in [`Bundle::omitted`] with the reason.
    /// [`Error::Rejected`] is the one failure that still propagates, because degrading on it would
    /// hide a malformed request behind a flag that reads as slowness.
    pub async fn bundle(&self, entities: &[(String, String)], deadline_ms: u64) -> Result<Bundle> {
        self.bundle_capped(entities, deadline_ms, None).await
    }

    /// As [`Client::bundle`], returning at most `limit` records.
    ///
    /// The cap goes to the store rather than being applied to the answer. Trimming here would leave
    /// the store reading and serialising its own cap to hand back five, which is what this replaced.
    pub async fn bundle_capped(
        &self,
        entities: &[(String, String)],
        deadline_ms: u64,
        limit: Option<u32>,
    ) -> Result<Bundle> {
        let target = self.target()?;
        let deadline = Instant::now() + Duration::from_millis(deadline_ms);
        let mut bundle = Bundle::default();

        for (position, (kind, id)) in entities.iter().enumerate() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                // Name every entity we never reached, so the caller sees the shape of the gap
                // rather than only that there is one.
                for (kind, id) in &entities[position..] {
                    bundle.omit(kind, id, "deadline exceeded");
                }
                break;
            }
            match fetch(&target, kind, id, left, limit).await {
                Ok(part) => bundle.absorb(part),
                Err(rejected @ Error::Rejected(_)) => return Err(rejected),
                Err(err) => bundle.omit(kind, id, &err.to_string()),
            }
        }
        Ok(bundle)
    }

    /// Stamps a draft into a complete record and submits it.
    ///
    /// A draft is deliberately not a record: it carries what the agent did and nothing about who
    /// did it or when, so this is where the identifier, the timestamps, the attribution and the
    /// store's classification defaults are added. [`record`] states each one and why it is safe.
    ///
    /// `correlation_id` is what later ties this record to the interaction that caused it; an empty
    /// string means there is none to name and leaves the field off the wire. It is a field of the
    /// record rather than one of its attributes, so an attribute an agent genuinely calls
    /// `correlation_id` keeps its own meaning.
    ///
    /// The record is stamped once, before either transport is chosen, and that is what keeps the
    /// store's idempotency working: the identifier *is* the idempotency key, so every redelivery a
    /// transport performs replays bytes that already carry it and lands as one record. What this
    /// cannot cover is a caller that calls `submit` again — that is a second submission, and
    /// whoever retries at that level owns deciding whether the first one landed.
    ///
    /// Goes through the sidecar whenever one is configured, and only then falls back to `base_url`.
    /// The sidecar takes a record as a framed line rather than as HTTP, because it owns the spool
    /// and its ack distinguishes more outcomes than a status code does.
    pub async fn submit(
        &self,
        draft: &ActionDraft,
        correlation_id: &str,
        deadline_ms: u64,
    ) -> Result<()> {
        let stamped = record::Record::stamp(&self.config.agent, draft, correlation_id);
        let payload = serde_json::to_vec(&stamped)
            .map_err(|err| Error::Transport(format!("encode record: {err}")))?;
        let budget = Duration::from_millis(deadline_ms);

        if let Some(socket) = &self.config.sidecar_socket {
            return sidecar::submit(socket, &payload, budget).await;
        }
        let target = http::Target::Tcp(http::Endpoint::parse(&self.config.base_url)?);
        http::request(&target, Method::POST, "/records", Some(payload), budget)
            .await?
            .ok_body()
            .map(|_| ())
    }

    /// Picks the transport for a read. The sidecar wins whenever it is configured, since going
    /// direct would mean this process needed key material of its own.
    ///
    /// The read socket, not the record socket. The two speak different protocols on purpose — the
    /// record socket frames one JSON line and the read socket speaks HTTP/1.1 — so a read sent at
    /// the record socket would sit there waiting for a newline that HTTP never sends.
    fn target(&self) -> Result<http::Target> {
        match &self.config.sidecar_socket {
            Some(socket) => Ok(http::Target::Unix(read_socket(socket))),
            None => http::Endpoint::parse(&self.config.base_url).map(http::Target::Tcp),
        }
    }
}

/// Extension a sidecar's record socket carries.
const SOCKET_EXT: &str = "sock";

/// What a sidecar names a caller's read socket, in place of [`SOCKET_EXT`].
const READ_SUFFIX: &str = ".read.sock";

/// The read socket beside a record socket: the same stem, with `.read.sock` for its extension.
///
/// Derived rather than configured, and derived by the sidecar's own rule so the two cannot drift.
/// A second setting would be a second thing to point at the wrong socket — and pointing reads at
/// one identity while records go to another is exactly the failure a caller could not see.
///
/// A path that does not end in `.sock` is appended to rather than rewritten: appending is the one
/// rule that cannot collide with the record socket's own path.
///
/// ```
/// use std::path::Path;
///
/// assert_eq!(
///     harness_memory::read_socket(Path::new("/run/sockets/agent.sock")),
///     Path::new("/run/sockets/agent.read.sock")
/// );
/// ```
#[must_use]
pub fn read_socket(record_socket: &Path) -> PathBuf {
    let stem = if record_socket
        .extension()
        .is_some_and(|ext| ext == SOCKET_EXT)
    {
        record_socket.file_stem()
    } else {
        record_socket.file_name()
    };
    let mut name = stem.unwrap_or_default().to_os_string();
    name.push(READ_SUFFIX);
    record_socket.with_file_name(name)
}

/// Fetches one entity's slice of context.
async fn fetch(
    target: &http::Target,
    kind: &str,
    id: &str,
    budget: Duration,
    limit: Option<u32>,
) -> Result<WireBundle> {
    // `kind:id` in one parameter, which is the store's grammar rather than a choice: it declares
    // `entity`, `actor`, `deadline_ms` and `limit`, and refuses anything else, so `kind` and `id` as
    // separate parameters are a `400`. Each half is encoded and the separator is not, so an id
    // carrying a `:` cannot move where the split falls.
    let mut route = format!("/bundle?entity={}:{}", encode(kind), encode(id));
    if let Some(limit) = limit {
        use std::fmt::Write as _;
        let _ = write!(route, "&limit={limit}");
    }
    let body = http::request(target, Method::GET, &route, None, budget)
        .await?
        .ok_body()?;
    serde_json::from_slice(&body).map_err(|err| Error::Transport(format!("decode bundle: {err}")))
}

/// Percent-encodes a query value, so an id containing `&` cannot invent a parameter.
fn encode(raw: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX[usize::from(byte >> 4)]));
                out.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
    out
}

/// One store response. Mirrors [`Bundle`], but is the wire shape and tolerates missing fields.
#[derive(Debug, Default, Deserialize)]
struct WireBundle {
    /// Records the store judged relevant.
    #[serde(default)]
    records: Vec<serde_json::Value>,
    /// Set when the store itself could not see everything.
    #[serde(default)]
    degraded: bool,
    /// What the store left out.
    #[serde(default)]
    omitted: Vec<String>,
}

/// Context returned by the store.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Bundle {
    /// Records judged relevant, newest first, exactly as the store put them on the wire.
    ///
    /// Opaque on purpose, and worth knowing what a store actually sends: the reference
    /// implementation answers with each record's *structure* -- its frontmatter fields -- and never
    /// its prose. An agent reading history gets what a record is about without the body, so a cap
    /// on how many records come back is worth setting rather than trimming afterwards.
    pub records: Vec<serde_json::Value>,
    /// `true` when a source was unavailable, so the caller knows this is partial.
    pub degraded: bool,
    /// What was left out, and why.
    pub omitted: Vec<String>,
}

impl Bundle {
    /// Folds in one store response, keeping its own degraded verdict.
    fn absorb(&mut self, part: WireBundle) {
        self.records.extend(part.records);
        self.degraded |= part.degraded;
        self.omitted.extend(part.omitted);
    }

    /// Records an entity that could not be included. Anything omitted makes the bundle degraded.
    fn omit(&mut self, kind: &str, id: &str, reason: &str) {
        self.omitted.push(format!("{kind}/{id}: {reason}"));
        self.degraded = true;
    }
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
pub struct Handle {
    client: Client,
    correlation_id: String,
    write_deadline_ms: u64,
}

impl Handle {
    /// Binds a client to one interaction.
    ///
    /// `write_deadline_ms` bounds a record submitted through [`MemoryHandle::record`], which is the
    /// one call that carries no deadline of its own: an agent queues a record and does not wait on
    /// it, so the budget has to be set by whoever wired the handle up.
    #[must_use]
    pub fn new(client: Client, correlation_id: impl Into<String>, write_deadline_ms: u64) -> Self {
        Self {
            client,
            correlation_id: correlation_id.into(),
            write_deadline_ms,
        }
    }
}

/// Translates a store failure into what an agent is allowed to see.
///
/// Permanent failures arrive as `Malformed` so the caller fixes the request; everything else
/// arrives as `Unavailable`, which is the agent-facing word for "worth retrying". A transport
/// failure is transient by nature, so it must not reach an agent as anything else.
fn to_agent(err: Error) -> harness_agent::Error {
    match err {
        Error::Rejected(detail) => harness_agent::Error::Malformed(detail),
        Error::Unavailable(detail) | Error::Transport(detail) => {
            harness_agent::Error::Unavailable(detail)
        }
    }
}

/// Flattens one record into a plain map.
///
/// A record that is not an object is kept under a single key rather than dropped: an odd shape is
/// visible to the agent, whereas a silently missing record is not.
fn project(value: serde_json::Value) -> BTreeMap<String, serde_json::Value> {
    match value {
        serde_json::Value::Object(fields) => fields.into_iter().collect(),
        other => [("value".to_owned(), other)].into(),
    }
}

#[async_trait::async_trait]
impl MemoryHandle for Handle {
    /// Projects a one-entity bundle into plain maps.
    ///
    /// A degraded bundle is still returned: the records in it are real, and whether partial context
    /// is safe to act on is the dispatcher's call via `Context::is_degraded`, not this projection's.
    /// `limit` is applied here because the bundle contract carries no limit of its own.
    async fn history(
        &self,
        kind: &str,
        id: &str,
        limit: u32,
        deadline_ms: u64,
    ) -> harness_agent::Result<Vec<BTreeMap<String, serde_json::Value>>> {
        let entities = [(kind.to_owned(), id.to_owned())];
        // The cap is the store's to apply. Asking for the default and keeping the first few made the
        // store serialise up to its own cap of structures so this could discard the difference.
        let bundle = self
            .client
            .bundle_capped(&entities, deadline_ms, Some(limit))
            .await
            .map_err(to_agent)?;
        Ok(bundle.records.into_iter().map(project).collect())
    }

    async fn record(&self, draft: ActionDraft) -> harness_agent::Result<()> {
        // The interaction id goes in the record's own field, so the draft the agent wrote reaches
        // the store exactly as the agent wrote it.
        self.client
            .submit(&draft, &self.correlation_id, self.write_deadline_ms)
            .await
            .map_err(to_agent)
    }
}
