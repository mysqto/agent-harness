//! Tests against real sockets.
//!
//! The stubs below are servers on a real TCP port or unix socket rather than an injected seam: the
//! transport, the status mapping and the sidecar framing are exactly the parts that are worth
//! testing, and a seam would stub out the code under test.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use harness_agent::{ActionDraft, MemoryHandle, Status};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};

use crate::{Bundle, Client, Config, Error, Handle};

/// Requests a stub has seen, head and body together.
type Seen = Arc<Mutex<Vec<String>>>;

/// A canned HTTP reply.
struct Reply {
    /// Status to return.
    status: u16,
    /// Body to return.
    body: String,
    /// How long to stall first, for exercising a deadline.
    delay: Duration,
}

impl Reply {
    /// A `200` carrying a JSON body.
    fn ok(body: &Value) -> Self {
        Self {
            status: 200,
            body: body.to_string(),
            delay: Duration::ZERO,
        }
    }

    /// A bare status, with no body worth reading.
    fn status(status: u16) -> Self {
        Self {
            status,
            body: String::new(),
            delay: Duration::ZERO,
        }
    }

    /// A reply that arrives far too late.
    fn stalled() -> Self {
        Self {
            status: 200,
            body: String::new(),
            delay: Duration::from_secs(30),
        }
    }
}

/// A bundle body with one record for `id`.
fn one_record(id: &str) -> Value {
    json!({"records": [{"action": "summarise", "entity": id}], "degraded": false, "omitted": []})
}

/// A neutral draft to submit.
fn draft() -> ActionDraft {
    ActionDraft {
        action: "summarise".into(),
        outcome: Status::Succeeded,
        attrs: [("count".to_owned(), json!(2))].into_iter().collect(),
        entities: vec![("order_ref".to_owned(), "ord-91h2".to_owned())],
        summary: "summarised two".into(),
    }
}

/// A config with neither transport reachable unless one is supplied.
fn config(base_url: &str, socket: Option<PathBuf>) -> Config {
    Config {
        base_url: base_url.to_owned(),
        sidecar_socket: socket,
        agent: "summariser".into(),
    }
}

/// A `base_url` whose port has nothing behind it: a bound listener is dropped to get one that is
/// free, which is the closest a test can get to a store that is simply not there.
async fn dead_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    format!("http://{addr}")
}

/// Reads one HTTP request, stopping at the end of its body so the next one is not swallowed.
async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read(&mut byte).await.unwrap_or(0) == 1 {
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let length = text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    if length > 0 {
        stream.read_exact(&mut body).await.expect("read body");
    }
    format!("{text}{}", String::from_utf8_lossy(&body))
}

/// Serves one canned reply on an accepted connection.
async fn serve_http<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, reply: Reply, seen: &Seen) {
    let request = read_request(&mut stream).await;
    seen.lock().expect("lock").push(request);
    tokio::time::sleep(reply.delay).await;
    let head = format!(
        "HTTP/1.1 {} OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        reply.status,
        reply.body.len()
    );
    // The client may have given up and closed already; that is the case under test, not a failure.
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(reply.body.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// An HTTP stub on a loopback port. Returns its `base_url` and the requests it sees.
async fn tcp_stub(replies: Vec<Reply>) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base_url = format!("http://{}", listener.local_addr().expect("addr"));
    let seen: Seen = Arc::default();
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        for reply in replies {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            serve_http(stream, reply, &recorded).await;
        }
    });
    (base_url, seen)
}

/// A socket in a directory that lives as long as the returned guard.
fn socket_path() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("memory.sock");
    (dir, path)
}

/// The same HTTP stub, but on a unix socket — where a sidecar would be.
fn unix_http_stub(replies: Vec<Reply>) -> (tempfile::TempDir, PathBuf, Seen) {
    let (dir, path) = socket_path();
    let listener = UnixListener::bind(&path).expect("bind");
    let seen: Seen = Arc::default();
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        for reply in replies {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            serve_http(stream, reply, &recorded).await;
        }
    });
    (dir, path, seen)
}

/// How a sidecar stub answers one record line.
enum Ack {
    /// Write this line back.
    Line(&'static str),
    /// Close without answering at all.
    Hangup,
    /// Hold the connection open and never answer.
    Silence,
}

/// A sidecar record stub: reads one line per connection, then answers as scripted.
fn unix_line_stub(acks: Vec<Ack>) -> (tempfile::TempDir, PathBuf, Seen) {
    let (dir, path) = socket_path();
    let listener = UnixListener::bind(&path).expect("bind");
    let seen: Seen = Arc::default();
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        for ack in acks {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).await.unwrap_or(0) == 1 {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
            }
            recorded
                .lock()
                .expect("lock")
                .push(String::from_utf8_lossy(&line).to_string());
            match ack {
                Ack::Line(line) => {
                    let _ = stream.write_all(format!("{line}\n").as_bytes()).await;
                }
                Ack::Hangup => {}
                Ack::Silence => tokio::time::sleep(Duration::from_secs(30)).await,
            }
            let _ = stream.shutdown().await;
        }
    });
    (dir, path, seen)
}

/// The single request a stub saw.
fn only(seen: &Seen) -> String {
    let seen = seen.lock().expect("lock");
    assert_eq!(seen.len(), 1, "expected exactly one request: {seen:?}");
    seen[0].clone()
}

#[tokio::test]
async fn a_bundle_gathers_every_entity() {
    let (base_url, seen) = tcp_stub(vec![
        Reply::ok(&one_record("ord-91h2")),
        Reply::ok(&one_record("t-7")),
    ])
    .await;
    let client = Client::new(config(&base_url, None));
    let entities = vec![
        ("order_ref".to_owned(), "ord-91h2".to_owned()),
        ("ticket".to_owned(), "t-7".to_owned()),
    ];

    let bundle = client.bundle(&entities, 2_000).await.expect("bundle");

    assert_eq!(bundle.records.len(), 2);
    assert!(!bundle.degraded);
    assert!(bundle.omitted.is_empty());
    let seen = seen.lock().expect("lock");
    assert!(
        seen[0].starts_with("GET /bundle?kind=order_ref&id=ord-91h2 "),
        "{seen:?}"
    );
    assert!(
        seen[1].starts_with("GET /bundle?kind=ticket&id=t-7 "),
        "{seen:?}"
    );
}

#[tokio::test]
async fn a_bundle_keeps_the_stores_own_degraded_verdict() {
    let body = json!({"records": [], "degraded": true, "omitted": ["cold storage: unreachable"]});
    let (base_url, _seen) = tcp_stub(vec![Reply::ok(&body)]).await;
    let client = Client::new(config(&base_url, None));

    let bundle = client
        .bundle(&[("ticket".to_owned(), "t-7".to_owned())], 2_000)
        .await
        .expect("bundle");

    // Whole-value: a verdict that arrived with an extra record, or with the reason dropped, is a
    // different answer from the one the store gave.
    assert_eq!(
        bundle,
        Bundle {
            records: Vec::new(),
            degraded: true,
            omitted: vec!["cold storage: unreachable".to_owned()],
        }
    );
}

#[tokio::test]
async fn a_bundle_past_its_deadline_degrades_instead_of_failing() {
    let (base_url, _seen) = tcp_stub(vec![Reply::stalled()]).await;
    let client = Client::new(config(&base_url, None));
    let entities = vec![
        ("order_ref".to_owned(), "ord-91h2".to_owned()),
        ("ticket".to_owned(), "t-7".to_owned()),
    ];

    let bundle = client
        .bundle(&entities, 40)
        .await
        .expect("degraded, not failed");

    assert!(bundle.degraded, "a short bundle must say so");
    assert!(bundle.records.is_empty());
    assert_eq!(bundle.omitted.len(), 2, "{:?}", bundle.omitted);
    assert!(
        bundle.omitted[0].contains("timed out"),
        "{:?}",
        bundle.omitted
    );
    assert!(
        bundle.omitted[1].contains("deadline exceeded"),
        "{:?}",
        bundle.omitted
    );
}

#[tokio::test]
async fn a_bundle_omits_an_entity_the_store_could_not_serve() {
    let (base_url, _seen) =
        tcp_stub(vec![Reply::ok(&one_record("ord-91h2")), Reply::status(503)]).await;
    let client = Client::new(config(&base_url, None));
    let entities = vec![
        ("order_ref".to_owned(), "ord-91h2".to_owned()),
        ("ticket".to_owned(), "t-7".to_owned()),
    ];

    let bundle = client.bundle(&entities, 2_000).await.expect("bundle");

    assert_eq!(bundle.records.len(), 1);
    assert!(bundle.degraded);
    assert_eq!(bundle.omitted.len(), 1);
    assert!(
        bundle.omitted[0].starts_with("ticket/t-7: unavailable"),
        "{:?}",
        bundle.omitted
    );
}

#[tokio::test]
async fn a_rejected_bundle_request_fails_rather_than_degrades() {
    // Degrading here would hide a request the caller has to fix behind a flag that reads as
    // slowness.
    let (base_url, _seen) = tcp_stub(vec![Reply::status(400)]).await;
    let client = Client::new(config(&base_url, None));

    let err = client
        .bundle(&[("ticket".to_owned(), "t-7".to_owned())], 2_000)
        .await
        .expect_err("rejected");

    assert!(matches!(err, Error::Rejected(_)), "{err:?}");
}

#[tokio::test]
async fn an_unparseable_bundle_body_is_omitted_not_returned_empty() {
    let (base_url, _seen) = tcp_stub(vec![Reply {
        status: 200,
        body: "<html>".to_owned(),
        delay: Duration::ZERO,
    }])
    .await;
    let client = Client::new(config(&base_url, None));

    let bundle = client
        .bundle(&[("ticket".to_owned(), "t-7".to_owned())], 2_000)
        .await
        .expect("bundle");

    assert!(bundle.degraded);
    assert_eq!(bundle.omitted.len(), 1);
}

#[tokio::test]
async fn an_entity_id_cannot_smuggle_a_query_parameter() {
    let (base_url, seen) = tcp_stub(vec![Reply::ok(&one_record("x"))]).await;
    let client = Client::new(config(&base_url, None));

    client
        .bundle(
            &[("order_ref".to_owned(), "a b&kind=other".to_owned())],
            2_000,
        )
        .await
        .expect("bundle");

    assert!(only(&seen).starts_with("GET /bundle?kind=order_ref&id=a%20b%26kind%3Dother "));
}

#[tokio::test]
async fn a_bundle_prefers_the_sidecar_socket_when_one_is_configured() {
    let (_dir, socket, seen) = unix_http_stub(vec![Reply::ok(&one_record("t-7"))]);
    // Nothing is listening on base_url, so a bundle can only succeed via the socket.
    let client = Client::new(config(&dead_url().await, Some(socket)));

    let bundle = client
        .bundle(&[("ticket".to_owned(), "t-7".to_owned())], 2_000)
        .await
        .expect("bundle");

    assert_eq!(bundle.records.len(), 1);
    assert!(only(&seen).starts_with("GET /bundle?kind=ticket&id=t-7 "));
}

#[tokio::test]
async fn a_bundle_falls_back_to_base_url_with_no_socket() {
    let (base_url, seen) = tcp_stub(vec![Reply::ok(&one_record("t-7"))]).await;
    let client = Client::new(config(&base_url, None));

    client
        .bundle(&[("ticket".to_owned(), "t-7".to_owned())], 2_000)
        .await
        .expect("bundle");

    assert!(only(&seen).to_lowercase().contains("host: 127.0.0.1"));
}

#[tokio::test]
async fn a_misconfigured_base_url_is_rejected() {
    let client = Client::new(config("https://memory.invalid", None));

    let err = client.bundle(&[], 2_000).await.expect_err("rejected");

    assert!(matches!(err, Error::Rejected(_)), "{err:?}");
}

#[tokio::test]
async fn submitting_with_no_socket_posts_to_base_url() {
    let (base_url, seen) = tcp_stub(vec![Reply::status(202)]).await;
    let client = Client::new(config(&base_url, None));

    client
        .submit(&draft(), "corr-1", 2_000)
        .await
        .expect("submitted");

    let request = only(&seen);
    assert!(request.starts_with("POST /records "), "{request}");
    assert!(request.contains("\"agent\":\"summariser\""), "{request}");
    assert!(
        request.contains("\"correlation_id\":\"corr-1\""),
        "{request}"
    );
    assert!(request.contains("\"action\":\"summarise\""), "{request}");
}

#[tokio::test]
async fn a_prefix_in_base_url_is_kept() {
    let (base_url, seen) = tcp_stub(vec![Reply::status(202)]).await;
    let client = Client::new(config(&format!("{base_url}/v1"), None));

    client
        .submit(&draft(), "corr-1", 2_000)
        .await
        .expect("submitted");

    assert!(only(&seen).starts_with("POST /v1/records "));
}

#[tokio::test]
async fn a_client_error_is_permanent_and_a_server_error_is_not() {
    for (status, permanent) in [
        (400, true),
        (404, true),
        (429, false),
        (500, false),
        (503, false),
    ] {
        let (base_url, _seen) = tcp_stub(vec![Reply::status(status)]).await;
        let client = Client::new(config(&base_url, None));

        let err = client
            .submit(&draft(), "corr-1", 2_000)
            .await
            .expect_err("failed");

        if permanent {
            assert!(matches!(err, Error::Rejected(_)), "{status}: {err:?}");
        } else {
            assert!(matches!(err, Error::Unavailable(_)), "{status}: {err:?}");
        }
    }
}

#[tokio::test]
async fn a_stalled_store_is_unavailable_rather_than_rejected() {
    let (base_url, _seen) = tcp_stub(vec![Reply::stalled()]).await;
    let client = Client::new(config(&base_url, None));

    let err = client
        .submit(&draft(), "corr-1", 40)
        .await
        .expect_err("timed out");

    assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
}

#[tokio::test]
async fn submitting_prefers_the_sidecar_over_base_url() {
    let (_dir, socket, seen) = unix_line_stub(vec![Ack::Line("{\"status\":\"accepted\"}")]);
    // Nothing is listening on base_url, so a success proves the socket was used.
    let client = Client::new(config(&dead_url().await, Some(socket)));

    client
        .submit(&draft(), "corr-1", 2_000)
        .await
        .expect("submitted");

    let line: Value = serde_json::from_str(&only(&seen)).expect("one json line");
    assert_eq!(line["agent"], json!("summariser"));
    assert_eq!(line["record"]["action"], json!("summarise"));
}

#[tokio::test]
async fn every_ack_status_maps_to_its_outcome() {
    for (ack, expected) in [
        ("{\"status\":\"accepted\"}", Ok(())),
        // Spooled is durable, so it is a success: reporting failure would double-write the record.
        ("{\"status\":\"spooled\"}", Ok(())),
        (
            "{\"status\":\"rejected\",\"detail\":\"bad entity\"}",
            Err("rejected"),
        ),
        ("{\"status\":\"spool_full\"}", Err("unavailable")),
        (
            "{\"status\":\"error\",\"detail\":\"disk\"}",
            Err("unavailable"),
        ),
    ] {
        let (_dir, socket, _seen) = unix_line_stub(vec![Ack::Line(ack)]);
        let client = Client::new(config("http://memory.invalid", Some(socket)));

        let outcome = client.submit(&draft(), "corr-1", 2_000).await;

        match (expected, outcome) {
            (Ok(()), got) => got.unwrap_or_else(|err| panic!("{ack} should succeed: {err:?}")),
            (Err("rejected"), Err(Error::Rejected(_))) | (Err(_), Err(Error::Unavailable(_))) => {}
            (_, got) => panic!("{ack} mapped wrongly: {got:?}"),
        }
    }
}

#[tokio::test]
async fn an_unusable_ack_is_reported_rather_than_panicking() {
    for ack in [Ack::Line("not json"), Ack::Hangup] {
        let (_dir, socket, _seen) = unix_line_stub(vec![ack]);
        let client = Client::new(config("http://memory.invalid", Some(socket)));

        let err = client
            .submit(&draft(), "corr-1", 2_000)
            .await
            .expect_err("no usable ack");

        assert!(matches!(err, Error::Transport(_)), "{err:?}");
    }
}

#[tokio::test]
async fn a_missing_sidecar_is_a_transport_failure() {
    let (_dir, socket) = socket_path();
    let client = Client::new(config("http://memory.invalid", Some(socket)));

    let err = client
        .submit(&draft(), "corr-1", 2_000)
        .await
        .expect_err("no sidecar");

    assert!(matches!(err, Error::Transport(_)), "{err:?}");
}

#[tokio::test]
async fn a_silent_sidecar_is_unavailable() {
    let (_dir, socket, _seen) = unix_line_stub(vec![Ack::Silence]);
    let client = Client::new(config("http://memory.invalid", Some(socket)));

    let err = client
        .submit(&draft(), "corr-1", 40)
        .await
        .expect_err("no ack");

    assert!(matches!(err, Error::Unavailable(_)), "{err:?}");
}

#[tokio::test]
async fn history_projects_records_and_applies_the_limit() {
    let body = json!({
        "records": [
            {"action": "summarise", "at": 3},
            {"action": "summarise", "at": 2},
            {"action": "summarise", "at": 1},
        ],
    });
    let (base_url, seen) = tcp_stub(vec![Reply::ok(&body)]).await;
    let handle = Handle::new(Client::new(config(&base_url, None)), "corr-1", 2_000);

    let history = handle
        .history("ticket", "t-7", 2, 2_000)
        .await
        .expect("history");

    assert_eq!(
        history.len(),
        2,
        "the limit is applied here, not on the wire"
    );
    assert_eq!(history[0]["at"], json!(3));
    assert!(only(&seen).starts_with("GET /bundle?kind=ticket&id=t-7 "));
}

#[tokio::test]
async fn history_keeps_a_record_that_is_not_an_object() {
    let (base_url, _seen) = tcp_stub(vec![Reply::ok(&json!({"records": ["bare"]}))]).await;
    let handle = Handle::new(Client::new(config(&base_url, None)), "corr-1", 2_000);

    let history = handle
        .history("ticket", "t-7", 10, 2_000)
        .await
        .expect("history");

    assert_eq!(
        history[0]["value"],
        json!("bare"),
        "a record must not vanish"
    );
}

#[tokio::test]
async fn history_still_returns_the_records_a_degraded_bundle_did_hold() {
    let body = json!({"records": [{"action": "summarise"}], "degraded": true});
    let (base_url, _seen) = tcp_stub(vec![Reply::ok(&body)]).await;
    let handle = Handle::new(Client::new(config(&base_url, None)), "corr-1", 2_000);

    let history = handle
        .history("ticket", "t-7", 10, 2_000)
        .await
        .expect("history");

    assert_eq!(history.len(), 1);
}

#[tokio::test]
async fn history_reports_a_rejection_as_malformed() {
    let (base_url, _seen) = tcp_stub(vec![Reply::status(422)]).await;
    let handle = Handle::new(Client::new(config(&base_url, None)), "corr-1", 2_000);

    let err = handle
        .history("ticket", "t-7", 10, 2_000)
        .await
        .expect_err("rejected");

    assert!(matches!(err, harness_agent::Error::Malformed(_)), "{err:?}");
}

#[tokio::test]
async fn recording_surfaces_a_transport_failure_as_retryable() {
    let handle = Handle::new(
        Client::new(config(&dead_url().await, None)),
        "corr-1",
        2_000,
    );

    let err = handle.record(draft()).await.expect_err("nothing listening");

    // An agent must see something it can retry, not an opaque failure it has to guess about.
    assert!(
        matches!(err, harness_agent::Error::Unavailable(_)),
        "{err:?}"
    );
}

#[tokio::test]
async fn recording_reports_a_rejection_as_malformed() {
    let (_dir, socket, _seen) = unix_line_stub(vec![Ack::Line("{\"status\":\"rejected\"}")]);
    let handle = Handle::new(
        Client::new(config("http://memory.invalid", Some(socket))),
        "corr-1",
        2_000,
    );

    let err = handle.record(draft()).await.expect_err("rejected");

    assert!(matches!(err, harness_agent::Error::Malformed(_)), "{err:?}");
}

#[tokio::test]
async fn recording_names_the_interaction_beside_the_record() {
    let (_dir, socket, seen) = unix_line_stub(vec![Ack::Line("{\"status\":\"spooled\"}")]);
    let handle = Handle::new(
        Client::new(config("http://memory.invalid", Some(socket))),
        "corr-1",
        2_000,
    );

    handle.record(draft()).await.expect("spooled is a success");

    let line: Value = serde_json::from_str(&only(&seen)).expect("json");
    assert_eq!(line["correlation_id"], json!("corr-1"));
    assert_eq!(
        line["record"]["attrs"].get("correlation_id"),
        None,
        "the link must not occupy an attribute key"
    );
}

#[tokio::test]
async fn an_attribute_genuinely_called_correlation_id_is_left_alone() {
    // Two different things that happened to share a name. Stamping the interaction into `attrs`
    // made one of them unrepresentable; now both arrive.
    let (_dir, socket, seen) = unix_line_stub(vec![Ack::Line("{\"status\":\"accepted\"}")]);
    let handle = Handle::new(
        Client::new(config("http://memory.invalid", Some(socket))),
        "corr-1",
        2_000,
    );
    let mut draft = draft();
    draft
        .attrs
        .insert("correlation_id".to_owned(), json!("corr-agent"));

    handle.record(draft).await.expect("submitted");

    let line: Value = serde_json::from_str(&only(&seen)).expect("json");
    assert_eq!(
        line["record"]["attrs"]["correlation_id"],
        json!("corr-agent")
    );
    assert_eq!(line["correlation_id"], json!("corr-1"));
}

#[tokio::test]
async fn a_submission_with_no_interaction_leaves_the_field_off_the_wire() {
    // An empty id is "nothing to link", not a link to nothing; a store must be able to tell.
    let (_dir, socket, seen) = unix_line_stub(vec![Ack::Line("{\"status\":\"accepted\"}")]);
    let client = Client::new(config("http://memory.invalid", Some(socket)));

    client.submit(&draft(), "", 2_000).await.expect("submitted");

    let line: Value = serde_json::from_str(&only(&seen)).expect("json");
    assert_eq!(line.get("correlation_id"), None);
    assert_eq!(line["agent"], json!("summariser"));
}
