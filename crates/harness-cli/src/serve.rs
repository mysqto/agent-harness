//! Serving the ingress socket.
//!
//! The contract is the one in `adapters/README.md`: an adapter writes `Envelope` lines to the
//! socket and reads `Delivery` lines back on the same connection. Nothing here knows what a source
//! is, and nothing here composes a message — the dispatcher's courier does that, which is what
//! keeps the egress filter a property of the system.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use harness_dispatch::Dispatcher;
use harness_dispatch::egress::Adapter;
use harness_envelope::{Delivery, Envelope};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::{Error, Result};

/// Binds the ingress socket, replacing one a crashed process left behind.
///
/// A socket file that nobody answers is litter, and refusing to start over it would mean a manual
/// cleanup after every crash. A socket somebody *does* answer is a genuine conflict — two
/// dispatchers on one path would each get an arbitrary half of the traffic — so that one refuses.
pub async fn bind(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| Error::Failed(format!("cannot create {}: {err}", parent.display())))?;
    }
    if std::fs::symlink_metadata(path).is_ok() {
        if UnixStream::connect(path).await.is_ok() {
            return Err(Error::Failed(format!(
                "{} is already served by another process",
                path.display()
            )));
        }
        std::fs::remove_file(path)
            .map_err(|err| Error::Failed(format!("cannot replace {}: {err}", path.display())))?;
        tracing::warn!(socket = %path.display(), "replaced a socket nobody was answering");
    }
    UnixListener::bind(path)
        .map_err(|err| Error::Failed(format!("cannot bind {}: {err}", path.display())))
}

/// Accepts connections until `shutdown` completes, then finishes in-flight work and unlinks.
///
/// Shutdown is ordered: stop accepting, tell open connections to take no more work, let what is
/// already running finish, and only then remove the socket. Two parts of that order are load
/// bearing. Removing the socket first would leave an adapter connecting to a path that no longer
/// exists while its previous message was still being handled. And telling connections to stop is
/// what bounds shutdown at all — an idle adapter holds its end open indefinitely, so waiting for
/// the last client to hang up is waiting forever.
pub async fn serve<S>(
    listener: UnixListener,
    dispatcher: Arc<Dispatcher>,
    replies: Replies,
    path: &Path,
    shutdown: S,
) -> Result<()>
where
    S: Future<Output = ()> + Send,
{
    let mut connections = JoinSet::new();
    let (closing, closed) = watch::channel(false);
    let outcome = accept_until(
        &listener,
        &dispatcher,
        &replies,
        &mut connections,
        &closed,
        shutdown,
    )
    .await;

    drop(listener);
    let _ = closing.send(true);
    while connections.join_next().await.is_some() {}
    if let Err(err) = std::fs::remove_file(path) {
        // Worth saying, not worth failing over: the next start replaces a stale socket anyway.
        tracing::warn!(socket = %path.display(), %err, "could not remove the socket");
    }
    outcome
}

/// Accepts and spawns until told to stop.
async fn accept_until<S>(
    listener: &UnixListener,
    dispatcher: &Arc<Dispatcher>,
    replies: &Replies,
    connections: &mut JoinSet<()>,
    closed: &watch::Receiver<bool>,
    shutdown: S,
) -> Result<()>
where
    S: Future<Output = ()> + Send,
{
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => {
                tracing::info!("shutting down; finishing in-flight work");
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    connections.spawn(connection(
                        stream,
                        dispatcher.clone(),
                        replies.clone(),
                        closed.clone(),
                    ));
                }
                // Accept failures are about the process, not the connection — an exhausted fd table
                // does not recover by being retried in a tight loop.
                Err(err) => return Err(Error::Failed(format!("cannot accept: {err}"))),
            }
        }
        // Reap what has finished, so the set does not grow for the life of the process.
        while connections.try_join_next().is_some() {}
    }
}

/// Handles one connection: envelope lines in, delivery lines out.
///
/// Envelopes on one connection are handled in order rather than concurrently, because the replies
/// go back down the same pipe and an adapter reading them pairwise would otherwise have to match
/// them up itself. Different connections still run at the same time.
///
/// `closed` stops it taking new work. It is checked between messages and never during one, so a
/// shutdown abandons whatever had not been read yet and finishes what had.
async fn connection(
    stream: UnixStream,
    dispatcher: Arc<Dispatcher>,
    replies: Replies,
    mut closed: watch::Receiver<bool>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    loop {
        let read = tokio::select! {
            biased;
            // Checked first, so a shutdown wins over a line that arrived at the same moment.
            _ = closed.changed() => break,
            read = lines.next_line() => read,
        };
        let line = match read {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(err) => {
                tracing::warn!(%err, "ingress read failed");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let envelope = match serde_json::from_str::<Envelope>(&line) {
            Ok(envelope) => envelope,
            // One unreadable line does not close the connection: an adapter sending a batch should
            // still get answers for the lines it got right.
            Err(err) => {
                tracing::warn!(%err, "discarding an unparseable ingress line");
                continue;
            }
        };

        let envelope_id = envelope.envelope_id.clone();
        let mut deliveries = replies.attach(&envelope_id);
        let handled = dispatcher.dispatch(envelope).await;
        replies.detach(&envelope_id);
        if let Err(err) = &handled {
            tracing::warn!(envelope_id = %envelope_id, %err, "dispatch failed");
        }

        // Taken from the courier's channel rather than from what dispatch returned: an adapter must
        // see the text every filter has been applied to, and only the courier has applied them.
        while let Ok(delivery) = deliveries.try_recv() {
            if let Err(err) = write_line(&mut writer, &delivery).await {
                tracing::warn!(envelope_id = %envelope_id, %err, "could not write a delivery");
                return;
            }
        }
    }
}

/// Writes one delivery as a line, flushed.
async fn write_line<W>(writer: &mut W, delivery: &Delivery) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_string(delivery).map_err(std::io::Error::other)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await
}

/// Completes on `SIGINT` or `SIGTERM`.
pub async fn signals() {
    match (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) {
        (Ok(mut interrupt), Ok(mut terminate)) => {
            tokio::select! {
                _ = interrupt.recv() => tracing::info!("interrupted"),
                _ = terminate.recv() => tracing::info!("terminated"),
            }
        }
        // With no handler installed the default disposition applies and the process dies on the
        // signal regardless, so there is nothing useful to wait for or to do instead.
        (Err(err), _) | (_, Err(err)) => {
            tracing::error!(%err, "cannot listen for signals");
            std::future::pending::<()>().await;
        }
    }
}

/// Routes deliveries back to the connection their envelope arrived on.
///
/// The dispatcher holds one courier for the life of the process while connections come and go, so
/// its adapter has to be a routing table. Keyed by `envelope_id` because that is the only thing a
/// [`Delivery`] and its connection share. Cloning shares the table.
#[derive(Clone, Default)]
pub struct Replies {
    routes: Arc<Mutex<HashMap<String, UnboundedSender<Delivery>>>>,
}

impl Replies {
    /// An empty routing table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Routes deliveries for `envelope_id` to the returned receiver, until detached.
    fn attach(&self, envelope_id: &str) -> UnboundedReceiver<Delivery> {
        let (sender, receiver) = mpsc::unbounded_channel();
        guard(&self.routes).insert(envelope_id.to_string(), sender);
        receiver
    }

    /// Stops routing for `envelope_id`.
    fn detach(&self, envelope_id: &str) {
        guard(&self.routes).remove(envelope_id);
    }
}

#[async_trait::async_trait]
impl Adapter for Replies {
    async fn send(&self, delivery: &Delivery) -> std::result::Result<(), harness_envelope::Error> {
        // Cloned out of the table rather than sent under the lock: a delivery must never be able to
        // hold the routing table while another connection is trying to attach.
        let route = guard(&self.routes).get(&delivery.envelope_id).cloned();
        match route {
            Some(sender) => sender.send(delivery.clone()).map_err(|_| {
                harness_envelope::Error::Unavailable(format!(
                    "connection for {} closed",
                    delivery.envelope_id
                ))
            }),
            // Retryable on purpose: the message was never delivered, so the courier must not
            // remember it as sent.
            None => Err(harness_envelope::Error::Unavailable(format!(
                "no connection for {}",
                delivery.envelope_id
            ))),
        }
    }
}

/// Takes a lock, keeping what is behind it if a previous holder panicked.
fn guard<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use harness_dispatch::Dispatcher;
    use harness_dispatch::egress::{Adapter, Courier};
    use harness_envelope::{Delivery, Envelope};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::oneshot;

    use super::{Replies, bind, serve};
    use crate::once::DryRun;
    use crate::registry;

    /// A dispatcher serving the built-in agent against a store that reaches nothing.
    fn dispatcher(replies: &Replies) -> Arc<Dispatcher> {
        Arc::new(Dispatcher::new(
            registry(&["echo".to_string()]).expect("registry"),
            Arc::new(DryRun::new(false)),
            Courier::new(Vec::new(), Box::new(replies.clone())),
        ))
    }

    /// A served socket, and the handle that stops it.
    struct Served {
        path: PathBuf,
        stop: Option<oneshot::Sender<()>>,
        serving: Option<tokio::task::JoinHandle<crate::Result<()>>>,
    }

    impl Served {
        async fn start(path: PathBuf) -> Self {
            let replies = Replies::new();
            let listener = bind(&path).await.expect("bind");
            let (stop, stopped) = oneshot::channel();
            let dispatcher = dispatcher(&replies);
            let serving = {
                let path = path.clone();
                tokio::spawn(async move {
                    serve(listener, dispatcher, replies, &path, async {
                        let _ = stopped.await;
                    })
                    .await
                })
            };
            Self {
                path,
                stop: Some(stop),
                serving: Some(serving),
            }
        }

        /// Sends `lines` on one connection and reads `expected` delivery lines back.
        async fn exchange(&self, lines: &[String], expected: usize) -> Vec<Delivery> {
            let stream = UnixStream::connect(&self.path).await.expect("connect");
            let (reader, mut writer) = stream.into_split();
            for line in lines {
                writer.write_all(line.as_bytes()).await.expect("write");
                writer.write_all(b"\n").await.expect("newline");
            }
            let mut replies = BufReader::new(reader).lines();
            let mut received = Vec::new();
            while received.len() < expected {
                let line = tokio::time::timeout(Duration::from_secs(5), replies.next_line())
                    .await
                    .expect("a delivery within the timeout")
                    .expect("read")
                    .expect("a delivery line");
                received.push(serde_json::from_str(&line).expect("delivery"));
            }
            received
        }

        async fn shutdown(mut self) -> crate::Result<()> {
            drop(self.stop.take());
            self.serving.take().expect("serving").await.expect("join")
        }
    }

    fn envelope_line(id: &str, body: &str) -> String {
        serde_json::to_string(&Envelope {
            envelope_id: id.into(),
            source: "cli".into(),
            received_at: "2026-08-19T14:30:12Z".into(),
            attempt: 1,
            reply_to: Some("stdout".into()),
            actor: Some("local".into()),
            body: body.into(),
            extra: std::collections::BTreeMap::new(),
        })
        .expect("serialise")
    }

    #[tokio::test]
    async fn an_envelope_line_in_is_a_delivery_line_out() {
        let dir = tempfile::tempdir().expect("temp dir");
        let served = Served::start(dir.path().join("ingress.sock")).await;

        let deliveries = served
            .exchange(&[envelope_line("cli-1", "echo hello")], 1)
            .await;

        assert_eq!(deliveries[0].envelope_id, "cli-1");
        assert_eq!(deliveries[0].target, "stdout");
        assert_eq!(deliveries[0].text, "hello");
        served.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn several_envelopes_on_one_connection_are_each_answered() {
        let dir = tempfile::tempdir().expect("temp dir");
        let served = Served::start(dir.path().join("ingress.sock")).await;

        let deliveries = served
            .exchange(
                &[
                    envelope_line("cli-1", "echo first"),
                    envelope_line("cli-2", "echo second"),
                ],
                2,
            )
            .await;

        assert_eq!(deliveries[0].text, "first");
        assert_eq!(deliveries[1].text, "second");
        served.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn a_bad_line_does_not_cost_the_connection_its_next_message() {
        let dir = tempfile::tempdir().expect("temp dir");
        let served = Served::start(dir.path().join("ingress.sock")).await;

        let deliveries = served
            .exchange(
                &[
                    String::new(),
                    "{not an envelope".to_string(),
                    r#"{"envelope_id":"x"}"#.to_string(),
                    envelope_line("cli-9", "nosuchintent please"),
                    envelope_line("cli-1", "echo still here"),
                ],
                1,
            )
            .await;

        assert_eq!(
            deliveries[0].text, "still here",
            "an unroutable envelope and two malformed lines must not end the connection"
        );
        served.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn shutdown_finishes_the_work_and_removes_the_socket() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ingress.sock");
        let served = Served::start(path.clone()).await;
        served
            .exchange(&[envelope_line("cli-1", "echo hello")], 1)
            .await;

        served.shutdown().await.expect("clean shutdown");
        assert!(
            !path.exists(),
            "a clean shutdown must not leave a socket behind"
        );
    }

    #[tokio::test]
    async fn shutdown_does_not_wait_for_an_idle_adapter_to_hang_up() {
        let dir = tempfile::tempdir().expect("temp dir");
        let served = Served::start(dir.path().join("ingress.sock")).await;
        // Held open across the shutdown, which is exactly what an idle adapter does. If shutdown
        // waited for the last client to close, this would never return.
        let held = UnixStream::connect(&served.path).await.expect("connect");

        tokio::time::timeout(Duration::from_secs(5), served.shutdown())
            .await
            .expect("shutdown must not wait for a client to hang up")
            .expect("clean shutdown");
        drop(held);
    }

    #[tokio::test]
    async fn a_socket_already_gone_is_not_a_shutdown_failure() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ingress.sock");
        let served = Served::start(path.clone()).await;
        std::fs::remove_file(&path).expect("remove");

        served
            .shutdown()
            .await
            .expect("a missing socket is nothing to fail over");
    }

    #[tokio::test]
    async fn a_socket_left_by_a_crash_is_replaced() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ingress.sock");
        // Exactly what a crash leaves: a bound path with nobody listening on it.
        drop(UnixListener::bind(&path).expect("first bind"));
        assert!(path.exists());

        let listener = bind(&path).await.expect("stale socket must not be fatal");
        assert!(UnixStream::connect(&path).await.is_ok());
        drop(listener);
    }

    #[tokio::test]
    async fn a_socket_someone_is_answering_is_not_replaced() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ingress.sock");
        let live = bind(&path).await.expect("bind");

        let error = bind(&path).await.expect_err("a live socket is a conflict");
        assert!(error.to_string().contains("already served"));
        drop(live);
    }

    #[tokio::test]
    async fn a_missing_runtime_directory_is_created() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("state/harness/ingress.sock");
        drop(bind(&path).await.expect("bind"));
        assert!(path.exists());
    }

    #[tokio::test]
    async fn an_unusable_socket_path_is_reported() {
        let dir = tempfile::tempdir().expect("temp dir");
        // A parent that is a file, not a directory.
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").expect("write");
        assert!(bind(&file.join("ingress.sock")).await.is_err());

        // A name too long for a unix socket address, so binding itself fails.
        let long = dir.path().join("l".repeat(200));
        assert!(bind(&long).await.is_err());

        // A directory where the socket should be: it exists, answers nothing, and cannot be
        // unlinked as a file.
        let occupied = dir.path().join("occupied");
        std::fs::create_dir(&occupied).expect("mkdir");
        assert!(bind(&occupied).await.is_err());
    }

    #[tokio::test]
    async fn a_delivery_for_an_unknown_envelope_is_retryable() {
        // The courier must not remember an undelivered message as sent, so this reports
        // unavailable rather than succeeding quietly.
        let replies = Replies::new();
        let delivery = Delivery {
            envelope_id: "cli-1".into(),
            target: "stdout".into(),
            text: "hello".into(),
            thread: None,
        };
        let error = replies.send(&delivery).await.expect_err("no route");
        assert!(matches!(
            error,
            harness_envelope::Error::Unavailable(ref why) if why.contains("no connection")
        ));

        // And the same once the connection has gone away.
        let receiver = replies.attach("cli-1");
        drop(receiver);
        let error = replies.send(&delivery).await.expect_err("closed route");
        assert!(matches!(
            error,
            harness_envelope::Error::Unavailable(ref why) if why.contains("closed")
        ));
    }

    #[tokio::test]
    async fn the_shell_adapters_own_output_is_accepted() {
        // Generated by running adapters/cli/adapter.sh, not transcribed from it: this is the test
        // that keeps the shell adapter and the binary from drifting apart.
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/cli/adapter.sh");
        let output = std::process::Command::new("sh")
            .arg(&script)
            .env("HARNESS_SOCKET", "/nonexistent/harness/ingress.sock")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .take()
                    .expect("stdin")
                    .write_all(b"echo hello\necho order ord-91h2\n")?;
                child.wait_with_output()
            })
            .expect("run the shell adapter");
        assert!(output.status.success(), "the adapter must exit cleanly");

        let emitted: Vec<String> = String::from_utf8(output.stdout)
            .expect("utf-8")
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(emitted.len(), 2, "one envelope per input line");

        let dir = tempfile::tempdir().expect("temp dir");
        let served = Served::start(dir.path().join("ingress.sock")).await;
        let deliveries = served.exchange(&emitted, 2).await;

        assert_eq!(deliveries[0].text, "hello");
        assert_eq!(deliveries[1].text, "order ord-91h2");
        assert!(
            deliveries[0].envelope_id.starts_with("cli-"),
            "the adapter's own id must survive the round trip: {:?}",
            deliveries[0].envelope_id
        );
        served.shutdown().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn a_signal_ends_the_wait() {
        // Registered here first so SIGTERM can never reach the default disposition and kill the
        // test process, whatever the ordering below turns out to be.
        let _installed = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("register");
        let waiting = tokio::spawn(super::signals());
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(
            std::process::Command::new("kill")
                .args(["-TERM", &std::process::id().to_string()])
                .status()
                .expect("kill")
                .success()
        );
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the signal must end the wait")
            .expect("join");
    }
}
