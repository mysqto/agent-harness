//! The harness binary, as a library.
//!
//! Two modes, and the second exists because of how development actually goes: [`serve_ingress`]
//! serves a dispatcher on a socket, and [`once::once`] feeds a single envelope through one and
//! prints what happened, so an agent can be exercised with no socket, no adapter and no memory
//! service standing.
//!
//! Everything lives here rather than in `main.rs` for one reason: a binary-only crate cannot be
//! unit tested, and the interesting parts of a command-line tool — config parsing, exit codes, what
//! a dry run reports — are exactly the parts worth testing.

#![forbid(unsafe_code)]

pub mod cli;
pub mod config;
pub mod echo;
pub mod error;
pub mod exit;
pub mod once;
pub mod serve;

#[cfg(test)]
mod fixtures;

use std::ffi::OsString;
use std::future::Future;
use std::io::Read;
use std::sync::Arc;

use clap::Parser;
use harness_agent::Agent;
use harness_dispatch::egress::Courier;
use harness_dispatch::{Dispatcher, Registry};

pub use cli::{Cli, Command};
pub use config::Config;
pub use echo::Echo;
pub use error::{Error, Result};

/// Agents this binary can serve without being recompiled.
///
/// One entry, deliberately. A deployment with real agents links them in and builds its own
/// [`Registry`]; `echo` is here because a reference implementation that ships is the only kind that
/// stays working.
pub const BUILT_IN_AGENTS: &[&str] = &[Echo::ID];

/// Parses arguments, runs the command, and returns the process exit code.
///
/// Reads standard input for the `once` subcommand, and only for it.
#[must_use]
pub fn main<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    main_with(args, &mut std::io::stdin())
}

/// [`main`], with standard input supplied.
///
/// The seam exists so the `once` path can be tested: a test cannot hand a process a stdin.
#[must_use]
pub fn main_with<I, T>(args: I, input: &mut dyn Read) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        // `--help` and `--version` arrive here too, and neither is a failure.
        Err(report) => {
            let _ = report.print();
            return if report.use_stderr() {
                exit::USAGE
            } else {
                exit::OK
            };
        }
    };

    match run_command(cli.command, input) {
        Ok(()) => exit::OK,
        Err(error) => {
            eprintln!("harness: {error}");
            error.code()
        }
    }
}

/// Runs one subcommand to completion on a fresh runtime.
fn run_command(command: Command, input: &mut dyn Read) -> Result<()> {
    match command {
        Command::Run {
            config,
            socket,
            agents,
        } => block_on(async move {
            let config = Config::load(&config.unwrap_or_else(Config::default_path))?;
            let socket = socket.unwrap_or_else(|| config.ingress_socket.clone());
            serve_ingress(&config, &socket, &agents, serve::signals()).await
        }),
        Command::Once { agents, degraded } => {
            let mut text = String::new();
            input
                .read_to_string(&mut text)
                .map_err(|err| Error::Usage(format!("cannot read stdin: {err}")))?;
            let envelope = once::read_envelope(&text)?;
            block_on(async move {
                let report = once::once(registry(&agents)?, envelope, degraded).await?;
                println!("{}", report.render());
                Ok(())
            })
        }
    }
}

/// Runs a future on a single-threaded runtime.
///
/// One thread is enough: the work is socket and HTTP waiting rather than computation, and a
/// current-thread runtime keeps the process cheap enough to be worth starting for one envelope.
fn block_on<F: Future<Output = Result<()>>>(work: F) -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| Error::Failed(format!("cannot start a runtime: {err}")))?
        .block_on(work)
}

/// Serves a dispatcher on `socket` until `shutdown` completes.
///
/// `shutdown` is a parameter rather than a signal handler reached for inside, because a shutdown
/// path that only a signal can trigger is a shutdown path that does not get tested.
pub async fn serve_ingress<S>(
    config: &Config,
    socket: &std::path::Path,
    agents: &[String],
    shutdown: S,
) -> Result<()>
where
    S: Future<Output = ()> + Send,
{
    let registry = registry(agents)?;
    let store = Arc::new(harness_memory::Client::new(config.memory_client()));
    // Replies go back on the connection the envelope arrived on, so the courier's adapter is a
    // routing table rather than one fixed destination.
    let replies = serve::Replies::new();
    let dispatcher = Arc::new(Dispatcher::new(
        registry,
        store,
        // Built before the listener: a policy this deployment named and cannot read is a reason
        // not to start, not a reason to serve unscreened.
        Courier::screened(Vec::new(), config.screen()?, Box::new(replies.clone())),
    ));
    let listener = serve::bind(socket).await?;
    tracing::info!(
        socket = %socket.display(),
        agents = ?dispatcher.registry().ids(),
        "serving ingress"
    );
    serve::serve(listener, dispatcher, replies, socket, shutdown).await
}

/// Builds a registry from agent names.
///
/// Unknown names are a usage error rather than a warning: silently serving fewer agents than were
/// asked for looks like a routing bug much later, from a different terminal.
pub fn registry(names: &[String]) -> Result<Registry> {
    let mut registry = Registry::new();
    for name in names {
        let agent: Arc<dyn Agent> = match name.as_str() {
            Echo::ID => Arc::new(Echo::new()),
            other => {
                return Err(Error::Usage(format!(
                    "unknown agent `{other}`; built in: {}",
                    BUILT_IN_AGENTS.join(", ")
                )));
            }
        };
        registry
            .register(agent)
            .map_err(|err| Error::Usage(format!("cannot register `{name}`: {err}")))?;
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::time::Duration;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use tokio::sync::oneshot;

    use super::{BUILT_IN_AGENTS, Config, Error, exit, main, main_with, registry, serve_ingress};

    #[test]
    fn help_is_a_success() {
        assert_eq!(main(["harness", "--help"]), exit::OK);
        assert_eq!(main(["harness", "--version"]), exit::OK);
    }

    #[test]
    fn an_unknown_flag_is_a_usage_error() {
        assert_eq!(main(["harness", "--nope"]), exit::USAGE);
        assert_eq!(main(["harness"]), exit::USAGE);
    }

    #[test]
    fn a_missing_config_is_a_config_error() {
        assert_eq!(
            main([
                "harness",
                "run",
                "--config",
                "/nonexistent/harness/config.toml"
            ]),
            exit::CONFIG
        );
    }

    #[test]
    fn once_reads_its_envelope_from_the_supplied_input() {
        let mut input = Cursor::new(b"echo hello".to_vec());
        assert_eq!(main_with(["harness", "once"], &mut input), exit::OK);
    }

    #[test]
    fn once_on_an_unreadable_stdin_is_a_usage_error() {
        // Invalid UTF-8 cannot be a message body, and the failure belongs to the caller.
        let mut input = Cursor::new(vec![0xff, 0xfe]);
        assert_eq!(main_with(["harness", "once"], &mut input), exit::USAGE);
    }

    #[test]
    fn once_on_an_unroutable_intent_exits_five() {
        let mut input = Cursor::new(b"nosuchintent please".to_vec());
        assert_eq!(main_with(["harness", "once"], &mut input), exit::UNROUTABLE);
    }

    #[test]
    fn only_the_built_in_agent_registers() {
        assert_eq!(BUILT_IN_AGENTS, ["echo"]);
        assert_eq!(
            registry(&["echo".to_string()])
                .expect("register")
                .ids()
                .len(),
            1
        );
        assert!(registry(&[]).expect("empty").ids().is_empty());
    }

    #[test]
    fn an_unknown_agent_name_is_a_usage_error() {
        let error =
            registry(&["nosuch".to_string()]).expect_err("an unknown agent must not register");
        assert!(matches!(error, Error::Usage(ref why) if why.contains("nosuch")));
        assert_eq!(error.code(), exit::USAGE);
    }

    #[test]
    fn run_reports_a_socket_it_cannot_bind() {
        // Reaches `run` end to end without a server to shut down: the config is fine and the
        // socket is impossible, so the command returns instead of serving.
        let dir = tempfile::tempdir().expect("temp dir");
        let config = dir.path().join("config.toml");
        std::fs::write(&config, installed(&dir.path().join("ingress.sock"))).expect("write");
        let blocked = dir.path().join("file");
        std::fs::write(&blocked, b"x").expect("write");

        assert_eq!(
            main([
                "harness".as_ref(),
                "run".as_ref(),
                "--config".as_ref(),
                config.as_os_str(),
                "--socket".as_ref(),
                blocked.join("ingress.sock").as_os_str(),
            ]),
            exit::FAILED
        );
    }

    /// A config as the installer writes it, pointed at `socket`.
    fn installed(socket: &std::path::Path) -> String {
        format!(
            "ingress_socket = \"{}\"\n\n[memory]\nbase_url = \"http://127.0.0.1:8080\"\nagent = \"harness\"\n",
            socket.display()
        )
    }

    #[tokio::test]
    async fn serving_answers_an_envelope_on_the_configured_socket() {
        // The whole `run` path bar the signal: config in, socket bound, agent registered, delivery
        // back out. No memory service is running, and none is needed — this envelope names no
        // entities, so nothing is fetched.
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("ingress.sock");
        let config = Config::parse(&installed(&socket)).expect("config");
        let (stop, stopped) = oneshot::channel::<()>();
        let serving = tokio::spawn({
            let socket = socket.clone();
            async move {
                serve_ingress(&config, &socket, &["echo".to_string()], async {
                    let _ = stopped.await;
                })
                .await
            }
        });

        let stream = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(stream) = UnixStream::connect(&socket).await {
                    return stream;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the socket must appear");

        let (reader, mut writer) = stream.into_split();
        let envelope = serde_json::json!({
            "envelope_id": "cli-1", "source": "cli", "received_at": "2026-08-19T14:30:12Z",
            "attempt": 1, "reply_to": "stdout", "actor": "local", "body": "echo hello", "extra": {}
        });
        writer
            .write_all(format!("{envelope}\n").as_bytes())
            .await
            .expect("write");

        let line = tokio::time::timeout(
            Duration::from_secs(5),
            BufReader::new(reader).lines().next_line(),
        )
        .await
        .expect("a delivery within the timeout")
        .expect("read")
        .expect("a delivery line");
        let delivery: harness_envelope::Delivery = serde_json::from_str(&line).expect("delivery");
        assert_eq!(delivery.text, "hello");
        assert_eq!(delivery.target, "stdout");

        drop(stop);
        serving.await.expect("join").expect("clean shutdown");
        assert!(!socket.exists(), "shutdown must remove the socket");
    }

    #[test]
    fn the_same_agent_twice_is_a_usage_error() {
        // Two claims on one intent is ambiguous by design; here it is the argument list's fault.
        let error = registry(&["echo".to_string(), "echo".to_string()])
            .expect_err("one intent claimed twice must not register");
        assert_eq!(error.code(), exit::USAGE);
    }
}
