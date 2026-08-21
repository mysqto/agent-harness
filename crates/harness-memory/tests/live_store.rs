//! A submission driven through the real memory service, end to end.
//!
//! Ignored, and it has to be: it runs the store's own binaries, which come from a sibling checkout
//! that CI does not have. Run it deliberately.
//!
//! ```sh
//! # Build the store's binaries once, in its own checkout:
//! (cd ../yaam && cargo build --release --bins)
//! # Then, from this repository:
//! cargo test -p harness-memory --test live_store -- --ignored --nocapture
//! ```
//!
//! The binaries are looked for beside this repository, at `../yaam/target/release`, and
//! `YAAM_BIN_DIR` overrides that. If they are not there the test says so and passes: a skip naming
//! what is missing is useful, and a failure on a machine that was never going to have the binaries
//! is not. It earns nothing towards the coverage gate either way.
//!
//! # Why this exists
//!
//! A unix-socket stub that accepts whatever it is handed is what let a record the service refuses
//! outright pass every test in this crate. So the assertion here is not an ack — a stub can produce
//! an ack. It is a file in the store's tree: the record was parsed, validated against the
//! deployment's entity kinds and attribute schema, unsealed, and written.

use std::fs;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use harness_agent::{ActionDraft, Status};
use harness_memory::{Client, Config};
use serde_json::json;
use tempfile::TempDir;

/// Identity the socket, the keyring and the record all have to agree on.
const AGENT: &str = "harness";

/// Signing key shared by the service's keyring and the sidecar's configuration, hex encoded.
///
/// Fixed rather than random: this is a loopback service holding one probe record for the length of
/// one test, and a constant makes the two files that have to match visibly match.
const SIGNING_KEY: &str = "1155aa4400ff77ee2266bb5511aa4400ff77ee2266bb5511aa4400ff77ee2266";

/// Secret half of the key the sidecar seals to, hex encoded.
///
/// Without it the service accepts plain JSON only and refuses a sealed body — and the sidecar seals
/// everything — so a run without this flag fails every write, which the service warns about at
/// startup.
const UNSEAL_KEY: &str = "4400ff77ee2266bb5511aa4400ff77ee2266bb5511aa4400ff77ee2266bb5511";

/// Where the service announces the public half of its sealing key.
const SEALING_KEY_LOG: &str = "sealing-public-key\" value=";

/// How long to wait for a child process to reach a state the test needs.
const READY: Duration = Duration::from_secs(20);

/// A running service and sidecar, and the temporary tree they were given.
///
/// The processes are killed and the tree removed by dropping this, so a panicking assertion cannot
/// leave a service holding a port or a sidecar holding a socket.
struct Lab {
    /// The temporary tree. Held for its destructor.
    _dir: TempDir,
    /// Service, then sidecar.
    children: Vec<Child>,
    /// Root of the memory tree, where written records appear.
    root: PathBuf,
    /// `host:port` the service is listening on.
    listen: String,
    /// The caller socket the sidecar serves for [`AGENT`].
    socket: PathBuf,
    /// Where each process's output went, for a failure message worth reading.
    server_log: PathBuf,
    /// As `server_log`, for the sidecar.
    agent_log: PathBuf,
}

impl Drop for Lab {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Lab {
    /// Brings up a service and a sidecar wired to each other, and waits until both are usable.
    fn start(bin: &Path) -> Self {
        // A unix socket path is capped near 108 bytes, so the state directory has to be short. The
        // system temporary directory is; a path under `target/` frequently is not.
        let dir = tempfile::tempdir().expect("temp dir");
        let lab = dir.path().to_owned();
        let root = lab.join("root");
        let state = lab.join("state");
        fs::create_dir_all(&state).expect("state dir");
        copy_tree(&spec_dir(), &root.join("spec"));

        let keyring = lab.join("keyring.json");
        fs::write(
            &keyring,
            json!({"callers": {AGENT: {"role": "writer", "key": SIGNING_KEY}}}).to_string(),
        )
        .expect("write keyring");
        let unseal = lab.join("unseal.key");
        fs::write(&unseal, UNSEAL_KEY).expect("write unseal key");

        let listen = format!("127.0.0.1:{}", free_port());
        let server_log = lab.join("server.log");
        let agent_log = lab.join("agent.log");
        let server = spawn(
            &bin.join("yaam-server"),
            &[
                "--root",
                &root.to_string_lossy(),
                "--keyring",
                &keyring.to_string_lossy(),
                "--unseal-key-file",
                &unseal.to_string_lossy(),
                "--listen",
                &listen,
            ],
            &server_log,
        );

        // The service prints the public half of its sealing key at startup, and the sidecar has to
        // seal to that exact key: sealed to anything else, the body is one the service cannot open.
        let sealing_key = until("the service's sealing public key", || {
            let text = log(&server_log);
            let at = text.find(SEALING_KEY_LOG)? + SEALING_KEY_LOG.len();
            Some(text[at..].split_whitespace().next()?.to_owned())
        });
        fs::write(
            state.join("upstream.json"),
            json!({
                "base_url": format!("http://{listen}"),
                "service_public_key": sealing_key,
                "signing_keys": {AGENT: SIGNING_KEY},
                "retry_interval_ms": 200,
            })
            .to_string(),
        )
        .expect("write upstream.json");

        let sidecar = spawn(
            &bin.join("yaam-agent"),
            &["--state-dir", &state.to_string_lossy()],
            &agent_log,
        );
        let socket = state.join("sockets").join(format!("{AGENT}.sock"));
        until("the sidecar's caller socket", || {
            // A sidecar that refuses to start says why once and exits, so waiting out the deadline
            // would report a timeout in place of the reason.
            let text = log(&agent_log);
            assert!(
                !text.contains("yaam-agent:"),
                "the sidecar refused to start:\n{text}"
            );
            socket.exists().then_some(())
        });

        Self {
            _dir: dir,
            children: vec![server, sidecar],
            root,
            listen,
            socket,
            server_log,
            agent_log,
        }
    }

    /// A client pointed at this lab's sidecar.
    fn client(&self) -> Client {
        Client::new(Config {
            base_url: format!("http://{}", self.listen),
            sidecar_socket: Some(self.socket.clone()),
            agent: AGENT.to_owned(),
        })
    }

    /// Both processes' output, for a failure that has to be diagnosed from one message.
    fn logs(&self) -> String {
        format!(
            "-- sidecar --\n{}\n-- service --\n{}",
            log(&self.agent_log),
            log(&self.server_log)
        )
    }
}

/// The store's `spec/`, which supplies the entity kinds, attribute schema and redaction policy the
/// service validates against. A root without one refuses every record.
fn spec_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../yaam/spec")
}

/// Where the store's binaries are, or `None` when they are not built.
fn binaries() -> Option<PathBuf> {
    let dir = std::env::var_os("YAAM_BIN_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../yaam/target/release"),
        PathBuf::from,
    );
    ["yaam-server", "yaam-agent"]
        .iter()
        .all(|name| dir.join(name).is_file())
        .then_some(dir)
}

/// A port nothing is listening on: a listener is bound to get one the kernel calls free, then
/// dropped. The window between that and the service binding it is the closest a test can get.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

/// Copies a directory tree.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create dir");
    for entry in fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

/// Polls until `probe` answers, panicking once [`READY`] has passed.
fn until<T>(what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + READY;
    while Instant::now() < deadline {
        if let Some(found) = probe() {
            return found;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{what} did not appear within {}s", READY.as_secs());
}

/// Reads a log file, treating "not created yet" as empty.
fn log(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == ErrorKind::NotFound => String::new(),
        Err(err) => panic!("read {}: {err}", path.display()),
    }
}

/// Starts a binary with both output streams captured to one file.
fn spawn(binary: &Path, args: &[&str], log_path: &Path) -> Child {
    let out = fs::File::create(log_path).expect("create log");
    let err = out.try_clone().expect("clone log handle");
    Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", binary.display()))
}

/// Every `.md` file under a directory, which is the shape a written record takes.
fn records(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_owned()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                found.push(path);
            }
        }
    }
    found
}

/// A draft the service will accept.
///
/// `deploy`, its attribute keys and the `deploy` entity kind are all declared in the store's own
/// `spec/`. A draft naming anything else is refused for a reason that has nothing to do with the
/// translation under test.
fn draft() -> ActionDraft {
    ActionDraft {
        action: "deploy".into(),
        outcome: Status::Succeeded,
        attrs: [("service".to_owned(), json!("api"))].into_iter().collect(),
        entities: vec![("deploy".to_owned(), "api/staging#1146".to_owned())],
        summary: "probe".into(),
    }
}

/// Submits one record through [`Client`] and asserts the store wrote it.
///
/// See the module documentation for how to run this and why it is ignored.
#[tokio::test]
#[ignore = "drives the store's binaries from a sibling checkout; see the module docs"]
async fn a_submitted_record_lands_in_the_stores_tree() {
    let Some(bin) = binaries() else {
        eprintln!(
            "skipped: no yaam-server/yaam-agent found. Build them with \
             `cargo build --release --bins` in the store's checkout, or set YAAM_BIN_DIR."
        );
        return;
    };
    let lab = Lab::start(&bin);

    lab.client()
        .submit(&draft(), "env-lab-1", 10_000)
        .await
        .unwrap_or_else(|err| panic!("submit: {err}\n{}", lab.logs()));

    // The assertion a stub cannot fake. An ack says the sidecar took the line; a file in the tree
    // says the service parsed the record, validated it against this deployment's spec, opened the
    // sealed body and wrote it.
    let written = until("a record in the store's tree", || {
        let found = records(&lab.root.join("records"));
        (!found.is_empty()).then_some(found)
    });
    assert_eq!(
        written.len(),
        1,
        "one submission is one record: {written:?}"
    );

    let stored = fs::read_to_string(&written[0]).expect("read the record");
    println!("wrote {}\n{stored}", written[0].display());
    for expected in [
        "agent: harness",
        "correlation_id: env-lab-1",
        "action: deploy",
        "outcome: success",
        "role: primary",
        "confidence: 1.0",
        "data_class: internal",
        "visibility: owner",
    ] {
        assert!(
            stored.contains(expected),
            "the stored record is missing `{expected}`:\n{stored}"
        );
    }
    // The interaction has a field of its own now, so an attribute may carry that name too.
    assert!(
        !stored.contains("attrs:\n  correlation_id"),
        "the interaction must not occupy an attribute key:\n{stored}"
    );
}
