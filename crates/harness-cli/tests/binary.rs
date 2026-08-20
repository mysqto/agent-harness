//! The binary as a script sees it: stdin in, a report out, and an exit code to branch on.
//!
//! The unit tests exercise the same paths in process. This runs the built binary, because the exit
//! code and the shape of what is printed are the interface for anything scripting the harness, and
//! neither is observable from inside.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// Runs the binary with `args`, writing `stdin` to it.
fn harness(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_harness-cli"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the harness");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("run to completion")
}

#[test]
fn one_line_of_text_is_dispatched_and_reported() {
    // The shortest way to exercise an agent, and the one documented in the setup skill.
    let output = harness(&["once"], "echo hello\n");
    let report = String::from_utf8(output.stdout).expect("utf-8");

    assert_eq!(output.status.code(), Some(0), "{report}");
    for expected in [
        "intent     echo",
        "agent      echo",
        "status     succeeded",
        "mutating   no",
        "context    complete",
        "deliveries 1",
        "→ stdout: hello",
        "records    none",
    ] {
        assert!(report.contains(expected), "missing `{expected}`:\n{report}");
    }
}

#[test]
fn an_envelope_as_json_is_dispatched_too() {
    let envelope = r#"{"envelope_id":"cli-1","source":"cli","received_at":"2026-08-19T14:30:12Z",
        "attempt":1,"reply_to":"stdout","actor":"local","body":"echo order ord-91h2","extra":{}}"#;
    let output = harness(&["once"], envelope);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8(output.stdout)
            .expect("utf-8")
            .contains("→ stdout: order ord-91h2")
    );
}

#[test]
fn every_failure_reports_the_code_help_documents() {
    for (args, stdin, code) in [
        (vec!["once"], "{\"envelope_id\":", 2),
        (vec!["--nope"], "", 2),
        (vec!["run", "--config", "/nonexistent/harness.toml"], "", 3),
        (vec!["once"], "summarise order ord-91h2\n", 5),
    ] {
        let output = harness(&args, stdin);
        assert_eq!(
            output.status.code(),
            Some(code),
            "{args:?} should exit {code}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn help_documents_the_exit_codes() {
    let output = harness(&["--help"], "");
    let help = String::from_utf8(output.stdout).expect("utf-8");

    assert_eq!(output.status.code(), Some(0));
    for line in ["0  success", "3  config error", "5  unroutable"] {
        assert!(help.contains(line), "missing `{line}`:\n{help}");
    }
}
