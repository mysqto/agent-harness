//! The guard as a harness invokes it: a process, a payload on stdin, an exit code.
//!
//! The unit tests already cover every rule. This exists because the *interface* is the exit code of
//! a real executable, and no in-process test can prove that the built binary blocks anything.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// Runs the built guard with `args`, writing `payload` to its stdin.
fn guard(args: &[&str], payload: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_harness-guard"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the guard");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("run to completion")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn the_binary_blocks_a_secret_read() {
    let output = guard(
        &["check"],
        r#"{"tool":"read","intents":[{"kind":"read","value":"~/.ssh/id_rsa"}]}"#,
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("private-keys"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_binary_blocks_a_destructive_command_outside_the_workspace() {
    let output = guard(
        &["check", "--harness", "claude-code"],
        r#"{"tool_name":"Bash","tool_input":{"command":"ls && sudo rm -rf ~"}}"#,
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("outside-workspace"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_binary_blocks_egress_to_an_unlisted_host() {
    let output = guard(
        &["check", "--harness", "claude-code"],
        r#"{"tool_name":"WebFetch","tool_input":{"url":"https://unlisted.test/x"}}"#,
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("network"), "{}", stderr(&output));
}

#[test]
fn the_binary_allows_ordinary_work_in_the_workspace() {
    // Runs with the crate directory as the workspace, which is what an unset `HARNESS_WORKSPACE`
    // means: confine to where the guard was invoked.
    for payload in [
        r#"{"tool_name":"Read","tool_input":{"file_path":"Cargo.toml"}}"#,
        r#"{"tool_name":"Write","tool_input":{"file_path":"src/generated.rs"}}"#,
        r#"{"tool_name":"Bash","tool_input":{"command":"cargo test --workspace"}}"#,
    ] {
        let output = guard(&["check", "--harness", "claude-code"], payload);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{payload}: {}",
            stderr(&output)
        );
        assert!(output.stderr.is_empty(), "{payload}: {}", stderr(&output));
    }
}

#[test]
fn an_unparseable_payload_exits_blocking() {
    let output = guard(&["check"], "not json at all");
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

#[test]
fn the_binary_emits_a_harness_config_it_can_be_wired_with() {
    let output = guard(
        &[
            "emit",
            "--harness",
            "claude-code",
            "--guard",
            "/opt/bin/harness-guard check",
        ],
        "",
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let rendered = String::from_utf8(output.stdout).expect("utf-8");
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
    assert_eq!(
        parsed["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "/opt/bin/harness-guard check"
    );
}
