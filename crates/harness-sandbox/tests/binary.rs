//! The binary as the installer sees it: a report on stdout and an exit code to branch on.
//!
//! The unit tests exercise the same paths in process. This runs the built binary, because
//! `setup/provision.sh` branches on the exit code and neither that nor the printed report is
//! observable from inside.

#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

use tempfile::TempDir;

/// Runs the binary with `args`.
fn sandbox(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_harness-sandbox"))
        .args(args)
        .output()
        .expect("run the binary")
}

#[test]
fn provisioning_reports_what_it_changed_and_audits_clean_afterwards() {
    let dir = TempDir::new().expect("tempdir");
    let root = dir.path().join("state");
    let root = root.to_str().expect("utf-8");

    let provision = sandbox(&["--root", root, "provision", "--agent", "alpha"]);
    let report = String::from_utf8(provision.stdout).expect("utf-8");
    assert_eq!(provision.status.code(), Some(0), "{report}");
    for expected in [
        "generated signing key",
        "harness.service",
        "harness.container.json",
        "agree on every property",
    ] {
        assert!(report.contains(expected), "missing `{expected}`:\n{report}");
    }

    assert_eq!(
        sandbox(&["--root", root, "audit"]).status.code(),
        Some(0),
        "a freshly provisioned tree must audit clean"
    );
    assert_eq!(sandbox(&["--root", root, "check"]).status.code(), Some(0));
}

#[test]
fn an_exposed_key_fails_the_audit_with_a_nonzero_status() {
    let dir = TempDir::new().expect("tempdir");
    let root = dir.path().join("state");
    let path = root.to_str().expect("utf-8");
    assert_eq!(
        sandbox(&["--root", path, "provision", "--agent", "alpha"])
            .status
            .code(),
        Some(0)
    );

    let key = root.join(".secrets/memory-keys/alpha");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).expect("loosen");

    let audit = sandbox(&["--root", path, "audit"]);
    let complaint = String::from_utf8(audit.stderr).expect("utf-8");
    assert_eq!(audit.status.code(), Some(1), "{complaint}");
    assert!(complaint.contains("0640"), "{complaint}");
}

#[test]
fn misuse_exits_two_so_a_script_can_tell_it_from_a_refusal() {
    assert_eq!(
        sandbox(&["--root", "/tmp", "rotate"]).status.code(),
        Some(2)
    );
    assert_eq!(sandbox(&["--help"]).status.code(), Some(0));
}
