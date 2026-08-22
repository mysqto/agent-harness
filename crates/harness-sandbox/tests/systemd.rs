//! What systemd itself says about the unit we emit.
//!
//! This is the honest limit of a test suite: no test here starts a confined service, because that
//! needs a privileged host with the service user, the paths and the image in place. What *can* be
//! checked without any of that is that systemd parses every directive the emitter writes and
//! recognises every value — which is what catches a misspelled directive, and a misspelled
//! directive is silently ignored by a running systemd rather than refused.
//!
//! Skipped, loudly, where `systemd-analyze` is not installed. A test that quietly passes on a host
//! without the tool would be worse than no test.

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::Command;

use harness_sandbox::Policy;

/// Whether `systemd-analyze` is here to ask.
fn available() -> bool {
    Command::new("systemd-analyze")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

#[test]
fn systemd_accepts_every_directive_the_emitter_writes() {
    if !available() {
        eprintln!("skipped: systemd-analyze is not installed, so the unit was not parsed");
        return;
    }

    let dir = tempfile::TempDir::new().expect("tempdir");
    let mut policy = Policy::phase0("harness", "/bin/true", Path::new("/var/lib/harness"));
    policy.hardening.egress_allow = vec!["10.0.0.0/8".to_owned()];
    // The verifier resolves `ExecStart` and complains about a binary that is not there, which is
    // about the deployment rather than the unit; `/bin/true` keeps the check on the directives.
    let path = dir.path().join("harness.service");
    std::fs::write(&path, policy.systemd_unit()).expect("write");

    let output = Command::new("systemd-analyze")
        .arg("verify")
        .arg(&path)
        .output()
        .expect("run systemd-analyze");
    let complaints = String::from_utf8_lossy(&output.stderr);

    // `verify` exits zero even for an unknown directive — it warns and ignores it, exactly as a
    // running systemd would — so the assertion is on what it said, not on the status.
    assert!(
        complaints.trim().is_empty(),
        "systemd objected to the emitted unit:\n{complaints}"
    );
    assert!(output.status.success(), "{complaints}");
}

#[test]
fn systemd_would_have_objected_to_a_directive_we_got_wrong() {
    // Proves the check above has teeth: the same call on a unit with one bad value does complain,
    // so an empty stderr is evidence rather than a tool that says nothing about anything.
    if !available() {
        eprintln!("skipped: systemd-analyze is not installed");
        return;
    }

    let dir = tempfile::TempDir::new().expect("tempdir");
    let policy = Policy::phase0("harness", "/bin/true", Path::new("/var/lib/harness"));
    let broken = policy
        .systemd_unit()
        .replace("NoNewPrivileges=true", "NoNewPrivilege=true");
    let path = dir.path().join("broken.service");
    std::fs::write(&path, broken).expect("write");

    let output = Command::new("systemd-analyze")
        .arg("verify")
        .arg(&path)
        .output()
        .expect("run systemd-analyze");
    let complaints = String::from_utf8_lossy(&output.stderr);

    assert!(
        complaints.contains("NoNewPrivilege"),
        "the verifier said nothing about a misspelled directive:\n{complaints}"
    );
}
