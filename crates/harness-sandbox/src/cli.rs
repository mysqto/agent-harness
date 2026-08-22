//! The command an installer or a runbook runs.
//!
//! Provisioning is here rather than in shell because every part of it is a thing worth testing: the
//! modes on a key file, the equivalence of two artefacts, the overlap window on a rotation. A shell
//! script that did the same work would be the one part of this layer with no test at all.
//!
//! Argument parsing, a report, and an exit code. Everything it decides lives in the other modules.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::keys::Keyring;
use crate::policy::Policy;
use crate::workspace::Layout;
use crate::{Error, Result};

/// Mode for the emitted artefacts: readable, never writable by the group that runs the service.
///
/// A service able to rewrite its own confinement is a service whose confinement is advisory.
const MODE_ARTEFACT: u32 = 0o644;

/// Confine a harness deployment: workspaces, sandbox artefacts, signing keys.
#[derive(Debug, Parser)]
#[command(name = "harness-sandbox", version, about, long_about = None)]
struct Cli {
    /// Deployment root. Everything the harness owns lives under it.
    #[arg(long, global = true, default_value = "/var/lib/harness")]
    root: PathBuf,
    #[command(subcommand)]
    command: Command,
}

/// What to do.
#[derive(Debug, Subcommand)]
enum Command {
    /// Create the tree, the per-agent keys, and the sandbox artefacts. Idempotent.
    Provision {
        /// An agent to provision. Repeatable.
        #[arg(long = "agent", required = true)]
        agents: Vec<String>,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Print one artefact on stdout.
    Emit {
        /// Which artefact.
        #[arg(long)]
        format: Format,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Check that a unit and a container profile still describe the same sandbox.
    Check {
        /// A systemd unit to read. Defaults to the one under the deployment root.
        #[arg(long)]
        unit: Option<PathBuf>,
        /// A container profile to read. Defaults to the one under the deployment root.
        #[arg(long)]
        profile: Option<PathBuf>,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Rotate one agent's signing key, keeping the old one valid for the overlap window.
    Rotate {
        /// The agent whose key is being replaced.
        #[arg(long)]
        agent: String,
        /// Treat this as the current time, in milliseconds. For reproducing a rotation.
        #[arg(long)]
        now_ms: Option<u64>,
    },
    /// Report anything in the tree that grants more than the policy allows.
    Audit,
}

/// Where the policy comes from. A file when a deployment keeps one, the Phase 0 defaults otherwise.
#[derive(Debug, Args)]
struct PolicyArgs {
    /// A declared policy as JSON. Overrides every other option here.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Service name.
    #[arg(long, default_value = "harness")]
    name: String,
    /// The command the sandbox runs.
    #[arg(long, default_value = "/usr/local/bin/harness run")]
    exec: String,
    /// An egress destination to allow. Repeatable; everything unlisted is denied.
    #[arg(long = "allow")]
    allow: Vec<String>,
}

/// The artefacts that can be emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// A systemd service unit.
    Systemd,
    /// A container profile as JSON.
    Container,
}

impl PolicyArgs {
    /// The policy: from the file when one is named, otherwise the Phase 0 defaults for this root.
    fn resolve(&self, root: &Path) -> Result<Policy> {
        let mut policy = match &self.policy {
            Some(path) => {
                let text = fs::read_to_string(path).map_err(|err| crate::io("read", path, &err))?;
                serde_json::from_str(&text)
                    .map_err(|err| Error::Policy(format!("{}: {err}", path.display())))?
            }
            None => Policy::phase0(&self.name, &self.exec, root),
        };
        // A declared file wins on everything except an allowlist given on the command line, which
        // is how a lab run opens exactly one destination without editing the shared policy.
        if !self.allow.is_empty() {
            policy.hardening.egress_allow.clone_from(&self.allow);
        }
        policy.validate()?;
        Ok(policy)
    }
}

/// Runs the command in `args`, returning the process exit code.
///
/// `0` for success, `1` for a refusal or a broken host, `2` for a usage error — the same split
/// anything scripting this needs to branch on.
pub fn run<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            // clap already distinguishes help from misuse, and its own code says which.
            let _ = err.print();
            return if err.use_stderr() { 2 } else { 0 };
        }
    };
    match dispatch(&cli) {
        Ok(report) => {
            for line in report {
                println!("{line}");
            }
            0
        }
        Err(err) => {
            eprintln!("harness-sandbox: {err}");
            1
        }
    }
}

/// Does the work, collecting what it did rather than printing as it goes, so a failure part-way
/// does not leave half a report on stdout.
fn dispatch(cli: &Cli) -> Result<Vec<String>> {
    let layout = Layout::new(&cli.root);
    match &cli.command {
        Command::Provision { agents, policy } => provision(&layout, agents, policy),
        Command::Emit { format, policy } => {
            let policy = policy.resolve(&cli.root)?;
            Ok(vec![match format {
                Format::Systemd => policy.systemd_unit(),
                Format::Container => policy.container_profile(),
            }])
        }
        Command::Check {
            unit,
            profile,
            policy,
        } => check(&layout, unit.as_deref(), profile.as_deref(), policy),
        Command::Rotate { agent, now_ms } => rotate(&layout, agent, *now_ms),
        Command::Audit => audit(&layout),
    }
}

/// Creates the tree, one key per agent, and both artefacts.
fn provision(layout: &Layout, agents: &[String], args: &PolicyArgs) -> Result<Vec<String>> {
    let policy = args.resolve(layout.root())?;
    let mut report = Vec::new();
    for change in layout.provision(agents)? {
        report.push(format!("→ {change}"));
    }

    for agent in agents {
        let path = layout.key_file(agent)?;
        if path.exists() {
            // Loading it checks the mode, so a re-run reports an exposed key rather than skipping
            // over it. Never regenerated: a new key here would silently invalidate whatever the
            // agent has already been signing with.
            Keyring::load(&path)?;
            report.push(format!("→ kept signing key {}", path.display()));
        } else {
            Keyring::provision(agent)?.save(&path)?;
            report.push(format!("→ generated signing key {}", path.display()));
        }
    }

    // Written only once the pair has been read back and agreed: a deployment should not end up
    // holding two artefacts that describe different sandboxes.
    let (unit, profile) = agreed(&policy)?;
    for (path, body) in [
        (unit_path(layout, &policy.name), unit),
        (profile_path(layout, &policy.name), profile),
        (
            layout.sandbox().join("policy.json"),
            serde_json::to_string_pretty(&policy)
                .map_err(|err| Error::Policy(format!("encode policy: {err}")))?,
        ),
    ] {
        write_artefact(&path, &body)?;
        report.push(format!("→ wrote {}", path.display()));
    }
    report.push(
        "→ the unit and the container profile were read back and agree on every property"
            .to_owned(),
    );
    Ok(report)
}

/// Reads both artefacts back and refuses to return them unless they describe the same sandbox.
fn agreed(policy: &Policy) -> Result<(String, String)> {
    let unit = policy.systemd_unit();
    let profile = policy.container_profile();
    compare(&unit, &profile, Some(policy))?;
    Ok((unit, profile))
}

/// Compares two artefacts, and each against the policy when one was declared.
fn compare(unit: &str, profile: &str, policy: Option<&Policy>) -> Result<()> {
    let from_unit = Policy::read_systemd(unit)?;
    let from_profile = Policy::read_container(profile)?;
    if from_unit != from_profile {
        return Err(Error::Policy(format!(
            "the unit and the container profile describe different sandboxes:\n  unit:      {from_unit:?}\n  container: {from_profile:?}"
        )));
    }
    if let Some(policy) = policy
        && from_unit != policy.hardening
    {
        return Err(Error::Policy(
            "both artefacts agree with each other but not with the declared policy".to_owned(),
        ));
    }
    Ok(())
}

/// Checks the pair a deployment is actually holding.
///
/// Always the files on disk, never a freshly generated pair: a check that re-emitted both artefacts
/// would agree with itself no matter what the host was running, which is the one answer nobody
/// needs.
fn check(
    layout: &Layout,
    unit: Option<&Path>,
    profile: Option<&Path>,
    args: &PolicyArgs,
) -> Result<Vec<String>> {
    let policy = args.resolve(layout.root())?;
    let unit = unit.map_or_else(|| unit_path(layout, &policy.name), Path::to_path_buf);
    let profile = profile.map_or_else(|| profile_path(layout, &policy.name), Path::to_path_buf);
    compare(&read(&unit)?, &read(&profile)?, None)?;
    Ok(vec![format!(
        "{} and {} agree on every property",
        unit.display(),
        profile.display()
    )])
}

/// Replaces one agent's key, keeping the old one acceptable for the overlap window.
fn rotate(layout: &Layout, agent: &str, now_ms: Option<u64>) -> Result<Vec<String>> {
    let path = layout.key_file(agent)?;
    let mut keyring = Keyring::load(&path)?;
    let now = now_ms.unwrap_or_else(now);
    keyring.rotate(now)?;
    keyring.save(&path)?;
    Ok(vec![
        format!("→ rotated the signing key of {agent} in {}", path.display()),
        format!(
            "→ the retired key is accepted until {} — until then, both are valid",
            keyring.accepts_previous_until().unwrap_or(now)
        ),
    ])
}

/// Reports permission drift, and says so in the exit code.
fn audit(layout: &Layout) -> Result<Vec<String>> {
    let findings = layout.audit()?;
    if findings.is_empty() {
        return Ok(vec![format!(
            "{}: every path is at least as tight as the policy",
            layout.root().display()
        )]);
    }
    Err(Error::Permissions(findings.join("\n  ")))
}

/// Wall clock in milliseconds.
///
/// A clock before the epoch would mean a rotation window in the past, so it is treated as zero
/// rather than panicking: the caller can pass `--now-ms` and get on with the rotation.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Where the unit for `name` lives under a deployment.
fn unit_path(layout: &Layout, name: &str) -> PathBuf {
    layout.sandbox().join(format!("{name}.service"))
}

/// Where the container profile for `name` lives under a deployment.
fn profile_path(layout: &Layout, name: &str) -> PathBuf {
    layout.sandbox().join(format!("{name}.container.json"))
}

/// Reads an artefact, naming the file.
fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|err| crate::io("read", path, &err))
}

/// Writes an artefact at [`MODE_ARTEFACT`], whatever the umask says.
fn write_artefact(path: &Path, body: &str) -> Result<()> {
    fs::write(path, body).map_err(|err| crate::io("write", path, &err))?;
    fs::set_permissions(path, fs::Permissions::from_mode(MODE_ARTEFACT))
        .map_err(|err| crate::io("chmod", path, &err))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use clap::Parser as _;
    use tempfile::TempDir;

    use super::{Cli, Format, PolicyArgs, dispatch, run};
    use crate::workspace::{MODE_KEY_FILE, mode_of};
    use crate::{Keyring, Layout, Policy};

    /// Runs the command line in process, so a failing case reports what it printed.
    fn sandbox(args: &[&str]) -> i32 {
        let mut full = vec!["harness-sandbox"];
        full.extend_from_slice(args);
        run(full)
    }

    /// Provisions a deployment under a temporary root and hands back both.
    fn provisioned() -> (TempDir, Layout) {
        let dir = TempDir::new().expect("tempdir");
        let root = dir.path().join("state");
        let code = sandbox(&[
            "--root",
            root.to_str().expect("utf-8"),
            "provision",
            "--agent",
            "alpha",
            "--agent",
            "beta",
        ]);
        assert_eq!(code, 0);
        (dir, Layout::new(root))
    }

    #[test]
    fn provisioning_writes_keys_at_0600_and_both_artefacts() {
        let (_dir, layout) = provisioned();

        for agent in ["alpha", "beta"] {
            let key = layout.key_file(agent).expect("path");
            assert_eq!(mode_of(&key).expect("mode"), MODE_KEY_FILE, "{agent}");
            Keyring::load(&key).expect("loads");
        }
        for name in ["harness.service", "harness.container.json", "policy.json"] {
            assert!(layout.sandbox().join(name).exists(), "{name} missing");
        }
    }

    #[test]
    fn provisioning_is_idempotent_and_keeps_the_existing_keys() {
        let (_dir, layout) = provisioned();
        let before = fs::read_to_string(layout.key_file("alpha").expect("path")).expect("read");

        let code = sandbox(&[
            "--root",
            layout.root().to_str().expect("utf-8"),
            "provision",
            "--agent",
            "alpha",
            "--agent",
            "beta",
        ]);

        assert_eq!(code, 0);
        let after = fs::read_to_string(layout.key_file("alpha").expect("path")).expect("read");
        assert_eq!(before, after, "a re-run must not replace a live key");
    }

    #[test]
    fn provisioning_refuses_to_reuse_an_exposed_key() {
        let (_dir, layout) = provisioned();
        let key = layout.key_file("alpha").expect("path");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("loosen");

        let code = sandbox(&[
            "--root",
            layout.root().to_str().expect("utf-8"),
            "provision",
            "--agent",
            "alpha",
        ]);
        assert_eq!(code, 1);
    }

    #[test]
    fn the_deployed_pair_checks_out_and_a_hand_edited_unit_does_not() {
        let (_dir, layout) = provisioned();
        let root = layout.root().to_str().expect("utf-8").to_owned();
        assert_eq!(sandbox(&["--root", &root, "check"]), 0);

        let unit = layout.sandbox().join("harness.service");
        let softened = fs::read_to_string(&unit)
            .expect("read")
            .replace("NoNewPrivileges=true", "NoNewPrivileges=false");
        fs::write(&unit, softened).expect("write");

        assert_eq!(
            sandbox(&["--root", &root, "check"]),
            1,
            "a softened unit must not agree with the container profile"
        );
    }

    #[test]
    fn check_against_a_named_pair_of_files() {
        let (dir, layout) = provisioned();
        let root = layout.root().to_str().expect("utf-8").to_owned();
        let unit = layout.sandbox().join("harness.service");
        let elsewhere = dir.path().join("copy.service");
        fs::copy(&unit, &elsewhere).expect("copy");

        assert_eq!(
            sandbox(&[
                "--root",
                &root,
                "check",
                "--unit",
                elsewhere.to_str().expect("utf-8"),
            ]),
            0
        );
        assert_eq!(
            sandbox(&[
                "--root",
                &root,
                "check",
                "--profile",
                dir.path().join("absent.json").to_str().expect("utf-8"),
            ]),
            1
        );
    }

    #[test]
    fn emitting_prints_one_artefact() {
        let dir = TempDir::new().expect("tempdir");
        let root = dir.path().to_str().expect("utf-8");
        assert_eq!(sandbox(&["--root", root, "emit", "--format", "systemd"]), 0);
        assert_eq!(
            sandbox(&["--root", root, "emit", "--format", "container"]),
            0
        );
    }

    #[test]
    fn emitting_uses_a_declared_policy_file() {
        let dir = TempDir::new().expect("tempdir");
        let mut policy = Policy::phase0("service", "/bin/true", dir.path());
        policy.hardening.pids_max = 8;
        let path = dir.path().join("policy.json");
        fs::write(&path, serde_json::to_string(&policy).expect("encode")).expect("write");

        let cli = Cli::try_parse_from([
            "harness-sandbox",
            "--root",
            dir.path().to_str().expect("utf-8"),
            "emit",
            "--format",
            "systemd",
            "--policy",
            path.to_str().expect("utf-8"),
        ])
        .expect("parse");
        let report = dispatch(&cli).expect("emit");

        assert!(report[0].contains("TasksMax=8"), "{}", report[0]);
    }

    #[test]
    fn an_allowlist_on_the_command_line_overrides_the_declared_policy() {
        let dir = TempDir::new().expect("tempdir");
        let args = PolicyArgs {
            policy: None,
            name: "harness".to_owned(),
            exec: "/bin/true".to_owned(),
            allow: vec!["10.0.0.0/8".to_owned()],
        };
        let policy = args.resolve(dir.path()).expect("resolve");

        assert_eq!(policy.hardening.egress_allow, vec!["10.0.0.0/8"]);
        assert!(policy.systemd_unit().contains("IPAddressAllow=10.0.0.0/8"));
        assert!(policy.container_profile().contains("harness-egress"));
    }

    #[test]
    fn a_policy_below_the_floor_is_refused_before_anything_is_written() {
        let dir = TempDir::new().expect("tempdir");
        let mut policy = Policy::phase0("harness", "/bin/true", dir.path());
        policy.hardening.no_new_privileges = false;
        let path = dir.path().join("soft.json");
        fs::write(&path, serde_json::to_string(&policy).expect("encode")).expect("write");

        let code = sandbox(&[
            "--root",
            dir.path().join("state").to_str().expect("utf-8"),
            "provision",
            "--agent",
            "alpha",
            "--policy",
            path.to_str().expect("utf-8"),
        ]);

        assert_eq!(code, 1);
        assert!(
            !dir.path()
                .join("state")
                .join("sandbox")
                .join("harness.service")
                .exists()
        );
    }

    #[test]
    fn a_policy_file_that_is_not_a_policy_is_reported() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("broken.json");
        fs::write(&path, "{ not json").expect("write");
        assert_eq!(
            sandbox(&[
                "--root",
                dir.path().to_str().expect("utf-8"),
                "emit",
                "--format",
                "systemd",
                "--policy",
                path.to_str().expect("utf-8"),
            ]),
            1
        );
        assert_eq!(
            sandbox(&[
                "--root",
                dir.path().to_str().expect("utf-8"),
                "emit",
                "--format",
                "systemd",
                "--policy",
                dir.path().join("absent.json").to_str().expect("utf-8"),
            ]),
            1
        );
    }

    #[test]
    fn rotating_keeps_the_old_key_valid_for_the_window() {
        let (_dir, layout) = provisioned();
        let path = layout.key_file("alpha").expect("path");
        let before = Keyring::load(&path).expect("load");
        let signed_earlier = before.sign(b"in flight");

        let code = sandbox(&[
            "--root",
            layout.root().to_str().expect("utf-8"),
            "rotate",
            "--agent",
            "alpha",
            "--now-ms",
            "1000",
        ]);
        assert_eq!(code, 0);

        let after = Keyring::load(&path).expect("load");
        assert_eq!(
            after.accepts_previous_until(),
            Some(1000 + crate::OVERLAP_MS)
        );
        assert!(after.verify(b"in flight", &signed_earlier, 2000).is_ok());
        assert!(
            after
                .verify(b"in flight", &signed_earlier, 1000 + crate::OVERLAP_MS)
                .is_err()
        );
        assert_eq!(mode_of(&path).expect("mode"), MODE_KEY_FILE);
    }

    #[test]
    fn rotating_without_a_time_uses_the_clock() {
        let (_dir, layout) = provisioned();
        let code = sandbox(&[
            "--root",
            layout.root().to_str().expect("utf-8"),
            "rotate",
            "--agent",
            "alpha",
        ]);
        assert_eq!(code, 0);
        let keyring = Keyring::load(&layout.key_file("alpha").expect("path")).expect("load");
        assert!(keyring.accepts_previous_until().unwrap_or_default() > crate::OVERLAP_MS);
    }

    #[test]
    fn rotating_an_agent_that_was_never_provisioned_fails() {
        let (_dir, layout) = provisioned();
        assert_eq!(
            sandbox(&[
                "--root",
                layout.root().to_str().expect("utf-8"),
                "rotate",
                "--agent",
                "gamma",
            ]),
            1
        );
    }

    #[test]
    fn auditing_a_clean_tree_passes_and_a_loosened_one_does_not() {
        let (_dir, layout) = provisioned();
        let root = layout.root().to_str().expect("utf-8").to_owned();
        assert_eq!(sandbox(&["--root", &root, "audit"]), 0);

        let private = layout.private("alpha").expect("path");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).expect("loosen");

        assert_eq!(sandbox(&["--root", &root, "audit"]), 1);
    }

    #[test]
    fn help_exits_zero_and_misuse_exits_two() {
        assert_eq!(sandbox(&["--help"]), 0);
        assert_eq!(sandbox(&["provision"]), 2, "provision needs an agent");
        assert_eq!(sandbox(&["nonsense"]), 2);
    }

    #[test]
    fn an_artefact_is_not_writable_by_the_service_that_runs_under_it() {
        let (_dir, layout) = provisioned();
        let mode = mode_of(&layout.sandbox().join("harness.service")).expect("mode");
        assert_eq!(mode & 0o222, 0o200, "only the owner may rewrite a policy");
    }

    #[test]
    fn provisioning_into_an_unwritable_root_reports_the_path() {
        let dir = TempDir::new().expect("tempdir");
        let blocked = dir.path().join("blocked");
        fs::write(&blocked, "a file where a root should be").expect("write");
        assert_eq!(
            sandbox(&[
                "--root",
                blocked.to_str().expect("utf-8"),
                "provision",
                "--agent",
                "alpha",
            ]),
            1
        );
    }

    #[test]
    fn a_format_is_one_of_two_artefacts() {
        // The enum is what keeps `emit` from growing a third artefact nobody compares.
        assert_ne!(Format::Systemd, Format::Container);
    }

    #[test]
    fn an_identity_that_is_a_path_is_refused_by_the_command_too() {
        let dir = TempDir::new().expect("tempdir");
        assert_eq!(
            sandbox(&[
                "--root",
                dir.path().to_str().expect("utf-8"),
                "provision",
                "--agent",
                "../escape",
            ]),
            1
        );
    }

    #[test]
    fn the_artefact_paths_are_where_the_runbook_says() {
        let layout = Layout::new(Path::new("/var/lib/harness"));
        assert_eq!(
            super::unit_path(&layout, "harness"),
            Path::new("/var/lib/harness/sandbox/harness.service")
        );
        assert_eq!(
            super::profile_path(&layout, "harness"),
            Path::new("/var/lib/harness/sandbox/harness.container.json")
        );
    }
}
