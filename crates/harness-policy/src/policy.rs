//! The declared policy: the single source of truth both layers read.
//!
//! Layer 1 (a harness's own allow/deny config) and layer 2 (the [`crate::Guard`]) are generated from
//! and evaluated against *this* document, never from each other. That is what makes them defence in
//! depth rather than one mechanism written twice: the hook does not care whether the harness config
//! was installed, and the harness config does not care whether the hook ran.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Policy schema version this build implements.
pub const SUPPORTED_VERSION: u32 = 1;

/// The policy as declared on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Schema version. Must equal [`SUPPORTED_VERSION`].
    pub version: u32,
    /// Where the agent is allowed to write. `${workspace}` expands to the workspace root.
    #[serde(default)]
    pub workspace_roots: Vec<String>,
    /// Programs that only launch another program, and so must not hide it.
    ///
    /// `sudo rm -rf /` is an `rm` rule violation; without this list it is an unknown program called
    /// `sudo` and every command rule misses it.
    #[serde(default)]
    pub command_wrappers: Vec<String>,
    /// Programs whose every path argument is a write — destructive, or a copy out.
    #[serde(default)]
    pub writing_programs: Vec<String>,
    /// Programs whose *last* path argument is the write and the rest are reads.
    ///
    /// Separate from [`Self::writing_programs`] because `cp /etc/hosts ./notes` reads a protected
    /// file and writes an ordinary one, and refusing it would be a false positive people disable the
    /// guard to get around.
    #[serde(default)]
    pub copy_programs: Vec<String>,
    /// Paths that must not be read or written, at all.
    #[serde(default)]
    pub secret_paths: Vec<PathRule>,
    /// Paths that may be read but never written.
    #[serde(default)]
    pub protected_paths: Vec<PathRule>,
    /// Commands refused by program name, optionally narrowed by argument.
    #[serde(default)]
    pub commands: Vec<CommandRule>,
    /// Which hosts the agent may reach.
    #[serde(default)]
    pub network: Network,
}

/// A named set of path patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRule {
    /// Stable identifier, reported in a denial so a block can be traced to a line of policy.
    pub id: String,
    /// Why this is denied, in words a person reads in a refusal message.
    pub reason: String,
    /// Glob patterns; see [`crate::glob`].
    pub patterns: Vec<String>,
}

/// A refused command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRule {
    /// Stable identifier, reported in a denial.
    pub id: String,
    /// Why this is denied.
    pub reason: String,
    /// Program names, matched against the command's basename as globs.
    pub programs: Vec<String>,
    /// Argument globs that must *all* match some argument. Empty means the program alone is enough.
    #[serde(default)]
    pub args: Vec<String>,
}

/// The egress allowlist.
///
/// An allowlist and not a denylist, because the thing being prevented is egress to an *arbitrary*
/// host: a list of bad hosts is a list of the ones somebody thought of.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Network {
    /// Why an off-list host is denied.
    #[serde(default)]
    pub reason: String,
    /// Hosts that may be reached. An entry beginning with `.` matches any subdomain.
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    /// Programs whose whole purpose is egress, so an unverifiable target is a refusal.
    #[serde(default)]
    pub programs: Vec<String>,
}

/// The policy shipped with this repository.
///
/// Embedded at compile time so the guard has a working policy with nothing installed, and so the
/// declared document is parsed by the test suite rather than only in production.
const BASELINE: &str = include_str!("../../../policy/tool-policy.json");

impl Policy {
    /// The policy shipped with this repository.
    pub fn baseline() -> Result<Self> {
        Self::parse(BASELINE, "baseline policy")
    }

    /// Reads a policy from `path`.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|why| Error::Unreadable {
            path: path.display().to_string(),
            why: why.to_string(),
        })?;
        Self::parse(&text, &path.display().to_string())
    }

    /// Parses a policy from JSON, rejecting a version this build does not implement.
    pub fn parse(text: &str, what: &str) -> Result<Self> {
        let policy: Self = serde_json::from_str(text).map_err(|why| Error::Malformed {
            what: what.to_string(),
            why: why.to_string(),
        })?;
        if policy.version == SUPPORTED_VERSION {
            Ok(policy)
        } else {
            Err(Error::Version {
                found: policy.version,
                supported: SUPPORTED_VERSION,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Policy;

    #[test]
    fn the_shipped_policy_parses_and_covers_the_three_named_areas() {
        let policy = Policy::baseline().expect("baseline parses");

        // The three the brief names, asserted through what the policy declares rather than by
        // counting rules, so adding a rule does not break the test.
        let secret: Vec<&str> = policy
            .secret_paths
            .iter()
            .map(|rule| rule.id.as_str())
            .collect();
        assert!(secret.contains(&"private-keys"));
        assert!(secret.contains(&"environment-files"));
        assert!(secret.contains(&"credential-stores"));
        assert!(!policy.writing_programs.is_empty());
        assert!(!policy.network.allow_hosts.is_empty());
        assert!(!policy.workspace_roots.is_empty());
    }

    #[test]
    fn a_newer_policy_version_is_refused_rather_than_partly_read() {
        let error = Policy::parse(r#"{"version": 99}"#, "test").expect_err("version refused");
        assert_eq!(
            error.to_string(),
            "policy version 99 is not supported (this guard implements 1)"
        );
    }

    #[test]
    fn a_policy_that_is_not_json_is_refused() {
        let error = Policy::parse("not json", "test").expect_err("parse fails");
        assert!(error.to_string().starts_with("malformed test:"), "{error}");
    }

    #[test]
    fn a_missing_policy_file_is_reported_with_its_path() {
        let error = Policy::load(std::path::Path::new("/nonexistent/tool-policy.json"))
            .expect_err("load fails");
        assert!(
            error
                .to_string()
                .starts_with("cannot read policy /nonexistent/tool-policy.json:"),
            "{error}"
        );
    }

    #[test]
    fn a_policy_file_on_disk_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tool-policy.json");
        std::fs::write(
            &path,
            serde_json::to_string(&Policy::baseline().expect("baseline")).expect("serialise"),
        )
        .expect("write");

        let loaded = Policy::load(&path).expect("load");
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.secret_paths.len(), 4);
    }
}
