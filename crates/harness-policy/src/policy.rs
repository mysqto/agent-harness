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
    /// Interpreters that take a program as an argument, and the tokens that hand them one.
    ///
    /// Absent from a document means the built-in surface rather than an empty one — see
    /// [`InlinePrograms`].
    #[serde(default)]
    pub inline_programs: InlinePrograms,
    /// Which hosts the agent may reach.
    #[serde(default)]
    pub network: Network,
}

/// The refusal of a program handed to an interpreter as an argument.
///
/// Not a list of what is protected, which is what every other group here is: it is a statement about
/// what a command line can be *read* as. `sh -c '<line>'` and `python3 -c '<program>'` put the whole
/// call inside one quoted word, so no rule in this document can see any of it, and the guard refuses
/// the shape rather than guessing at the contents.
///
/// **An absent group means the built-in surface, not an empty one.** That asymmetry is deliberate and
/// it is the lesson this rule was built from: a deployment had declared a setting meaning exactly
/// this, and nothing enforced it, because the mechanism it named was not present. A policy file older
/// than this build must not become a second way to declare the rule and not have it. Declaring
/// `interpreters: []` still turns it off, and is a decision somebody makes in writing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlinePrograms {
    /// Why this is refused, in words a person reads in a refusal message.
    #[serde(default = "InlinePrograms::default_reason")]
    pub reason: String,
    /// The interpreters, and what each one's "here is a program" token looks like.
    #[serde(default = "InlinePrograms::builtin")]
    pub interpreters: Vec<Interpreter>,
}

impl Default for InlinePrograms {
    fn default() -> Self {
        Self {
            reason: Self::default_reason(),
            interpreters: Self::builtin(),
        }
    }
}

/// One interpreter family: the programs, and the tokens that hand them a program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interpreter {
    /// Program names, matched against the command's basename as globs.
    pub programs: Vec<String>,
    /// Single-dash option *letters* that introduce a program.
    ///
    /// A set of characters rather than a list of tokens because clustering is a character question:
    /// `-lc` and `-cSOMETHING` both carry `c`, and a rule written in whole tokens misses both.
    #[serde(default)]
    pub flags: String,
    /// Long option names with the same meaning, without their dashes.
    ///
    /// Matched as a substring of the option's name, so a spelling nobody listed (`--commands`) is
    /// refused with the one that was.
    #[serde(default)]
    pub options: Vec<String>,
}

impl InlinePrograms {
    /// The group as `spec/tool-policy.json` declares it, or `None` if it does not.
    ///
    /// Read back out of the shipped document rather than written a second time in Rust. That
    /// document is the only place a rule is declared (AGENTS.md §6), and a hand-copied list here
    /// would be a second policy nobody reads and nothing keeps in step. Parsed as a plain JSON value
    /// on purpose: deserialising it as [`InlinePrograms`] would call the very defaults this supplies.
    fn shipped() -> Option<serde_json::Value> {
        serde_json::from_str::<serde_json::Value>(BASELINE)
            .ok()?
            .get("inline_programs")
            .cloned()
    }

    fn default_reason() -> String {
        Self::shipped()
            .and_then(|group| Some(group.get("reason")?.as_str()?.to_string()))
            .unwrap_or_default()
    }

    /// The surface used when a policy document does not name one.
    fn builtin() -> Vec<Interpreter> {
        Self::shipped()
            .and_then(|group| serde_json::from_value(group.get("interpreters")?.clone()).ok())
            .unwrap_or_default()
    }
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
const BASELINE: &str = include_str!("../../../spec/tool-policy.json");

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

    /// There is one declaration of this rule, and the fallback is a read of it.
    ///
    /// A rule is declared in `spec/tool-policy.json` and nowhere else. The constant this build falls
    /// back to when a document does not name the group is that same document, read back — so the two
    /// cannot drift, and removing the group from the document fails here rather than leaving a gate
    /// quietly falling back to itself.
    #[test]
    fn the_built_in_surface_is_the_shipped_document_rather_than_a_second_copy_of_it() {
        let shipped = Policy::baseline().expect("baseline").inline_programs;
        assert!(!shipped.interpreters.is_empty());
        assert!(!shipped.reason.is_empty());

        let silent = Policy::parse(r#"{"version":1}"#, "test").expect("parse");
        assert_eq!(silent.inline_programs.interpreters, shipped.interpreters);
        assert_eq!(silent.inline_programs.reason, shipped.reason);
    }

    /// An absent group is the built-in surface; an empty one is a decision.
    #[test]
    fn a_document_that_does_not_name_the_interpreters_still_gets_them() {
        let silent = Policy::parse(r#"{"version":1}"#, "test").expect("parse");
        assert!(!silent.inline_programs.interpreters.is_empty());

        let off = Policy::parse(
            r#"{"version":1,"inline_programs":{"interpreters":[]}}"#,
            "test",
        )
        .expect("parse");
        assert!(off.inline_programs.interpreters.is_empty());
        // The wording still comes from somewhere, so a refusal from a partial document reads as a
        // sentence rather than as an empty string.
        assert!(!off.inline_programs.reason.is_empty());
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
        // Against the baseline rather than a literal, so adding a rule group is not a test edit.
        assert_eq!(
            loaded.secret_paths.len(),
            Policy::baseline().expect("baseline").secret_paths.len()
        );
    }
}
