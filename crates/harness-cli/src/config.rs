//! The deployment config, exactly as `setup/install.sh` writes it.
//!
//! Key names are matched to that script rather than chosen here. A rename on this side is not a
//! compile error anywhere — it is a deployment that starts, listens on the wrong path, and reports
//! nothing wrong, which is the most expensive kind of mistake this file can make.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{Error, Result};

/// Where the harness listens, and where memory lives.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Config {
    /// Unix socket adapters write envelopes to.
    pub ingress_socket: PathBuf,
    /// How to reach the memory service.
    pub memory: Memory,
}

/// Memory service coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Memory {
    /// Base URL of the service.
    pub base_url: String,
    /// Local sidecar socket, when one is deployed.
    ///
    /// Optional because the installer comments it out by default. Present is the better deployment:
    /// the sidecar holds the signing key, so this process needs none.
    #[serde(default)]
    pub sidecar_socket: Option<PathBuf>,
    /// Identity records are attributed to.
    pub agent: String,
}

impl Config {
    /// Reads and parses a config file.
    ///
    /// The path is part of every failure message: on a host with a default config and an overridden
    /// one, "cannot read" without a path sends the reader to the wrong file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| Error::Config(format!("cannot read {}: {err}", path.display())))?;
        parse(&text).map_err(|why| Error::Config(format!("{}: {why}", path.display())))
    }

    /// Parses config text.
    ///
    /// Unknown keys are accepted. The installer says the file is safe to edit, and a config that
    /// refused to load because it carried a key this build did not know yet would make every
    /// upgrade a two-step operation.
    pub fn parse(text: &str) -> Result<Self> {
        parse(text).map_err(Error::Config)
    }

    /// Where the installer puts the config.
    ///
    /// Reads the same environment variables the installer does, so a deployment that moved its
    /// runtime directory does not have to pass `--config` to every invocation.
    #[must_use]
    pub fn default_path() -> PathBuf {
        default_path(
            std::env::var_os("HARNESS_CONFIG"),
            std::env::var_os("HARNESS_RUNTIME"),
            std::env::var_os("HOME"),
        )
    }

    /// The memory client configuration this describes.
    #[must_use]
    pub fn memory_client(&self) -> harness_memory::Config {
        harness_memory::Config {
            base_url: self.memory.base_url.clone(),
            sidecar_socket: self.memory.sidecar_socket.clone(),
            agent: self.memory.agent.clone(),
        }
    }
}

/// Parses, reporting the failure as one line.
///
/// `toml` renders a multi-line snippet with a caret under the offending span. On a stderr line that
/// is noise; the message and the path are what a reader acts on.
fn parse(text: &str) -> std::result::Result<Config, String> {
    toml::from_str(text).map_err(|err| {
        err.message()
            .lines()
            .next()
            .unwrap_or("unparseable")
            .to_string()
    })
}

/// Resolves the config path from the environment.
///
/// Split out from [`Config::default_path`] because setting a process-wide variable is not something
/// a test in this crate may do — `unsafe_code` is forbidden — and the precedence is worth testing.
fn default_path(
    explicit: Option<OsString>,
    runtime: Option<OsString>,
    home: Option<OsString>,
) -> PathBuf {
    if let Some(explicit) = explicit {
        return PathBuf::from(explicit);
    }
    runtime
        .map_or_else(
            || PathBuf::from(home.unwrap_or_default()).join(".local/state/harness"),
            PathBuf::from,
        )
        .join("config.toml")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Config, default_path};
    use crate::{Error, exit};

    /// What the installer writes, with the sidecar left commented out as it ships.
    const INSTALLED: &str = r#"
# Written by setup/install.sh. Safe to edit; re-running the installer will not overwrite it.
ingress_socket = "/run/harness/ingress.sock"

[memory]
base_url = "http://127.0.0.1:8080"
# Prefer a sidecar when present: it holds the signing key, so this process needs none.
# sidecar_socket = "/run/harness/memory-agent.sock"
agent = "harness"
"#;

    #[test]
    fn the_installers_config_parses() {
        let config = Config::parse(INSTALLED).expect("parse");
        assert_eq!(
            config.ingress_socket,
            PathBuf::from("/run/harness/ingress.sock")
        );
        assert_eq!(config.memory.base_url, "http://127.0.0.1:8080");
        assert_eq!(config.memory.agent, "harness");
        assert_eq!(config.memory.sidecar_socket, None);
    }

    #[test]
    fn a_config_file_loads_from_disk() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, INSTALLED).expect("write");
        assert_eq!(
            Config::load(&path).expect("load"),
            Config::parse(INSTALLED).unwrap()
        );
    }

    #[test]
    fn an_uncommented_sidecar_reaches_the_memory_client() {
        let text = INSTALLED.replace("# sidecar_socket", "sidecar_socket");
        let client = Config::parse(&text).expect("parse").memory_client();
        assert_eq!(
            client.sidecar_socket,
            Some(PathBuf::from("/run/harness/memory-agent.sock"))
        );
        assert_eq!(client.base_url, "http://127.0.0.1:8080");
        assert_eq!(client.agent, "harness");
    }

    #[test]
    fn a_key_this_build_does_not_know_is_not_fatal() {
        let text = format!("{INSTALLED}\nfilters = [\"redact\"]\n");
        assert!(Config::parse(&text).is_ok());
    }

    #[test]
    fn a_missing_file_is_a_config_error_naming_the_path() {
        let error = Config::load(&PathBuf::from("/nonexistent/harness.toml")).expect_err("missing");
        assert!(
            matches!(error, Error::Config(ref why) if why.contains("/nonexistent/harness.toml"))
        );
        assert_eq!(error.code(), exit::CONFIG);
    }

    #[test]
    fn malformed_config_is_a_config_error_on_one_line() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "ingress_socket = \n[memory\n").expect("write");
        let error = Config::load(&path).expect_err("malformed");
        assert_eq!(error.code(), exit::CONFIG);
        assert_eq!(
            error.to_string().lines().count(),
            1,
            "a parse error belongs on one line: {error}"
        );
    }

    #[test]
    fn a_missing_required_key_names_it() {
        for (text, missing) in [
            (
                "[memory]\nbase_url = \"u\"\nagent = \"a\"\n",
                "ingress_socket",
            ),
            ("ingress_socket = \"/s\"\n", "memory"),
            (
                "ingress_socket = \"/s\"\n[memory]\nagent = \"a\"\n",
                "base_url",
            ),
            (
                "ingress_socket = \"/s\"\n[memory]\nbase_url = \"u\"\n",
                "agent",
            ),
        ] {
            let error = Config::parse(text).expect_err(missing);
            assert!(
                error.to_string().contains(missing),
                "{missing} should be named: {error}"
            );
            assert_eq!(error.code(), exit::CONFIG);
        }
    }

    #[test]
    fn an_explicit_config_path_wins_over_the_runtime_directory() {
        assert_eq!(
            default_path(
                Some("/etc/harness/explicit.toml".into()),
                Some("/var/lib/harness".into()),
                Some("/home/someone".into())
            ),
            PathBuf::from("/etc/harness/explicit.toml")
        );
    }

    #[test]
    fn the_runtime_directory_wins_over_home() {
        assert_eq!(
            default_path(None, Some("/var/lib/harness".into()), Some("/h".into())),
            PathBuf::from("/var/lib/harness/config.toml")
        );
    }

    #[test]
    fn home_supplies_the_installers_default() {
        assert_eq!(
            default_path(None, None, Some("/home/someone".into())),
            PathBuf::from("/home/someone/.local/state/harness/config.toml")
        );
        // No HOME either: still a usable relative path rather than a panic.
        assert!(
            default_path(None, None, None).ends_with("config.toml"),
            "a missing HOME must not lose the file name"
        );
    }

    #[test]
    fn the_environments_path_is_the_one_the_installer_writes() {
        assert!(Config::default_path().ends_with("config.toml"));
    }
}
