//! The command line, as clap sees it.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::exit;

/// Run a dispatcher, or a single agent for development.
#[derive(Debug, Parser)]
#[command(
    name = "harness",
    version,
    about,
    after_help = exit::HELP,
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The two modes.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Serve a dispatcher on the ingress socket until interrupted.
    Run {
        /// Config file written by `setup/install.sh`.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Ingress socket, overriding the one in the config.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
        /// Agent to serve. Repeat for several.
        #[arg(long = "agent", value_name = "NAME", default_value = "echo")]
        agents: Vec<String>,
    },
    /// Dispatch one envelope from stdin, print what happened, and exit.
    ///
    /// Contacts nothing: no socket, no adapter, no memory service. Input is either an envelope as
    /// JSON or a plain line, which is wrapped in one — which is what makes `echo 'echo hi' |
    /// harness once` a usable way to exercise an agent.
    Once {
        /// Agent to dispatch to. Repeat for several.
        #[arg(long = "agent", value_name = "NAME", default_value = "echo")]
        agents: Vec<String>,
        /// Report the context bundle as degraded, to exercise the refusal path.
        #[arg(long)]
        degraded: bool,
    },
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::{CommandFactory, Parser};

    use super::{Cli, Command};

    /// Every field either subcommand can carry, so a test asserts on values rather than on shape.
    struct Parsed {
        config: Option<PathBuf>,
        socket: Option<PathBuf>,
        agents: Vec<String>,
        degraded: bool,
    }

    fn parse(args: &[&str]) -> Parsed {
        match Cli::try_parse_from(args).expect("parse").command {
            Command::Run {
                config,
                socket,
                agents,
            } => Parsed {
                config,
                socket,
                agents,
                degraded: false,
            },
            Command::Once { agents, degraded } => Parsed {
                config: None,
                socket: None,
                agents,
                degraded,
            },
        }
    }

    #[test]
    fn run_defaults_to_the_built_in_agent_and_the_configured_socket() {
        let parsed = parse(&["harness", "run"]);
        assert_eq!(parsed.agents, ["echo"]);
        assert!(parsed.config.is_none() && parsed.socket.is_none());
    }

    #[test]
    fn run_takes_a_config_a_socket_and_several_agents() {
        let parsed = parse(&[
            "harness",
            "run",
            "--config",
            "/etc/harness/config.toml",
            "--socket",
            "/run/harness/ingress.sock",
            "--agent",
            "echo",
            "--agent",
            "other",
        ]);
        assert_eq!(
            parsed.config,
            Some(PathBuf::from("/etc/harness/config.toml"))
        );
        assert_eq!(
            parsed.socket,
            Some(PathBuf::from("/run/harness/ingress.sock"))
        );
        assert_eq!(parsed.agents, ["echo", "other"]);
    }

    #[test]
    fn once_takes_a_degraded_flag() {
        assert!(!parse(&["harness", "once"]).degraded);
        let parsed = parse(&["harness", "once", "--degraded"]);
        assert_eq!(parsed.agents, ["echo"]);
        assert!(parsed.degraded);
    }

    #[test]
    fn a_subcommand_is_required() {
        assert!(Cli::try_parse_from(["harness"]).is_err());
        assert!(Cli::try_parse_from(["harness", "serve"]).is_err());
    }

    #[test]
    fn help_lists_the_exit_codes() {
        let rendered = Cli::command().render_long_help().to_string();
        for code in ["0  success", "4  dispatch refused", "5  unroutable"] {
            assert!(rendered.contains(code), "missing {code} from --help");
        }
    }
}
