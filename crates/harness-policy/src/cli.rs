//! The guard's command line, as a function.
//!
//! The binary is a shell around this: read arguments, maybe read stdin, print, exit. Keeping the
//! decision here means every exit code below is covered by an ordinary unit test — a guard whose
//! blocking path is only exercised by a live harness is a guard nobody has seen refuse anything.

use std::path::PathBuf;

use crate::error::Result;
use crate::eval::{Decision, Guard};
use crate::harness;
use crate::policy::Policy;

/// Exit code for a call the policy permits.
pub const ALLOW: u8 = 0;

/// Exit code for a blocked call — and for anything that could not be decided.
///
/// There is deliberately no third code meaning "unsure". A payload that will not parse, a policy
/// that will not load and a rule violation are all answered the same way, because the alternative is
/// a guard that opens whenever it is confused.
pub const BLOCK: u8 = 2;

/// What an invocation produced.
#[derive(Debug, PartialEq, Eq)]
pub struct Run {
    /// Process exit code.
    pub code: u8,
    /// Text for stdout.
    pub stdout: String,
    /// Text for stderr — the refusal a person or a model reads.
    pub stderr: String,
}

const USAGE: &str = "\
usage: harness-guard <command> [options]

  check   decide one tool call, read as JSON on stdin
  emit    print a harness's own allow/deny config, generated from the policy

options:
  --harness NAME   harness whose payload shape to read, or whose config to write
                   (neutral, claude-code, hermes, openclaw; default neutral)
  --policy FILE    policy to enforce (default: the policy built into this binary)
  --guard COMMAND  how the emitted config should invoke this guard
  -h, --help       this text

exit codes: 0 allowed, 2 blocked — including when the guard could not decide.
";

/// Runs one invocation. `read_stdin` is called only when the payload is needed.
pub fn run(args: &[String], read_stdin: impl FnOnce() -> std::io::Result<String>) -> Run {
    let parsed = Options::parse(args);
    // A harness that reads its verdict from stdout has to be told about *this* kind of block too. A
    // payload it could not parse is the most likely block of all, and one delivered only as an exit
    // code such a harness reads as no opinion — installed, and enforcing nothing.
    let reporting = match &parsed {
        Ok(options) if options.command == "check" => options.harness.clone(),
        _ => String::new(),
    };
    match parsed.and_then(|options| dispatch(options, read_stdin)) {
        Ok(run) => run,
        // Every failure is a block: see [`BLOCK`].
        Err(error) => {
            let reason = format!("harness-guard: {error}");
            Run {
                code: BLOCK,
                stdout: harness::verdict(&reporting, &reason).unwrap_or_default(),
                stderr: format!("{reason}\n"),
            }
        }
    }
}

fn dispatch(options: Options, read_stdin: impl FnOnce() -> std::io::Result<String>) -> Result<Run> {
    if options.help {
        return Ok(printed(USAGE));
    }
    let policy = match &options.policy {
        Some(path) => Policy::load(path)?,
        None => Policy::baseline()?,
    };
    match options.command.as_str() {
        "emit" => {
            let command = options
                .guard
                .unwrap_or_else(|| format!("harness-guard check --harness {}", options.harness));
            let config = harness::generate(&options.harness, &policy, &command)?;
            Ok(printed(&format!("{config}\n")))
        }
        "check" => {
            let payload = read_stdin().map_err(|why| crate::Error::Unreadable {
                path: "stdin".to_string(),
                why: why.to_string(),
            })?;
            let call = harness::translate(&options.harness, &payload)?;
            Ok(decision(&Guard::from_env(policy), &call, &options.harness))
        }
        other => Err(crate::Error::Malformed {
            what: "command line".to_string(),
            why: format!("unknown command `{other}`\n\n{USAGE}"),
        }),
    }
}

fn decision(guard: &Guard, call: &crate::ToolCall, harness: &str) -> Run {
    match guard.check(call) {
        Decision::Allow => Run {
            code: ALLOW,
            stdout: String::new(),
            stderr: String::new(),
        },
        Decision::Deny(denial) => {
            // The tool name is for the person reading the log; the rule is for whoever has to
            // decide whether the policy or the request was wrong. One text, both channels: a harness
            // reading the verdict off stdout gets the same words as the log does.
            let reason = format!("{} refused: {denial}", call.tool);
            Run {
                code: BLOCK,
                stdout: harness::verdict(harness, &reason).unwrap_or_default(),
                stderr: format!("{reason}\n"),
            }
        }
    }
}

fn printed(text: &str) -> Run {
    Run {
        code: ALLOW,
        stdout: text.to_string(),
        stderr: String::new(),
    }
}

/// The parsed command line.
struct Options {
    command: String,
    harness: String,
    policy: Option<PathBuf>,
    guard: Option<String>,
    help: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut options = Self {
            // No arguments is a check: that is how a hook invokes it, and a hook that silently
            // printed usage instead of deciding would be a hole.
            command: "check".to_string(),
            harness: "neutral".to_string(),
            policy: None,
            guard: None,
            help: false,
        };
        let mut rest = args.iter();
        let mut positional_seen = false;
        while let Some(arg) = rest.next() {
            let mut value = |flag: &str| -> Result<String> {
                rest.next().cloned().ok_or_else(|| crate::Error::Malformed {
                    what: "command line".to_string(),
                    why: format!("{flag} needs a value"),
                })
            };
            match arg.as_str() {
                "-h" | "--help" => options.help = true,
                "--harness" => options.harness = value("--harness")?,
                "--policy" => options.policy = Some(PathBuf::from(value("--policy")?)),
                "--guard" => options.guard = Some(value("--guard")?),
                flag if flag.starts_with('-') => {
                    return Err(crate::Error::Malformed {
                        what: "command line".to_string(),
                        why: format!("unknown option `{flag}`"),
                    });
                }
                positional if positional_seen => {
                    return Err(crate::Error::Malformed {
                        what: "command line".to_string(),
                        why: format!("unexpected argument `{positional}`"),
                    });
                }
                positional => {
                    options.command = positional.to_string();
                    positional_seen = true;
                }
            }
        }
        Ok(options)
    }
}

#[cfg(test)]
mod tests {
    use super::{ALLOW, BLOCK, Run, run};

    fn invoke(args: &[&str], stdin: &str) -> Run {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        run(&args, || Ok(stdin.to_string()))
    }

    #[test]
    fn a_permitted_call_exits_zero_and_says_nothing() {
        let outcome = invoke(
            &["check"],
            r#"{"tool":"read","intents":[{"kind":"read","value":"src/lib.rs"}]}"#,
        );
        assert_eq!(
            outcome,
            Run {
                code: ALLOW,
                stdout: String::new(),
                stderr: String::new()
            }
        );
    }

    #[test]
    fn a_denied_call_exits_two_and_names_the_rule() {
        let outcome = invoke(
            &["check"],
            r#"{"tool":"read","intents":[{"kind":"read","value":"/root/.ssh/id_rsa"}]}"#,
        );
        assert_eq!(outcome.code, BLOCK);
        assert!(
            outcome.stderr.contains("read refused"),
            "{}",
            outcome.stderr
        );
        assert!(
            outcome.stderr.contains("private-keys"),
            "{}",
            outcome.stderr
        );
    }

    #[test]
    fn no_arguments_at_all_still_decides() {
        // How a hook with a bare command line invokes it.
        let outcome = invoke(
            &[],
            r#"{"tool":"shell","intents":[{"kind":"command","value":"passwd"}]}"#,
        );
        assert_eq!(outcome.code, BLOCK);
    }

    #[test]
    fn a_harness_payload_is_translated_before_it_is_judged() {
        let outcome = invoke(
            &["check", "--harness", "claude-code"],
            r#"{"tool_name":"Bash","tool_input":{"command":"mkfs.ext4 /dev/sdb"}}"#,
        );
        assert_eq!(outcome.code, BLOCK);
        assert!(
            outcome.stderr.contains("filesystem-format"),
            "{}",
            outcome.stderr
        );
    }

    /// The envelope a runtime that reads its verdict from stdout actually sends.
    fn envelope(tool: &str, input: &str) -> String {
        format!(
            r#"{{"hook_event_name":"pre_tool_call","tool_name":"{tool}","tool_input":{input},
                 "session_id":"s1","cwd":"/w","extra":{{}}}}"#
        )
    }

    /// The block directive, as that runtime parses it back off stdout.
    fn directive(stdout: &str) -> serde_json::Value {
        serde_json::from_str(stdout).expect("stdout is one JSON object")
    }

    #[test]
    fn a_block_is_said_on_stdout_when_that_is_where_the_harness_reads_it() {
        // The failure this guards against: that runtime parses stdout and treats empty stdout as no
        // opinion, whatever the exit code was. Exit 2 and silence is an adapter that looks installed
        // and enforces nothing.
        let outcome = invoke(
            &["check", "--harness", "hermes"],
            &envelope("terminal", r#"{"command":"cat ~/.ssh/id_rsa"}"#),
        );
        assert_eq!(outcome.code, BLOCK);
        let said = directive(&outcome.stdout);
        assert_eq!(said["decision"], "block");
        assert!(
            said["reason"]
                .as_str()
                .expect("a reason")
                .contains("private-keys"),
            "{said}"
        );
        // stderr still carries it too: the log and the runtime read the same words.
        assert!(
            outcome.stderr.contains("private-keys"),
            "{}",
            outcome.stderr
        );
    }

    #[test]
    fn a_payload_that_harness_could_not_send_is_blocked_on_stdout_as_well() {
        // The likeliest block of all — the wrong `--harness`, a renamed field, arguments that were
        // not a mapping — and the one that would otherwise be delivered only as an exit code the
        // runtime does not read.
        for payload in [
            r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
            r#"{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":null}"#,
            "not json at all",
        ] {
            let outcome = invoke(&["check", "--harness", "hermes"], payload);
            assert_eq!(outcome.code, BLOCK, "{payload}");
            assert_eq!(directive(&outcome.stdout)["decision"], "block", "{payload}");
        }
    }

    #[test]
    fn a_permitted_call_leaves_that_harness_no_opinion_to_read() {
        let outcome = invoke(
            &["check", "--harness", "hermes"],
            &envelope("read_file", r#"{"path":"Cargo.toml"}"#),
        );
        assert_eq!(outcome.code, ALLOW);
        assert!(outcome.stdout.is_empty(), "{}", outcome.stdout);
    }

    #[test]
    fn a_command_line_mistake_under_that_harness_is_still_only_a_log_line() {
        // `emit` writes config to stdout, so a refusal must not be mixed into it. Only `check` is
        // answering a runtime that reads stdout.
        let outcome = invoke(
            &["emit", "--harness", "hermes", "--policy", "/nonexistent"],
            "",
        );
        assert_eq!(outcome.code, BLOCK);
        assert!(outcome.stdout.is_empty(), "{}", outcome.stdout);
    }

    #[test]
    fn emit_writes_the_hook_fragment_for_that_harness() {
        let outcome = invoke(&["emit", "--harness", "hermes"], "");
        assert_eq!(outcome.code, ALLOW);
        assert!(
            outcome.stdout.contains("pre_tool_call:"),
            "{}",
            outcome.stdout
        );
        assert!(
            outcome
                .stdout
                .contains(r#"- command: "harness-guard check --harness hermes""#),
            "{}",
            outcome.stdout
        );
    }

    #[test]
    fn a_payload_that_will_not_parse_is_blocked_not_waved_through() {
        let outcome = invoke(&["check"], "{ not json");
        assert_eq!(outcome.code, BLOCK);
        assert!(
            outcome.stderr.contains("malformed tool call"),
            "{}",
            outcome.stderr
        );
    }

    #[test]
    fn unreadable_stdin_is_blocked() {
        let outcome = run(&["check".to_string()], || {
            Err(std::io::Error::other("pipe closed"))
        });
        assert_eq!(outcome.code, BLOCK);
        assert!(
            outcome.stderr.contains("cannot read policy stdin")
                || outcome.stderr.contains("pipe closed"),
            "{}",
            outcome.stderr
        );
    }

    #[test]
    fn an_unloadable_policy_blocks_rather_than_falling_back_to_the_built_in_one() {
        // A guard that quietly substitutes a different policy is enforcing something nobody wrote.
        let outcome = invoke(&["check", "--policy", "/nonexistent/policy.json"], "{}");
        assert_eq!(outcome.code, BLOCK);
        assert!(
            outcome.stderr.contains("cannot read policy"),
            "{}",
            outcome.stderr
        );
    }

    #[test]
    fn a_policy_from_a_file_is_the_one_enforced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tool-policy.json");
        std::fs::write(
            &path,
            r#"{"version":1,"secret_paths":[{"id":"local","reason":"local rule","patterns":["**/*.local"]}]}"#,
        )
        .expect("write");
        let policy = path.to_string_lossy().to_string();

        let allowed = invoke(
            &["check", "--policy", &policy],
            r#"{"tool":"read","intents":[{"kind":"read","value":"/root/.ssh/id_rsa"}]}"#,
        );
        let blocked = invoke(
            &["check", "--policy", &policy],
            r#"{"tool":"read","intents":[{"kind":"read","value":"notes.local"}]}"#,
        );

        assert_eq!(
            allowed.code, ALLOW,
            "the file's policy replaces the built-in one"
        );
        assert_eq!(blocked.code, BLOCK);
        assert!(blocked.stderr.contains("local rule"), "{}", blocked.stderr);
    }

    #[test]
    fn emit_prints_a_harness_config_without_reading_stdin() {
        let outcome = run(
            &[
                "emit".to_string(),
                "--harness".to_string(),
                "claude-code".to_string(),
            ],
            || panic!("emit must not read stdin"),
        );
        assert_eq!(outcome.code, ALLOW);
        assert!(outcome.stdout.contains("PreToolUse"), "{}", outcome.stdout);
        assert!(
            outcome
                .stdout
                .contains("harness-guard check --harness claude-code"),
            "{}",
            outcome.stdout
        );
    }

    #[test]
    fn emit_uses_the_guard_command_it_was_given() {
        let outcome = invoke(
            &[
                "emit",
                "--harness",
                "claude-code",
                "--guard",
                "/opt/bin/guard check",
            ],
            "",
        );
        assert!(
            outcome.stdout.contains("/opt/bin/guard check"),
            "{}",
            outcome.stdout
        );
    }

    #[test]
    fn help_is_printed_on_request_and_exits_zero() {
        let outcome = invoke(&["--help"], "");
        assert_eq!(outcome.code, ALLOW);
        assert!(outcome.stdout.contains("exit codes: 0 allowed, 2 blocked"));
    }

    #[test]
    fn a_command_line_mistake_is_blocked_and_explained() {
        for (args, expected) in [
            (vec!["chek"], "unknown command `chek`"),
            (vec!["check", "--nope"], "unknown option `--nope`"),
            (vec!["check", "--harness"], "--harness needs a value"),
            (vec!["check", "extra"], "unexpected argument `extra`"),
            (
                vec!["check", "--harness", "emacs"],
                "unknown harness `emacs`",
            ),
        ] {
            let outcome = invoke(&args, "{}");
            assert_eq!(outcome.code, BLOCK, "{args:?}");
            assert!(
                outcome.stderr.contains(expected),
                "{args:?}: {}",
                outcome.stderr
            );
        }
    }
}
