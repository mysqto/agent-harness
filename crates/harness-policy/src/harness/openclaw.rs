//! Glue for a harness that describes a tool call as a name plus a `params` object, gates shell
//! execution with an allowlist, and lets a plugin refuse a call before it runs.
//!
//! Nothing in here decides anything. It renames fields on the way in and renders settings on the way
//! out; every refusal still comes from the policy.
//!
//! This harness reaches the tool-call boundary through a plugin hook rather than a hook command, so
//! the generated config wires *where the guard lives* instead of a command line. What the harness
//! cannot express is left to the guard rather than approximated — see [`config`].
//!
//! What arrives at [`translate`] is the harness's *own* tool calls. Its relay has no adapter for the
//! `claude` CLI's tool events, so an agent shelling through that runtime's native tools never reaches
//! this translator at all, and no reading of the payload can widen that — a translator only sees what
//! it is handed. `harnesses/openclaw/README.md` says where that leaves the shell, and what covers it.

use serde_json::{Map, Value, json};

use crate::call::{Intent, ToolCall};
use crate::error::{Error, Result};
use crate::policy::Policy;

/// The plugin id the generated config enables.
///
/// Also the key under `plugins.entries`, so it has to match the plugin manifest's own `id` exactly
/// or the settings below configure a plugin that never loads.
pub const PLUGIN_ID: &str = "harness-tool-policy";

/// How long the plugin gives the guard to answer, in milliseconds.
///
/// Emitted rather than left to a default because this hook has *no* host-side default timeout: an
/// unbounded handler wedges the tool call for ever. It is not a policy rule — the policy says nothing
/// about how fast the guard answers — which is why it is a constant here and not read from the policy.
pub const GUARD_TIMEOUT_MS: u64 = 5_000;

/// Stands in for the directory the plugin is installed to, substituted by the installer.
///
/// The generator cannot know that path and must not guess one: a guessed path is a `load.paths` entry
/// pointing at nothing, which loads no plugin and reports no error.
pub const PLUGIN_DIR_PLACEHOLDER: &str = "${plugin_dir}";

/// The backend that runs an agent through Claude Code's own tool loop.
///
/// A constant because it is the backend a strict exec gate silences. That backend decides whether the
/// model may use its native tools at all by reading the gate as `security == "full" && ask == "off"`,
/// and every other shape refuses *each* native tool call outright rather than consulting an
/// allowlist. So the strict posture below cannot be emitted without also pinning this backend's argv.
pub const CLI_BACKEND: &str = "claude-cli";

/// The backend flag that pre-approves commands, compared with dashes, case and any `=value` removed.
const PRE_APPROVAL_FLAG: &str = "allowedtools";

/// `params` fields that carry a shell command line.
const COMMAND_FIELDS: [&str; 2] = ["command", "script"];

/// `toolKind` for a call whose payload is a program rather than a command line.
const CODE_MODE: &str = "code_mode_exec";

/// `params` fields that carry a URL.
const FETCH_FIELDS: [&str; 2] = ["url", "uri"];

/// `params` fields that name a single path.
const PATH_FIELDS: [&str; 4] = ["path", "file_path", "filePath", "target"];

/// Tools whose named path is only read.
///
/// Everything else naming a path is treated as writing to it, because guessing "read" on a tool this
/// build has not seen is the guess that fails open.
const READ_TOOLS: [&str; 6] = ["read", "grep", "glob", "list", "search", "memory_search"];

/// Translates one `before_tool_call` event into the neutral shape.
///
/// Intents come from the *fields present*, not from a table of known tools: a harness release that
/// adds a tool still gets its command, URL and paths checked. `derivedPaths` — the host's own
/// best-effort parse of a structured edit envelope — is folded in as writes, since it exists exactly
/// for the tools whose payload a generic field sweep cannot read.
///
/// A code-mode call is **refused outright**, not translated. The harness mirrors the program into the
/// same `command` field a shell call uses, so it looks translatable and is not: the policy is written
/// in terms of command lines, and reading a program as one gets the answer wrong in the dangerous
/// direction. `sh('cat ~/.ssh/id_rsa')` parses as the program `sh` with a quoted argument and is
/// permitted, while the shell line it builds would not be. Refusing is the only honest answer left —
/// a deployment that needs code mode has to describe code in the policy first.
pub fn translate(payload: &str) -> Result<ToolCall> {
    let root: Value = serde_json::from_str(payload).map_err(|why| Error::Malformed {
        what: "hook payload".to_string(),
        why: why.to_string(),
    })?;
    let tool = root
        .get("toolName")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let empty = Map::new();
    let params = root
        .get("params")
        .and_then(Value::as_object)
        .unwrap_or(&empty);

    if root.get("toolKind").and_then(Value::as_str) == Some(CODE_MODE) {
        return Err(Error::Undecidable {
            what: format!("a code-mode `{tool}` call"),
            why:
                "its payload is a program, and the policy describes command lines. Turn code mode \
                  off, or describe code in the policy"
                    .to_string(),
        });
    }

    let mut intents = Vec::new();
    for field in COMMAND_FIELDS {
        if let Some(command) = params.get(field).and_then(Value::as_str) {
            intents.push(Intent::Command(command.to_string()));
        }
    }
    for field in FETCH_FIELDS {
        if let Some(url) = params.get(field).and_then(Value::as_str) {
            intents.push(Intent::Fetch(url.to_string()));
        }
    }

    // Reads are named by the tool; anything else touching a path is assumed to write.
    let reads = READ_TOOLS.contains(&tool.to_ascii_lowercase().as_str());
    let mut paths = Vec::new();
    for field in PATH_FIELDS {
        match params.get(field) {
            Some(Value::String(path)) => paths.push(path.clone()),
            // `paths`-style fields arrive as arrays on the multi-file tools.
            Some(Value::Array(entries)) => paths.extend(
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string),
            ),
            _ => {}
        }
    }
    if let Some(Value::Array(entries)) = root.get("derivedPaths") {
        // Always writes: the host derives these for edit envelopes, and a lenient parse that we then
        // treated as a read would be a write nobody checked.
        for entry in entries.iter().filter_map(Value::as_str) {
            intents.push(Intent::Write(entry.to_string()));
        }
    }
    for path in paths {
        intents.push(if reads {
            Intent::Read(path)
        } else {
            Intent::Write(path)
        });
    }
    Ok(ToolCall { tool, intents })
}

/// Renders the fragment to merge into the harness's config file — layer 1, plus where layer 2 lives.
///
/// `guard_command` is split on whitespace into an argv the plugin spawns directly. A guard path
/// containing a space is therefore not supported here, and the alternative — handing the plugin a
/// string to re-split — would put argument parsing in the harness directory.
///
/// `backend_args` are argv words to pin on [`CLI_BACKEND`], and they decide whether layer 1 is
/// emitted at all. **The strict exec gate and the pre-approvals that make it survivable are emitted
/// as a pair, or neither is.** The gate alone is not a stricter version of this fragment, it is an
/// outage: on a host whose agents work through that backend, `security: allowlist` with `ask:
/// on-miss` fails the backend's `full`-and-`off` test and every native tool call is refused, so the
/// agent answers from recalled context and writes nothing. Nothing catches that — the config
/// validates, the policy renders as a tidy table, and the only symptom is work that never lands.
///
/// The generator cannot tell that host from one whose agents run through the harness's own `exec`
/// tool, where the same block is exactly right. So it emits only the shape that is safe on both:
/// with pre-approvals pinned, a command on that list never raises a permission request and so never
/// reaches the refusal; without them, layer 1 is left out and the deployment's existing exec posture
/// is untouched. Emitting less is the cheaper mistake, because layer 2 is the control and a fragment
/// that cannot be applied without disarming the agents is worse than one that says less.
///
/// Which commands to pre-approve is the deployment's knowledge and not the policy's — the policy
/// grants no programs, so an allowlist generated from it would be empty, which brings the outage
/// back by another route. Naming them is therefore the caller's job, and `backend_args` that name
/// nothing to pre-approve is refused rather than emitted: it is the bricked pairing spelled out at
/// length, and it is the one input for which silence would be indistinguishable from success.
///
/// What this cannot say, and why each is left to the guard rather than approximated:
///
/// - **Which programs are refused.** The harness gates shell execution with an *allowlist* of
///   command patterns, held in its host approvals file rather than this config, and it has no deny
///   list that inspects a command line. A deny policy does not translate into an allowlist, so what
///   layer 1 can carry is a posture and not a rule — and the guard is what actually reads the
///   policy's denied programs.
/// - **Secret and protected paths.** Nothing in this config file speaks about paths.
/// - **The egress allowlist.** Same shape one level up: there is no per-host gate to generate.
///
/// Everything else here is a settings key pointing at the guard.
pub fn config(policy: &Policy, guard_command: &str, backend_args: &[String]) -> Result<String> {
    let argv: Vec<Value> = guard_command
        .split_whitespace()
        .map(|word| json!(word))
        .collect();
    if argv.is_empty() {
        return Err(Error::Malformed {
            what: "guard command".to_string(),
            why: "empty — the plugin would have nothing to spawn".to_string(),
        });
    }

    let mut fragment = Map::new();

    if !backend_args.is_empty() {
        if !pre_approves(backend_args) {
            return Err(Error::Malformed {
                what: "cli backend args".to_string(),
                why: format!(
                    "nothing among {backend_args:?} pre-approves a command, so pinning them beside \
                     a strict exec gate would refuse every native tool call. Name the commands the \
                     agents need with --allowedTools, or pass no backend args and leave the exec \
                     gate to the deployment"
                ),
            });
        }
        // `security` and `ask` rather than the newer single `mode` key: the harness hard-rejects a
        // config carrying both spellings, and a deployment old enough to need this fragment already
        // has these two set. Emitting `mode` would make an existing config fail validation.
        fragment.insert(
            "tools".to_string(),
            json!({ "exec": { "security": "allowlist", "ask": "on-miss" } }),
        );
        // Pinned in the same breath as the gate, because this is what keeps the gate from being an
        // outage. On a host that does not use this backend the pin is an unused backend's argv; on a
        // host that does, it is the difference between a policy and a silence.
        fragment.insert(
            "agents".to_string(),
            json!({
                "defaults": { "cliBackends": { CLI_BACKEND: { "args": backend_args } } }
            }),
        );
    }

    fragment.insert(
        "plugins".to_string(),
        json!({
            // A placeholder rather than a path: where the plugin is installed is the installer's
            // knowledge, not the policy's, and `${…}` is how this repo's specs already say
            // "substituted at install time".
            "load": { "paths": [PLUGIN_DIR_PLACEHOLDER] },
            "entries": {
                PLUGIN_ID: {
                    "enabled": true,
                    // The operator-visible bound, and the one that wins: a hook timeout set here
                    // overrides what the plugin asks for. Kept at twice the plugin's own budget so
                    // the plugin still answers first, with a refusal that names the rule.
                    "hooks": { "timeouts": { "before_tool_call": GUARD_TIMEOUT_MS * 2 } },
                    "config": {
                        "guard": argv,
                        "timeoutMs": GUARD_TIMEOUT_MS,
                        // Recorded so a fragment generated against an older policy is visible in the
                        // config rather than only in whoever remembers when it was installed.
                        "policyVersion": policy.version,
                    }
                }
            }
        }),
    );

    serde_json::to_string_pretty(&Value::Object(fragment)).map_err(|why| Error::Malformed {
        what: "config fragment".to_string(),
        why: why.to_string(),
    })
}

/// Whether `args` pre-approve any command, which is the whole of what keeps a strict gate working.
///
/// Matched with dashes, case and any `=value` stripped, because refusing a correct pinning over its
/// spelling would send an operator looking for the shortest way past the refusal — and the shortest
/// way past it is to drop the pre-approvals and keep the gate, which is the outage this exists to
/// prevent.
fn pre_approves(args: &[String]) -> bool {
    args.iter().any(|word| {
        let flag = word.split('=').next().unwrap_or(word);
        let letters: String = flag.chars().filter(char::is_ascii_alphanumeric).collect();
        letters.eq_ignore_ascii_case(PRE_APPROVAL_FLAG)
    })
}

#[cfg(test)]
mod tests {
    use super::{PLUGIN_ID, config, translate};
    use crate::call::Intent;
    use crate::policy::Policy;

    fn baseline() -> Policy {
        Policy::baseline().expect("baseline")
    }

    /// One pre-approval, in the spelling an operator would actually write.
    fn pre_approved() -> Vec<String> {
        vec![
            "--allowedTools".to_string(),
            "Bash(git status:*),Read".to_string(),
        ]
    }

    #[test]
    fn an_exec_call_becomes_a_command_intent() {
        let call =
            translate(r#"{"toolName":"exec","params":{"command":"rm -rf /"}}"#).expect("translate");
        assert_eq!(call.tool, "exec");
        assert_eq!(call.intents, vec![Intent::Command("rm -rf /".to_string())]);
    }

    #[test]
    fn a_read_tool_becomes_a_read_and_everything_else_a_write() {
        let read =
            translate(r#"{"toolName":"read","params":{"path":"/srv/a"}}"#).expect("translate");
        assert_eq!(read.intents, vec![Intent::Read("/srv/a".to_string())]);

        for tool in ["write", "edit", "apply_patch", "SomeFutureEditor"] {
            let call = translate(&format!(
                r#"{{"toolName":"{tool}","params":{{"path":"/srv/a"}}}}"#
            ))
            .expect("translate");
            assert_eq!(
                call.intents,
                vec![Intent::Write("/srv/a".to_string())],
                "{tool}"
            );
        }
    }

    #[test]
    fn the_read_tool_table_ignores_case() {
        // The harness lowercases tool names in some surfaces and not others.
        let call =
            translate(r#"{"toolName":"Read","params":{"path":"/srv/a"}}"#).expect("translate");
        assert_eq!(call.intents, vec![Intent::Read("/srv/a".to_string())]);
    }

    #[test]
    fn derived_paths_are_writes_even_for_a_tool_that_only_reads() {
        // The host derives these for edit envelopes. Trusting the tool name over the host's own
        // parse would turn a lenient read into an unchecked write.
        let call = translate(
            r#"{"toolName":"read","params":{},"derivedPaths":["/etc/passwd","~/.bashrc"]}"#,
        )
        .expect("translate");
        assert_eq!(
            call.intents,
            vec![
                Intent::Write("/etc/passwd".to_string()),
                Intent::Write("~/.bashrc".to_string()),
            ]
        );
    }

    #[test]
    fn a_path_field_carrying_an_array_yields_one_intent_per_entry() {
        let call =
            translate(r#"{"toolName":"write","params":{"path":["a","b"]}}"#).expect("translate");
        assert_eq!(
            call.intents,
            vec![
                Intent::Write("a".to_string()),
                Intent::Write("b".to_string())
            ]
        );
    }

    #[test]
    fn a_fetch_tool_becomes_a_fetch_intent() {
        let call = translate(r#"{"toolName":"web_fetch","params":{"url":"https://h.test/x"}}"#)
            .expect("translate");
        assert_eq!(
            call.intents,
            vec![Intent::Fetch("https://h.test/x".to_string())]
        );
    }

    #[test]
    fn a_payload_missing_its_fields_still_translates() {
        let call = translate("{}").expect("translate");
        assert_eq!(call.tool, "unknown");
        assert!(call.intents.is_empty());
    }

    #[test]
    fn a_payload_that_is_not_json_is_refused() {
        let error = translate("not json").expect_err("refused");
        assert!(
            error.to_string().starts_with("malformed hook payload:"),
            "{error}"
        );
    }

    #[test]
    fn several_fields_in_one_call_all_become_intents() {
        let call = translate(
            r#"{"toolName":"exec","params":{"command":"cat x","url":"https://h.test","path":"/srv/a"}}"#,
        )
        .expect("translate");
        assert_eq!(call.intents.len(), 3);
    }

    #[test]
    fn the_translated_call_is_still_judged_by_the_policy() {
        // The point of the translator: an ordinary harness payload reaches a refusal.
        let guard = crate::eval::Guard::from_env(baseline());
        let call = translate(r#"{"toolName":"exec","params":{"command":"cat ~/.ssh/id_rsa"}}"#)
            .expect("translate");
        assert!(guard.check(&call).is_deny());
    }

    #[test]
    fn the_fragment_wires_the_plugin_wherever_layer_1_lands() {
        let rendered = config(
            &baseline(),
            "/opt/bin/harness-guard check --harness openclaw",
            &[],
        )
        .expect("config");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");

        let entry = &parsed["plugins"]["entries"][PLUGIN_ID];
        assert_eq!(entry["enabled"], true);
        assert_eq!(
            entry["config"]["guard"],
            serde_json::json!(["/opt/bin/harness-guard", "check", "--harness", "openclaw"]),
            "the guard is an argv, so the plugin spawns it without a shell"
        );
        assert_eq!(entry["config"]["policyVersion"], 1);
        assert_eq!(
            parsed["plugins"]["load"]["paths"],
            serde_json::json!([super::PLUGIN_DIR_PLACEHOLDER]),
            "the install path is the installer's to fill in"
        );
    }

    #[test]
    fn a_code_mode_payload_is_refused_because_no_rule_can_read_it() {
        // Reading a program as a command line answers wrongly in the dangerous direction: this
        // payload parses as the program `sh` with a quoted argument and would be *permitted*, while
        // the shell line it builds would not be. So it is refused rather than translated.
        let error = translate(
            r#"{"toolName":"exec","toolKind":"code_mode_exec","toolInputKind":"javascript",
                "params":{"command":"await sh('cat ~/.ssh/id_rsa')"}}"#,
        )
        .expect_err("refused");
        assert!(error.to_string().contains("code-mode"), "{error}");

        // The same text without the code-mode marker really is a command line, and is read as one.
        let call = translate(r#"{"toolName":"exec","params":{"command":"cat ~/.ssh/id_rsa"}}"#)
            .expect("translate");
        assert!(
            crate::eval::Guard::from_env(baseline())
                .check(&call)
                .is_deny()
        );
    }

    #[test]
    fn the_fragment_bounds_the_hook_because_the_harness_does_not() {
        // No host-side default exists for this hook, so an unbounded handler would wedge tool calls.
        let parsed: serde_json::Value =
            serde_json::from_str(&config(&baseline(), "guard", &[]).expect("config"))
                .expect("json");
        let entry = &parsed["plugins"]["entries"][PLUGIN_ID];
        let plugin_budget = entry["config"]["timeoutMs"]
            .as_u64()
            .expect("plugin budget");
        let host_budget = entry["hooks"]["timeouts"]["before_tool_call"]
            .as_u64()
            .expect("host budget");
        assert_eq!(plugin_budget, super::GUARD_TIMEOUT_MS);
        assert!(
            host_budget > plugin_budget,
            "the host would time out first, and its refusal names no rule"
        );
    }

    #[test]
    fn the_fragment_never_claims_a_command_deny_list_it_cannot_enforce() {
        // The harness's node deny list matches command *ids*, not shell text, so emitting the
        // policy's denied programs there would be entries that match nothing.
        let rendered = config(&baseline(), "guard", &pre_approved()).expect("config");
        assert!(
            !rendered.contains("denyCommands"),
            "emitted a deny list this harness cannot apply:\n{rendered}"
        );
        for program in ["passwd", "mkfs", "shutdown"] {
            assert!(
                !rendered.contains(program),
                "{program} appears in a fragment that cannot gate it:\n{rendered}"
            );
        }
    }

    #[test]
    fn the_exec_gate_is_left_out_when_no_command_is_pre_approved() {
        // The gate on its own is not a stricter fragment, it is an outage: the CLI backend reads
        // anything but `full`/`off` as "refuse every native tool call", and an agent that cannot act
        // still answers from recalled context, so nothing about the deployment looks broken.
        let rendered = config(&baseline(), "guard", &[]).expect("config");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        assert!(
            parsed.get("tools").is_none(),
            "an exec gate was emitted with nothing pre-approved:\n{rendered}"
        );
        assert!(
            parsed.get("agents").is_none(),
            "a backend was pinned with nothing to pin:\n{rendered}"
        );
        assert!(
            parsed["plugins"]["entries"][PLUGIN_ID]["enabled"] == true,
            "layer 2 went missing with layer 1:\n{rendered}"
        );
    }

    #[test]
    fn the_exec_gate_and_the_pre_approvals_that_survive_it_are_emitted_together() {
        // The pairing is the whole rule: a pre-approved command never raises a permission request,
        // so it never reaches the refusal the strict gate would otherwise hand every native call.
        let rendered = config(&baseline(), "guard", &pre_approved()).expect("config");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        assert_eq!(parsed["tools"]["exec"]["security"], "allowlist");
        assert_eq!(parsed["tools"]["exec"]["ask"], "on-miss");
        assert_eq!(
            parsed["agents"]["defaults"]["cliBackends"][super::CLI_BACKEND]["args"],
            serde_json::json!(["--allowedTools", "Bash(git status:*),Read"]),
            "the gate was emitted without the pinning that keeps the agents able to act"
        );
    }

    #[test]
    fn backend_args_that_pre_approve_nothing_are_refused_rather_than_paired_with_the_gate() {
        // The bricked pairing, spelled out. Emitting it would validate, render as a tidy policy, and
        // leave an agent that answers and never writes.
        let error = config(
            &baseline(),
            "guard",
            &["--dangerously-skip-updates".to_string()],
        )
        .expect_err("refused");
        assert!(error.to_string().contains("--allowedTools"), "{error}");
    }

    #[test]
    fn a_pre_approval_is_recognised_however_the_operator_spelled_it() {
        // Refusing a correct pinning over its spelling invites the one edit that brings the outage
        // back: drop the pre-approvals, keep the gate.
        for spelling in [
            "--allowedTools",
            "--allowed-tools",
            "--allowedTools=Bash(ls:*)",
            "--allowed_tools",
        ] {
            let rendered = config(&baseline(), "guard", &[spelling.to_string()]).expect(spelling);
            let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
            assert_eq!(
                parsed["tools"]["exec"]["security"], "allowlist",
                "{spelling} was not read as a pre-approval"
            );
        }
    }

    #[test]
    fn an_empty_guard_command_is_refused_rather_than_emitted() {
        // A fragment with nothing to spawn installs a layer 2 that never runs.
        let error = config(&baseline(), "   ", &[]).expect_err("refused");
        assert!(error.to_string().contains("guard command"), "{error}");
    }
}
