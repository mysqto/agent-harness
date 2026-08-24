//! Glue for a harness whose hook payload is a declared envelope and whose verdict is read from the
//! hook's stdout rather than from its exit code.
//!
//! Two differences from a harness that blocks on an exit code shape everything here.
//!
//! The envelope is *declared*: the runtime builds all six fields on every firing, so a payload
//! missing one came from something else — a different hook event, a different harness, a renamed
//! field — and reading it as a call with nothing to check is the failure in [`crate::call`] again.
//! Every such payload is refused instead.
//!
//! And the runtime decides from stdout. Empty or unparseable stdout means "no opinion", and it
//! reaches that conclusion whatever the exit code was. A guard that only exited non-zero would be a
//! hook that is installed, logs a warning nobody reads, and enforces nothing. That is what
//! [`verdict`] is for.

use serde_json::{Map, Value};

use crate::call::{Intent, ToolCall};
use crate::error::{Error, Result};
use crate::policy::Policy;

/// The only hook event this translator can read.
///
/// The runtime honours a block directive on this event alone, so a payload from another one is a
/// wiring mistake. Refused rather than allowed: the hook was asked a question it cannot answer.
const EVENT: &str = "pre_tool_call";

/// Seconds the hook is allowed before the runtime gives up on it.
///
/// A timed-out hook is read as having no opinion, so this is deliberately far above the guard's
/// runtime — the cost of waiting is a pause, the cost of timing out is an unchecked tool call.
const TIMEOUT: u32 = 30;

/// Input fields that name a path. Each may hold one path or a list of them.
///
/// Only `command` is named by the runtime's documented wire protocol; the rest are the field names its
/// file tools and the filesystem tools it exposes over MCP use. A field this list does not name
/// yields no intent, so extending it is how a new tool gets its paths checked.
const PATH_FIELDS: [&str; 7] = [
    "file_path",
    "path",
    "paths",
    "filename",
    "directory",
    "source",
    "destination",
];

/// Tools whose named paths are only read.
///
/// Taken from the runtime's own set of tools it considers side-effect free, so the two agree on which
/// calls change nothing. Anything absent from it that names a path is treated as writing to it —
/// guessing "read" for an unfamiliar tool is the guess that fails open.
const READ_TOOLS: [&str; 16] = [
    "read_file",
    "search_files",
    "web_search",
    "web_extract",
    "session_search",
    "browser_snapshot",
    "browser_console",
    "browser_get_images",
    "mcp_filesystem_read_file",
    "mcp_filesystem_read_text_file",
    "mcp_filesystem_read_multiple_files",
    "mcp_filesystem_list_directory",
    "mcp_filesystem_list_directory_with_sizes",
    "mcp_filesystem_directory_tree",
    "mcp_filesystem_get_file_info",
    "mcp_filesystem_search_files",
];

/// Translates a pre-tool-call payload into the neutral shape.
///
/// Strict about the envelope and about the fields it knows, lenient about the ones it does not: an
/// unrecognised field is a call this policy has no opinion on, while a *recognised* field holding a
/// shape this cannot read is a call it failed to understand, and those two answers differ.
pub fn translate(payload: &str) -> Result<ToolCall> {
    let root: Value = serde_json::from_str(payload).map_err(|why| Error::Malformed {
        what: "hook payload".to_string(),
        why: why.to_string(),
    })?;
    let root = root
        .as_object()
        .ok_or_else(|| refuse("payload is not an object"))?;

    let event = required_text(root, "hook_event_name")?;
    if event != EVENT {
        return Err(refuse(&format!(
            "hook event `{event}` is not `{EVENT}` — this guard decides tool calls and nothing else"
        )));
    }
    let tool = required_text(root, "tool_name")?;
    if tool.trim().is_empty() {
        return Err(refuse("`tool_name` is empty"));
    }

    // Present-but-not-an-object is the case worth being loud about: the runtime nulls this field
    // whenever the arguments are not a mapping, and a call whose arguments cannot be read is not a
    // call with no arguments.
    let input = root
        .get("tool_input")
        .ok_or_else(|| refuse("`tool_input` is missing"))?;
    let input = input.as_object().ok_or_else(|| {
        refuse("`tool_input` is not an object — a call whose arguments cannot be read is not a call with none")
    })?;

    let mut intents = Vec::new();
    if let Some(command) = optional_text(input, "command")? {
        intents.push(Intent::Command(command));
    }
    if let Some(url) = optional_text(input, "url")? {
        intents.push(Intent::Fetch(url));
    }
    let reads = READ_TOOLS.contains(&tool.as_str());
    for field in PATH_FIELDS {
        for path in path_list(input, field)? {
            intents.push(if reads {
                Intent::Read(path)
            } else {
                Intent::Write(path)
            });
        }
    }
    Ok(ToolCall { tool, intents })
}

/// Renders a refusal in the shape this harness parses from the hook's stdout.
///
/// The exit code is not what it reads, so this is the whole of the refusal as far as the runtime is
/// concerned. It accepts two spellings of the same directive and normalises them internally; this
/// emits the one the other harness in this repo already speaks, so one refusal text serves both.
#[must_use]
pub fn verdict(reason: &str) -> String {
    let directive = serde_json::json!({ "decision": "block", "reason": reason });
    format!("{directive}\n")
}

/// Renders the hook wiring — layer 2 — as a config fragment in the harness's own format.
///
/// There is no layer 1 to generate. What this runtime configures is which *hook scripts* may run, not
/// which tools the model may call, so there is no allow/deny list to write the policy into and every
/// rule is left to the hook. Per the contract in `harnesses/README.md` that is a generator omitting
/// what its harness cannot express, which is allowed; emitting an allow the policy does not grant is
/// not, and a fragment with no allow list emits none.
#[must_use]
pub fn hooks(policy: &Policy, guard_command: &str) -> String {
    let paths = policy.secret_paths.len() + policy.protected_paths.len();
    let commands = policy.commands.len();
    // A JSON string literal is a valid double-quoted YAML scalar, so this escapes a command
    // containing quotes, colons or backslashes without a YAML writer.
    let command = Value::String(guard_command.to_string());
    format!(
        "\
# Generated from the tool policy. Merge this into the config file rather than replacing it — that
# file holds credentials. Regenerate with `harness-guard emit --harness hermes`.
#
# Layer 2 only: this runtime has no tool allow/deny config to generate into, so the hook carries
# every rule alone: {paths} path rules, {commands} command rules, workspace containment, and the
# egress allowlist.
#
# No `matcher`, deliberately: a matcher narrows the hook to the tools it names and leaves every
# other tool unchecked.
hooks:
  pre_tool_call:
    - command: {command}
      timeout: {TIMEOUT}
"
    )
}

/// A payload this shape could not read. Every one of these blocks.
fn refuse(why: &str) -> Error {
    Error::Malformed {
        what: "hook payload".to_string(),
        why: why.to_string(),
    }
}

/// Reads a top-level envelope field that is always present when the runtime sent the payload.
fn required_text(root: &Map<String, Value>, field: &str) -> Result<String> {
    match root.get(field) {
        Some(Value::String(text)) => Ok(text.clone()),
        Some(other) => Err(refuse(&format!(
            "`{field}` is {}, not a string",
            kind(other)
        ))),
        None => Err(refuse(&format!("`{field}` is missing"))),
    }
}

/// Reads an input field this translator has an opinion about.
///
/// An explicit `null` is treated as absent: it carries no path, command or host, so there is nothing
/// to check and refusing it would only be a false positive.
fn optional_text(input: &Map<String, Value>, field: &str) -> Result<Option<String>> {
    match input.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(other) => Err(refuse(&format!(
            "`{field}` is {}, not a string",
            kind(other)
        ))),
    }
}

/// Reads a path field, which may hold one path or a list of them.
fn path_list(input: &Map<String, Value>, field: &str) -> Result<Vec<String>> {
    match input.get(field) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(path)) => Ok(vec![path.clone()]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(path) => Ok(path.clone()),
                other => Err(refuse(&format!(
                    "`{field}` lists {}, not a path",
                    kind(other)
                ))),
            })
            .collect(),
        Some(other) => Err(refuse(&format!(
            "`{field}` is {}, not a path or a list of them",
            kind(other)
        ))),
    }
}

/// Names a JSON shape for a refusal message.
fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::Array(_) => "a list",
        Value::Object(_) => "an object",
        // Every caller can use a string, so this is only ever asked about the other shapes.
        Value::String(_) => "a string",
    }
}

#[cfg(test)]
mod tests {
    use super::{hooks, translate, verdict};
    use crate::call::Intent;
    use crate::policy::Policy;

    /// Wraps a tool name and input in the envelope the runtime actually sends.
    fn payload(tool: &str, input: &str) -> String {
        format!(
            r#"{{"hook_event_name":"pre_tool_call","tool_name":"{tool}","tool_input":{input},
                 "session_id":"s1","cwd":"/w","extra":{{"turn_id":"t1"}}}}"#
        )
    }

    #[test]
    fn the_shell_tool_becomes_a_command_intent() {
        let call = translate(&payload("terminal", r#"{"command":"rm -rf /"}"#)).expect("translate");
        assert_eq!(call.tool, "terminal");
        assert_eq!(call.intents, vec![Intent::Command("rm -rf /".to_string())]);
    }

    #[test]
    fn a_read_tool_reads_and_everything_else_writes() {
        let read = translate(&payload("read_file", r#"{"path":"/srv/a"}"#)).expect("translate");
        assert_eq!(read.intents, vec![Intent::Read("/srv/a".to_string())]);

        for tool in ["write_file", "patch", "process", "some_future_tool"] {
            let call = translate(&payload(tool, r#"{"path":"/srv/a"}"#)).expect("translate");
            assert_eq!(
                call.intents,
                vec![Intent::Write("/srv/a".to_string())],
                "{tool}"
            );
        }
    }

    #[test]
    fn a_path_field_holding_a_list_yields_one_intent_per_path() {
        // The shape a multi-file read arrives in, and the one a single-path reader would miss.
        let call = translate(&payload(
            "mcp_filesystem_read_multiple_files",
            r#"{"paths":["/srv/a","/srv/b"]}"#,
        ))
        .expect("translate");
        assert_eq!(
            call.intents,
            vec![
                Intent::Read("/srv/a".to_string()),
                Intent::Read("/srv/b".to_string())
            ]
        );
    }

    #[test]
    fn a_move_names_both_of_its_paths_as_writes() {
        let call = translate(&payload(
            "mcp_filesystem_move_file",
            r#"{"source":"/srv/a","destination":"/srv/b"}"#,
        ))
        .expect("translate");
        assert_eq!(
            call.intents,
            vec![
                Intent::Write("/srv/a".to_string()),
                Intent::Write("/srv/b".to_string())
            ]
        );
    }

    #[test]
    fn a_fetching_tool_becomes_a_fetch_intent() {
        let call =
            translate(&payload("web_extract", r#"{"url":"https://h.test/x"}"#)).expect("translate");
        assert_eq!(
            call.intents,
            vec![Intent::Fetch("https://h.test/x".to_string())]
        );
    }

    #[test]
    fn several_fields_in_one_call_all_become_intents() {
        let call = translate(&payload(
            "terminal",
            r#"{"command":"cat x","url":"https://h.test","file_path":"/srv/a"}"#,
        ))
        .expect("translate");
        assert_eq!(
            call.intents,
            vec![
                Intent::Command("cat x".to_string()),
                Intent::Fetch("https://h.test".to_string()),
                Intent::Write("/srv/a".to_string()),
            ]
        );
    }

    #[test]
    fn a_call_with_nothing_the_policy_cares_about_yields_no_intents() {
        let call = translate(&payload("todo", r#"{"items":[]}"#)).expect("translate");
        assert!(call.intents.is_empty());
        let empty = translate(&payload("todo", "{}")).expect("translate");
        assert!(empty.intents.is_empty());
    }

    #[test]
    fn a_null_field_is_nothing_to_check_rather_than_a_refusal() {
        // It carries no path, command or host, so there is nothing to deny and refusing it would
        // only be a false positive.
        let call = translate(&payload(
            "read_file",
            r#"{"path":null,"command":null,"url":null}"#,
        ))
        .expect("translate");
        assert!(call.intents.is_empty());
    }

    #[test]
    fn a_payload_this_shape_cannot_read_is_refused_not_read_as_an_empty_call() {
        // Each of these once parsed into a call with no intents somewhere, and no intents is nothing
        // to deny. The dangerous call sits in the payload unexamined and the guard exits 0.
        for (broken, expected) in [
            // The other harness's payload shape, fed to this translator by the wrong --harness.
            (
                r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
                "`hook_event_name` is missing",
            ),
            // Arguments the runtime could not serialise as a mapping.
            (
                r#"{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":null}"#,
                "`tool_input` is not an object — a call whose arguments cannot be read is not a \
                 call with none",
            ),
            (
                r#"{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":"rm -rf /"}"#,
                "`tool_input` is not an object — a call whose arguments cannot be read is not a \
                 call with none",
            ),
            (
                r#"{"hook_event_name":"pre_tool_call","tool_name":"terminal"}"#,
                "`tool_input` is missing",
            ),
            // A hook wired to an event whose verdict means something else.
            (
                r#"{"hook_event_name":"post_tool_call","tool_name":"terminal","tool_input":{}}"#,
                "hook event `post_tool_call` is not `pre_tool_call` — this guard decides tool \
                 calls and nothing else",
            ),
            // A renamed or absent tool name.
            (
                r#"{"hook_event_name":"pre_tool_call","tool_input":{}}"#,
                "`tool_name` is missing",
            ),
            (
                r#"{"hook_event_name":"pre_tool_call","tool_name":7,"tool_input":{}}"#,
                "`tool_name` is a number, not a string",
            ),
            (
                r#"{"hook_event_name":null,"tool_name":"terminal","tool_input":{}}"#,
                "`hook_event_name` is null, not a string",
            ),
            (
                r#"{"hook_event_name":"pre_tool_call","tool_name":"  ","tool_input":{}}"#,
                "`tool_name` is empty",
            ),
            // A field this translator knows, holding a shape it cannot read.
            (
                r#"{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":["rm","-rf","/"]}}"#,
                "`command` is a list, not a string",
            ),
            (
                r#"{"hook_event_name":"pre_tool_call","tool_name":"web_extract","tool_input":{"url":42}}"#,
                "`url` is a number, not a string",
            ),
            (
                r#"{"hook_event_name":"pre_tool_call","tool_name":"read_file","tool_input":{"paths":["/srv/a",{"p":"/srv/b"}]}}"#,
                "`paths` lists an object, not a path",
            ),
            (
                r#"{"hook_event_name":"pre_tool_call","tool_name":"read_file","tool_input":{"path":true}}"#,
                "`path` is a boolean, not a path or a list of them",
            ),
            // Not an envelope at all.
            ("[]", "payload is not an object"),
        ] {
            let error = translate(broken).expect_err("refused").to_string();
            assert_eq!(error, format!("malformed hook payload: {expected}"));
        }
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
    fn a_refusal_is_rendered_in_the_shape_this_harness_reads_from_stdout() {
        // The whole reason this function exists: the runtime ignores the exit code here and reads
        // the verdict off stdout, so a block that says nothing on stdout is not a block.
        let rendered = verdict("terminal refused: blocked by private-keys");
        assert!(rendered.ends_with('\n'));
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        assert_eq!(parsed["decision"], "block");
        assert_eq!(
            parsed["reason"],
            "terminal refused: blocked by private-keys"
        );
    }

    #[test]
    fn a_refusal_containing_json_punctuation_is_still_one_readable_directive() {
        let rendered = verdict("shell refused: blocked by \"quoted\" rule (a\\b)\nsecond line");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        assert_eq!(parsed["decision"], "block");
        assert_eq!(
            parsed["reason"],
            "shell refused: blocked by \"quoted\" rule (a\\b)\nsecond line"
        );
    }

    #[test]
    fn the_generated_fragment_wires_the_hook_on_the_one_event_that_can_block() {
        let rendered = hooks(
            &Policy::baseline().expect("baseline"),
            "harness-guard check --harness hermes",
        );
        assert!(
            rendered.contains("hooks:\n  pre_tool_call:\n"),
            "{rendered}"
        );
        assert!(
            rendered.contains("- command: \"harness-guard check --harness hermes\"\n"),
            "{rendered}"
        );
        assert!(rendered.contains("timeout: 30\n"), "{rendered}");
        // A matcher would narrow the hook to the tools it names and leave the rest unchecked.
        assert!(!rendered.contains("matcher:"), "{rendered}");
    }

    #[test]
    fn the_generated_fragment_says_how_many_rules_the_hook_is_carrying_alone() {
        let policy = Policy::baseline().expect("baseline");
        let rendered = hooks(&policy, "guard");
        let paths = policy.secret_paths.len() + policy.protected_paths.len();
        assert!(
            rendered.contains(&format!("{paths} path rules")),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("{} command rules", policy.commands.len())),
            "{rendered}"
        );
    }

    #[test]
    fn a_guard_command_needing_quoting_survives_the_fragment() {
        let rendered = hooks(
            &Policy::baseline().expect("baseline"),
            r#"/opt/a b/guard check --policy "c:d""#,
        );
        assert!(
            rendered.contains("- command: \"/opt/a b/guard check --policy \\\"c:d\\\"\"\n"),
            "{rendered}"
        );
    }
}
