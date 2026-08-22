//! Glue for a harness that describes a tool call as a name plus an input object, and configures
//! tool permissions in a settings file.
//!
//! Nothing in here decides anything. It renames fields on the way in and renders patterns on the way
//! out; every refusal still comes from the policy.

use serde_json::{Map, Value, json};

use crate::call::{Intent, ToolCall};
use crate::error::{Error, Result};
use crate::policy::Policy;

/// Input fields that name a path.
const PATH_FIELDS: [&str; 3] = ["file_path", "notebook_path", "path"];

/// Translates a pre-tool-use payload into the neutral shape.
///
/// Intents come from the *fields present*, not from a table of known tools: a harness that adds a
/// tool tomorrow still gets its `command` or `file_path` checked. An unrecognised tool naming a path
/// is treated as writing to it, because guessing "read" on an unknown tool is the guess that fails
/// open.
pub fn translate(payload: &str) -> Result<ToolCall> {
    let root: Value = serde_json::from_str(payload).map_err(|why| Error::Malformed {
        what: "hook payload".to_string(),
        why: why.to_string(),
    })?;
    let tool = root
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let empty = Map::new();
    let input = root
        .get("tool_input")
        .and_then(Value::as_object)
        .unwrap_or(&empty);

    let mut intents = Vec::new();
    if let Some(command) = input.get("command").and_then(Value::as_str) {
        intents.push(Intent::Command(command.to_string()));
    }
    if let Some(url) = input.get("url").and_then(Value::as_str) {
        intents.push(Intent::Fetch(url.to_string()));
    }
    let reads = READ_TOOLS.contains(&tool.as_str());
    for field in PATH_FIELDS {
        if let Some(path) = input.get(field).and_then(Value::as_str) {
            intents.push(if reads {
                Intent::Read(path.to_string())
            } else {
                Intent::Write(path.to_string())
            });
        }
    }
    Ok(ToolCall { tool, intents })
}

/// Tools whose named path is only read.
const READ_TOOLS: [&str; 4] = ["Read", "Grep", "Glob", "NotebookRead"];

/// Renders the harness's settings file: the deny list (layer 1) and the hook wiring (layer 2).
///
/// Two rules cannot be expressed here and are left to the hook rather than approximated:
/// containment of writes to the workspace (a deny list cannot say "everywhere except"), and the
/// egress allowlist (same shape, one level up). What *is* expressible is emitted exactly.
pub fn settings(policy: &Policy, guard_command: &str) -> Result<String> {
    let mut deny = Vec::new();
    for rule in &policy.secret_paths {
        for pattern in &rule.patterns {
            deny.push(json!(format!("Read({})", path_spec(pattern))));
            deny.push(json!(format!("Write({})", path_spec(pattern))));
        }
    }
    for rule in &policy.protected_paths {
        for pattern in &rule.patterns {
            deny.push(json!(format!("Write({})", path_spec(pattern))));
        }
    }
    for rule in &policy.commands {
        for program in &rule.programs {
            deny.push(json!(format!("Bash({program}:*)")));
        }
    }
    let allow: Vec<Value> = policy
        .network
        .allow_hosts
        .iter()
        .map(|host| json!(format!("WebFetch(domain:{host})")))
        .collect();

    let settings = json!({
        "permissions": { "deny": deny, "allow": allow },
        "hooks": {
            "PreToolUse": [{
                "matcher": "*",
                "hooks": [{ "type": "command", "command": guard_command }]
            }]
        }
    });
    serde_json::to_string_pretty(&settings).map_err(|why| Error::Malformed {
        what: "settings".to_string(),
        why: why.to_string(),
    })
}

/// Renders a policy pattern in the harness's path syntax.
///
/// Absolute paths take a second leading slash and workspace-relative ones a `./`, which is how this
/// harness distinguishes them. A `**` glob needs no translation.
fn path_spec(pattern: &str) -> String {
    if let Some(rest) = pattern.strip_prefix("${workspace}/") {
        return format!("./{rest}");
    }
    if pattern.starts_with('/') {
        return format!("/{pattern}");
    }
    pattern.to_string()
}

#[cfg(test)]
mod tests {
    use super::{path_spec, settings, translate};
    use crate::call::Intent;
    use crate::policy::Policy;

    #[test]
    fn a_shell_tool_becomes_a_command_intent() {
        let call = translate(r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#)
            .expect("translate");
        assert_eq!(call.tool, "Bash");
        assert_eq!(call.intents, vec![Intent::Command("rm -rf /".to_string())]);
    }

    #[test]
    fn a_read_tool_becomes_a_read_and_a_write_tool_a_write() {
        let read = translate(r#"{"tool_name":"Read","tool_input":{"file_path":"/srv/a"}}"#)
            .expect("translate");
        assert_eq!(read.intents, vec![Intent::Read("/srv/a".to_string())]);

        for tool in [
            "Write",
            "Edit",
            "MultiEdit",
            "NotebookEdit",
            "SomeFutureEditor",
        ] {
            let call = translate(&format!(
                r#"{{"tool_name":"{tool}","tool_input":{{"file_path":"/srv/a"}}}}"#
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
    fn an_unknown_tool_naming_a_path_is_treated_as_writing_to_it() {
        // The conservative guess. The other one fails open.
        let call = translate(r#"{"tool_name":"SomethingNew","tool_input":{"path":"/srv/a"}}"#)
            .expect("translate");
        assert_eq!(call.intents, vec![Intent::Write("/srv/a".to_string())]);
    }

    #[test]
    fn a_fetch_tool_becomes_a_fetch_intent() {
        let call = translate(r#"{"tool_name":"WebFetch","tool_input":{"url":"https://h.test/x"}}"#)
            .expect("translate");
        assert_eq!(
            call.intents,
            vec![Intent::Fetch("https://h.test/x".to_string())]
        );
    }

    #[test]
    fn a_payload_with_nothing_the_policy_cares_about_yields_no_intents() {
        let call =
            translate(r#"{"tool_name":"TodoWrite","tool_input":{"todos":[]}}"#).expect("translate");
        assert!(call.intents.is_empty());
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
            r#"{"tool_name":"Bash","tool_input":{"command":"cat x","url":"https://h.test","file_path":"/srv/a"}}"#,
        )
        .expect("translate");
        assert_eq!(call.intents.len(), 3);
    }

    #[test]
    fn the_generated_settings_deny_the_policys_paths_and_programs() {
        let rendered = settings(
            &Policy::baseline().expect("baseline"),
            "harness-guard check --harness claude-code",
        )
        .expect("settings");

        for expected in [
            "\"Read(~/.ssh/**)\"",
            "\"Write(~/.bashrc)\"",
            "\"Bash(passwd:*)\"",
            "\"Write(//etc/systemd/**)\"",
            "\"WebFetch(domain:127.0.0.1)\"",
            "harness-guard check --harness claude-code",
            "PreToolUse",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected}:\n{rendered}"
            );
        }
    }

    #[test]
    fn the_generated_settings_are_valid_json_with_the_hook_wired_once() {
        let rendered = settings(&Policy::baseline().expect("baseline"), "guard").expect("settings");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        let hooks = parsed["hooks"]["PreToolUse"]
            .as_array()
            .expect("hook array");
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["hooks"][0]["command"], "guard");
    }

    #[test]
    fn path_syntax_distinguishes_absolute_workspace_and_glob_patterns() {
        assert_eq!(path_spec("/etc/**"), "//etc/**");
        assert_eq!(path_spec("${workspace}/out/**"), "./out/**");
        assert_eq!(path_spec("~/.ssh/**"), "~/.ssh/**");
        assert_eq!(path_spec("**/.env"), "**/.env");
    }
}
