//! The harness-neutral shape of a tool call.
//!
//! Every harness describes a tool call differently, so the guard is written against this and each
//! harness gets a translator (`crate::harness`). Adding a harness is one translator; it never
//! touches the policy or the evaluator.

use serde::{Deserialize, Serialize};

/// What a tool call is asking the machine to do.
///
/// Four intents, because those are the four things the policy has an opinion about. A tool that does
/// none of them produces no intents and is allowed — this is a denylist, and layers 4 and 5 of the
/// plan's §10.2 are what stand behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Intent {
    /// Read the contents of a path.
    Read(String),
    /// Create, modify or remove a path.
    Write(String),
    /// Run a shell command line.
    Command(String),
    /// Reach a URL over the network.
    Fetch(String),
}

/// One tool call, normalised.
///
/// `deny_unknown_fields`, and `intents` is required rather than defaulted, because both defaults were
/// a way for this guard to allow everything quietly. A payload carrying a `tool` and a body this shape
/// does not name — the wrong `--harness`, or a harness that renamed a field — parsed into zero intents,
/// and zero intents is nothing to deny. The dangerous call sat in the payload unexamined and the guard
/// exited 0. Absence of intents is now a failure to understand the call, which blocks; an explicitly
/// empty list is still a call that does nothing, which does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    /// The harness's name for the tool, carried for reporting only — decisions come from intents, so
    /// renaming a tool cannot change what is allowed.
    pub tool: String,
    /// Everything this call would do. All of them are checked; the first denial wins.
    pub intents: Vec<Intent>,
}

impl ToolCall {
    /// A call with a single intent.
    #[must_use]
    pub fn new(tool: &str, intent: Intent) -> Self {
        Self {
            tool: tool.to_string(),
            intents: vec![intent],
        }
    }

    /// Parses a call from the neutral JSON shape.
    pub fn parse(text: &str) -> crate::Result<Self> {
        serde_json::from_str(text).map_err(|why| crate::Error::Malformed {
            what: "tool call".to_string(),
            why: why.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    /// A payload this shape cannot read must block, not allow.
    ///
    /// The regression: `intents` was defaulted and unknown fields were ignored, so a claude-code
    /// payload fed to the neutral reader parsed into a `ToolCall` with no intents. Nothing to deny
    /// meant exit 0, and the command it carried was never looked at.
    #[test]
    fn a_payload_this_shape_cannot_read_is_not_an_empty_call() {
        for payload in [
            r#"{"tool":"shell","input":{"command":"cat /etc/shadow"}}"#,
            r#"{"tool":"Bash","input":{"command":"rm -rf /"}}"#,
            r#"{"tool":"shell"}"#,
        ] {
            assert!(
                ToolCall::parse(payload).is_err(),
                "a call this shape cannot read must be refused, not read as doing nothing: {payload}"
            );
        }
    }

    #[test]
    fn a_call_that_genuinely_does_nothing_is_still_readable() {
        // The other half: an explicit empty list is a call with nothing to check, which is not the
        // same as a call this shape failed to understand.
        let call = ToolCall::parse(r#"{"tool":"shell","intents":[]}"#).expect("readable");
        assert!(call.intents.is_empty());
    }

    use super::{Intent, ToolCall};

    #[test]
    fn the_neutral_shape_round_trips() {
        let call = ToolCall {
            tool: "shell".to_string(),
            intents: vec![
                Intent::Command("ls".to_string()),
                Intent::Read("/etc/hosts".to_string()),
            ],
        };
        let json = serde_json::to_string(&call).expect("serialise");
        assert_eq!(ToolCall::parse(&json).expect("parse"), call);
    }

    #[test]
    fn a_tool_with_nothing_to_check_says_so_explicitly() {
        // Was: `intents` defaulted, so `{"tool":"ping"}` parsed as a call doing nothing. That made a
        // tool with nothing to check indistinguishable from a payload this shape could not read, and
        // the second of those must block. An empty list expresses the first just as well.
        let call = ToolCall::parse(r#"{"tool":"ping","intents":[]}"#).expect("parse");
        assert!(call.intents.is_empty());
        assert!(
            ToolCall::parse(r#"{"tool":"ping"}"#).is_err(),
            "an absent `intents` is a call that was not understood"
        );
    }

    #[test]
    fn a_call_that_is_not_json_is_refused() {
        let error = ToolCall::parse("{").expect_err("parse fails");
        assert!(
            error.to_string().starts_with("malformed tool call:"),
            "{error}"
        );
    }

    #[test]
    fn a_single_intent_call_names_its_tool() {
        let call = ToolCall::new("read", Intent::Read("/tmp/x".to_string()));
        assert_eq!(call.tool, "read");
        assert_eq!(call.intents, vec![Intent::Read("/tmp/x".to_string())]);
    }
}
