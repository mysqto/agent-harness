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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    /// The harness's name for the tool, carried for reporting only — decisions come from intents, so
    /// renaming a tool cannot change what is allowed.
    pub tool: String,
    /// Everything this call would do. All of them are checked; the first denial wins.
    #[serde(default)]
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
    fn intents_are_optional_so_an_unknown_tool_is_expressible() {
        let call = ToolCall::parse(r#"{"tool":"ping"}"#).expect("parse");
        assert!(call.intents.is_empty());
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
