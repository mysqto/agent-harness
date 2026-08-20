//! What an agent produces.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How a task turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Did what was asked.
    Succeeded,
    /// Attempted and did not succeed.
    Failed,
    /// Partly done; the outcome says what remains.
    Partial,
    /// Deliberately not done.
    Declined,
}

/// A message an agent wants delivered.
///
/// The agent describes it; the dispatcher sends it. Nothing here names a transport, so the same
/// outcome can be delivered to a chat, a webhook or a terminal without the agent knowing which.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Egress {
    /// Opaque destination, meaningful to the adapter that will deliver it.
    pub target: String,
    /// Plain-text body. Adapters may render it richer.
    pub text: String,
    /// Thread or conversation to attach to, if the target supports one.
    pub thread: Option<String>,
}

/// A record the agent wants written to memory.
///
/// A draft, not a record: the dispatcher stamps identity, timing and attribution, so an agent
/// cannot attribute an action to someone else or backdate one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionDraft {
    /// What was done.
    pub action: String,
    /// How it went.
    pub outcome: Status,
    /// Declared, classified attributes.
    pub attrs: BTreeMap<String, serde_json::Value>,
    /// Entities this action touched, as `(kind, id)`.
    pub entities: Vec<(String, String)>,
    /// Prose for the record body.
    pub summary: String,
}

/// The result of handling a task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    /// How it went.
    pub status: Status,
    /// Messages to deliver.
    pub egress: Vec<Egress>,
    /// Records to write.
    pub records: Vec<ActionDraft>,
}

impl Outcome {
    /// A successful outcome with nothing to say and nothing to record.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            status: Status::Succeeded,
            egress: Vec::new(),
            records: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ActionDraft, Egress, Outcome, Status};

    #[test]
    fn ok_is_empty_and_successful() {
        let outcome = Outcome::ok();
        assert_eq!(outcome.status, Status::Succeeded);
        assert!(outcome.egress.is_empty());
        assert!(outcome.records.is_empty());
    }

    #[test]
    fn outcome_survives_a_json_round_trip() {
        // The dispatcher may hand an outcome across a process boundary, so the wire form has to be
        // lossless for every field an agent can set.
        let outcome = Outcome {
            status: Status::Partial,
            egress: vec![Egress {
                target: "stdout".into(),
                text: "two of three done".into(),
                thread: Some("t-1".into()),
            }],
            records: vec![ActionDraft {
                action: "summarise".into(),
                outcome: Status::Partial,
                attrs: [("count".to_string(), serde_json::json!(2))]
                    .into_iter()
                    .collect(),
                entities: vec![("order_ref".into(), "ord-91h2".into())],
                summary: "summarised two".into(),
            }],
        };
        let text = serde_json::to_string(&outcome).expect("serialise");
        assert_eq!(
            serde_json::from_str::<Outcome>(&text).expect("parse"),
            outcome
        );
    }

    #[test]
    fn status_serialises_in_snake_case() {
        // Adapters in other languages match on these strings, so the casing is part of the contract.
        assert_eq!(
            serde_json::to_string(&Status::Succeeded).unwrap(),
            "\"succeeded\""
        );
        assert_eq!(
            serde_json::to_string(&Status::Declined).unwrap(),
            "\"declined\""
        );
    }
}
