//! Inbound work, normalised.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A stable agent identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

/// One unit of dispatched work.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId(pub String);

/// Something an agent declares it can handle. The dispatcher matches intents against these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Intent name, e.g. `summarise`.
    pub intent: String,
    /// Whether handling this intent changes state somewhere.
    ///
    /// Declared by the agent and used by the dispatcher to decide whether partial context is
    /// tolerable, so an agent cannot quietly mutate under a read-shaped intent.
    pub mutating: bool,
}

/// Who or what caused this task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// Source-scoped identifier of the actor.
    pub id: String,
    /// Which source it came from.
    pub source: String,
}

/// A task handed to an agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    /// Identity of this task.
    pub task_id: TaskId,
    /// Ties every stage of one interaction together, across adapters and agents.
    pub correlation_id: String,
    /// What is being asked for.
    pub intent: String,
    /// Arguments, already normalised by the dispatcher.
    pub args: BTreeMap<String, serde_json::Value>,
    /// Whether this task changes state.
    ///
    /// Set from the matched capability. An agent may read it, but the dispatcher has already used
    /// it — a mutating task is refused before it reaches an agent when context is incomplete.
    pub mutating: bool,
    /// Who caused it, when known. Absent for scheduled or system-originated work.
    pub actor: Option<Actor>,
}

#[cfg(test)]
mod tests {
    use super::{Actor, Capability, Task, TaskId};

    fn task() -> Task {
        Task {
            task_id: TaskId("t-1".into()),
            correlation_id: "env-1".into(),
            intent: "summarise".into(),
            args: [("id".to_string(), serde_json::json!("ord-91h2"))]
                .into_iter()
                .collect(),
            mutating: false,
            actor: Some(Actor {
                id: "u-1".into(),
                source: "cli".into(),
            }),
        }
    }

    #[test]
    fn task_survives_a_json_round_trip() {
        let text = serde_json::to_string(&task()).expect("serialise");
        assert_eq!(serde_json::from_str::<Task>(&text).expect("parse"), task());
    }

    #[test]
    fn a_task_with_no_actor_is_valid() {
        // Scheduled and system-originated work has no actor; the field is optional on purpose.
        let mut t = task();
        t.actor = None;
        let text = serde_json::to_string(&t).expect("serialise");
        assert_eq!(
            serde_json::from_str::<Task>(&text).expect("parse").actor,
            None
        );
    }

    #[test]
    fn capability_declares_whether_it_mutates() {
        let cap = Capability {
            intent: "refund".into(),
            mutating: true,
        };
        let text = serde_json::to_string(&cap).expect("serialise");
        assert!(
            serde_json::from_str::<Capability>(&text)
                .expect("parse")
                .mutating
        );
    }
}
