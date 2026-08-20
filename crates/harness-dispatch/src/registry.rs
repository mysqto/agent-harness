//! Which agent handles what.

use std::sync::Arc;

use harness_agent::{Agent, AgentId};

/// The set of agents available to dispatch.
#[derive(Default)]
pub struct Registry {
    agents: Vec<Arc<dyn Agent>>,
}

// Hand written: `Arc<dyn Agent>` cannot be derived through, and without `Debug` a caller cannot
// `expect_err` on a registry it failed to build. The identities are the only part worth printing.
impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("agents", &self.ids())
            .finish()
    }
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self { agents: Vec::new() }
    }

    /// Registers an agent.
    ///
    /// Rejects a second agent claiming an intent already claimed: silently preferring one would
    /// make routing depend on registration order, which is the kind of behaviour that changes when
    /// someone reorders a config file.
    pub fn register(&mut self, agent: Arc<dyn Agent>) -> crate::Result<()> {
        // Every intent is checked before anything is stored, so a rejected registration leaves the
        // registry as it was rather than half applied.
        for capability in agent.capabilities() {
            if let Some(other) = self.claimant(&capability.intent) {
                return Err(crate::Error::Ambiguous {
                    intent: capability.intent.clone(),
                    agents: format!("{}, {}", other.id().0, agent.id().0),
                });
            }
        }
        self.agents.push(agent);
        Ok(())
    }

    /// Finds the agent for an intent.
    pub fn resolve(&self, intent: &str) -> crate::Result<&Arc<dyn Agent>> {
        // The single match is guaranteed rather than picked: `register` refused the second claimant,
        // so no order-dependent choice is left to make here.
        self.claimant(intent)
            .ok_or_else(|| crate::Error::Unroutable(intent.to_string()))
    }

    /// The registered agent claiming `intent`, if any.
    fn claimant(&self, intent: &str) -> Option<&Arc<dyn Agent>> {
        self.agents
            .iter()
            .find(|agent| agent.capabilities().iter().any(|c| c.intent == intent))
    }

    /// Identities of every registered agent.
    #[must_use]
    pub fn ids(&self) -> Vec<AgentId> {
        self.agents.iter().map(|a| a.id().clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use harness_agent::AgentId;

    use super::Registry;
    use crate::Error;
    use crate::fixtures::RecordingAgent;

    #[test]
    fn a_new_registry_holds_nothing() {
        assert!(Registry::new().ids().is_empty());
        assert!(Registry::default().ids().is_empty());
    }

    #[test]
    fn a_registered_agent_resolves_for_every_intent_it_claims() {
        let mut registry = Registry::new();
        let agent = Arc::new(
            RecordingAgent::new("reader", &[("summarise", false)]).with_intent("explain", false),
        );
        registry.register(agent).expect("register");

        for intent in ["summarise", "explain"] {
            assert_eq!(
                registry.resolve(intent).expect("resolve").id(),
                &AgentId("reader".into())
            );
        }
        assert_eq!(registry.ids(), vec![AgentId("reader".into())]);
    }

    #[test]
    fn a_second_agent_claiming_one_intent_is_ambiguous() {
        // Preferring either one would make routing depend on registration order.
        let mut registry = Registry::new();
        registry
            .register(Arc::new(RecordingAgent::new(
                "reader",
                &[("summarise", false)],
            )))
            .expect("register");
        let error = registry
            .register(Arc::new(RecordingAgent::new(
                "other",
                &[("summarise", false)],
            )))
            .expect_err("second claim on one intent");

        assert!(matches!(error, Error::Ambiguous { ref intent, .. } if intent == "summarise"));
        assert_eq!(
            error.to_string(),
            "intent `summarise` is claimed by more than one agent: reader, other"
        );
        assert_eq!(
            registry.ids(),
            vec![AgentId("reader".into())],
            "a rejected registration must not be half applied"
        );
    }

    #[test]
    fn a_clash_on_a_later_intent_still_rejects_the_whole_agent() {
        let mut registry = Registry::new();
        registry
            .register(Arc::new(RecordingAgent::new("writer", &[("apply", true)])))
            .expect("register");
        registry
            .register(Arc::new(
                RecordingAgent::new("mixed", &[("summarise", false)]).with_intent("apply", true),
            ))
            .expect_err("clash on the second capability");

        assert_eq!(registry.ids(), vec![AgentId("writer".into())]);
        assert!(matches!(
            registry.resolve("summarise"),
            Err(Error::Unroutable(_))
        ));
    }

    #[test]
    fn a_registry_names_the_agents_it_holds_when_printed() {
        // The point of the impl: a failure involving a registry can say which agents were in it.
        let mut registry = Registry::new();
        registry
            .register(Arc::new(RecordingAgent::new(
                "reader",
                &[("summarise", false)],
            )))
            .expect("register");

        assert_eq!(
            format!("{registry:?}"),
            "Registry { agents: [AgentId(\"reader\")] }"
        );
    }

    #[test]
    fn an_unclaimed_intent_is_unroutable() {
        let error = Registry::new()
            .resolve("summarise")
            .err()
            .expect("nothing registered");

        assert!(matches!(error, Error::Unroutable(ref intent) if intent == "summarise"));
        assert_eq!(error.to_string(), "no agent handles intent `summarise`");
    }
}
