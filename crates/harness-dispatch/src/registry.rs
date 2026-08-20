//! Which agent handles what.

use std::sync::Arc;

use harness_agent::{Agent, AgentId};

/// The set of agents available to dispatch.
#[derive(Default)]
pub struct Registry {
    agents: Vec<Arc<dyn Agent>>,
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
    pub fn register(&mut self, _agent: Arc<dyn Agent>) -> crate::Result<()> {
        todo!("reject duplicate intents")
    }

    /// Finds the agent for an intent.
    pub fn resolve(&self, _intent: &str) -> crate::Result<&Arc<dyn Agent>> {
        todo!("single match or Unroutable")
    }

    /// Identities of every registered agent.
    #[must_use]
    pub fn ids(&self) -> Vec<AgentId> {
        self.agents.iter().map(|a| a.id().clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Registry;

    #[test]
    fn a_new_registry_holds_nothing() {
        assert!(Registry::new().ids().is_empty());
        assert!(Registry::default().ids().is_empty());
    }
}
