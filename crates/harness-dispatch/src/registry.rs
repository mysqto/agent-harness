//! Which handler handles what.
//!
//! One table, two kinds of handler. An [`Agent`] and a [`crate::Worker`] are routed to by the same
//! rule — the single claimant of an intent — and that rule is written once here rather than twice,
//! because two routing tables that agree today are two routing tables that can stop agreeing.

use std::sync::Arc;

use harness_agent::{Agent, AgentId, Capability};

/// What routing needs of a handler, whichever interface it implements.
///
/// Deliberately not spelled `id` and `capabilities`: those are the names both handler traits
/// already use, and a second trait offering the same names would make `handler.id()` ambiguous at
/// every call site that has this one in scope.
pub trait Routable {
    /// Stable identity of the handler.
    fn handler_id(&self) -> &AgentId;

    /// The intents it claims.
    fn claims(&self) -> &[Capability];
}

impl Routable for dyn Agent {
    fn handler_id(&self) -> &AgentId {
        Agent::id(self)
    }

    fn claims(&self) -> &[Capability] {
        Agent::capabilities(self)
    }
}

/// The set of handlers available to route to.
///
/// Defaults to agents, so `Registry` written on its own still means what it meant before workers
/// existed and every caller spelling it that way is untouched.
pub struct Registry<H: ?Sized = dyn Agent> {
    handlers: Vec<Arc<H>>,
}

// Hand written because a derive would demand `Default` of a type parameter that is not sized. There
// is nothing to default about a handler in any case; the empty registry is the whole meaning.
impl<H: ?Sized> Default for Registry<H> {
    fn default() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }
}

// Hand written: `Arc<dyn Agent>` cannot be derived through, and without `Debug` a caller cannot
// `expect_err` on a registry it failed to build. The identities are the only part worth printing.
impl<H: ?Sized + Routable> std::fmt::Debug for Registry<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("handlers", &self.ids())
            .finish()
    }
}

impl<H: ?Sized + Routable> Registry<H> {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Registers a handler.
    ///
    /// Rejects a second handler claiming an intent already claimed: silently preferring one would
    /// make routing depend on registration order, which is the kind of behaviour that changes when
    /// someone reorders a config file.
    pub fn register(&mut self, handler: Arc<H>) -> crate::Result<()> {
        // Every intent is checked before anything is stored, so a rejected registration leaves the
        // registry as it was rather than half applied.
        for capability in handler.claims() {
            if let Some(other) = self.claimant(&capability.intent) {
                return Err(crate::Error::Ambiguous {
                    intent: capability.intent.clone(),
                    agents: format!("{}, {}", other.handler_id().0, handler.handler_id().0),
                });
            }
        }
        self.handlers.push(handler);
        Ok(())
    }

    /// Finds the handler for an intent.
    pub fn resolve(&self, intent: &str) -> crate::Result<&Arc<H>> {
        // The single match is guaranteed rather than picked: `register` refused the second claimant,
        // so no order-dependent choice is left to make here.
        self.claimant(intent)
            .ok_or_else(|| crate::Error::Unroutable(intent.to_string()))
    }

    /// The registered handler claiming `intent`, if any.
    fn claimant(&self, intent: &str) -> Option<&Arc<H>> {
        self.handlers
            .iter()
            .find(|handler| handler.claims().iter().any(|c| c.intent == intent))
    }

    /// Identities of every registered handler.
    #[must_use]
    pub fn ids(&self) -> Vec<AgentId> {
        self.handlers
            .iter()
            .map(|handler| handler.handler_id().clone())
            .collect()
    }

    /// Whether the handler claiming `intent` declares that it changes state.
    ///
    /// `false` when nothing claims it — not a judgement about the intent, since the caller has
    /// either resolved already or is about to fail to.
    #[must_use]
    pub fn mutates(&self, intent: &str) -> bool {
        self.claimant(intent).is_some_and(|handler| {
            handler
                .claims()
                .iter()
                .any(|c| c.intent == intent && c.mutating)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use harness_agent::AgentId;

    use super::Registry;
    use crate::Error;
    use crate::fixtures::{RecordingAgent, RecordingWorker};

    #[test]
    fn a_new_registry_holds_nothing() {
        let empty: Registry = Registry::new();
        assert!(empty.ids().is_empty());
        let defaulted: Registry = Registry::default();
        assert!(defaulted.ids().is_empty());
    }

    #[test]
    fn a_registered_agent_resolves_for_every_intent_it_claims() {
        let mut registry: Registry = Registry::new();
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
        let mut registry: Registry = Registry::new();
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
        let mut registry: Registry = Registry::new();
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
        let mut registry: Registry = Registry::new();
        registry
            .register(Arc::new(RecordingAgent::new(
                "reader",
                &[("summarise", false)],
            )))
            .expect("register");

        assert_eq!(
            format!("{registry:?}"),
            "Registry { handlers: [AgentId(\"reader\")] }"
        );
    }

    #[test]
    fn an_unclaimed_intent_is_unroutable() {
        let empty: Registry = Registry::new();
        let error = empty
            .resolve("summarise")
            .err()
            .expect("nothing registered");

        assert!(matches!(error, Error::Unroutable(ref intent) if intent == "summarise"));
        assert_eq!(error.to_string(), "no agent handles intent `summarise`");
    }

    #[test]
    fn a_worker_registry_routes_by_the_same_one_claimant_rule() {
        // The reason `Registry` is generic: if workers had their own table, this rule could drift
        // out of step with the one agents are routed by, and nothing would say so.
        let mut workers = crate::Workers::new();
        workers
            .register(Arc::new(RecordingWorker::new(
                "lookup",
                &[("summarise", false)],
            )))
            .expect("register");
        let error = workers
            .register(Arc::new(RecordingWorker::new(
                "other",
                &[("summarise", false)],
            )))
            .expect_err("second claim on one intent");

        assert!(matches!(error, Error::Ambiguous { ref intent, .. } if intent == "summarise"));
        assert_eq!(
            workers.resolve("summarise").expect("resolve").id(),
            &AgentId("lookup".into())
        );
        assert!(matches!(
            workers.resolve("explain"),
            Err(Error::Unroutable(_))
        ));
    }

    #[test]
    fn a_registry_reports_which_intents_change_state() {
        // Read by the dispatcher before it composes anything, so the answer for an intent nothing
        // claims has to be a plain `false` rather than a panic on an unwrap.
        let mut registry: Registry = Registry::new();
        registry
            .register(Arc::new(
                RecordingAgent::new("mixed", &[("summarise", false)]).with_intent("apply", true),
            ))
            .expect("register");

        assert!(registry.mutates("apply"));
        assert!(!registry.mutates("summarise"));
        assert!(!registry.mutates("nobody-claims-this"));
    }
}
