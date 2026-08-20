//! The built-in echo agent.

use harness_agent::{Agent, AgentId, Capability, Context, Egress, Outcome, Result, Status, Task};

/// Sends a message back where it came from, and nothing else.
///
/// Deliberately trivial. It exists for two reasons: it is a reference implementation of [`Agent`]
/// small enough to read in one sitting, and it proves adapter → dispatcher → agent → delivery is
/// wired up without needing a real agent, a real source or a memory service. It reaches for
/// nothing, records nothing, and names no destination — an empty egress target means "wherever this
/// came from", which the dispatcher resolves.
pub struct Echo {
    id: AgentId,
    capabilities: Vec<Capability>,
}

impl Echo {
    /// The name this agent registers under, and the intent it claims.
    pub const ID: &'static str = "echo";

    /// An echo agent.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: AgentId(Self::ID.to_string()),
            capabilities: vec![Capability {
                intent: Self::ID.to_string(),
                // Nothing changes anywhere, so context is never load-bearing here.
                mutating: false,
            }],
        }
    }
}

impl Default for Echo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Agent for Echo {
    fn id(&self) -> &AgentId {
        &self.id
    }

    fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    async fn handle(&self, task: Task, _ctx: &dyn Context) -> Result<Outcome> {
        // Routing should make this impossible; failing loudly if it happens is how a routing bug
        // stays visible instead of turning into an odd reply.
        if task.intent != Self::ID {
            return Err(harness_agent::Error::Unsupported(task.intent));
        }
        let body = task
            .args
            .get("text")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        Ok(Outcome {
            status: Status::Succeeded,
            egress: vec![Egress {
                target: String::new(),
                text: spoken(body),
                thread: None,
            }],
            records: Vec::new(),
        })
    }
}

/// The part of the body worth echoing.
///
/// The dispatcher passes the whole body through, intent word included, because what the words mean
/// is the agent's business. This agent's reading is "everything after my name", so `echo hello`
/// answers `hello` rather than repeating the command back.
fn spoken(body: &str) -> String {
    let trimmed = body.trim();
    trimmed
        .strip_prefix(Echo::ID)
        .map_or(trimmed, str::trim_start)
        .to_string()
}

#[cfg(test)]
mod tests {
    use harness_agent::{Agent, AgentId, Context, Health, Status};

    use super::Echo;
    use crate::fixtures::{StubContext, task};

    #[tokio::test]
    async fn it_echoes_the_body_after_its_own_name() {
        let outcome = Echo::new()
            .handle(task("echo", "echo hello"), &StubContext::new())
            .await
            .expect("handle");

        assert_eq!(outcome.status, Status::Succeeded);
        assert_eq!(outcome.egress.len(), 1);
        assert_eq!(outcome.egress[0].text, "hello");
        assert_eq!(
            outcome.egress[0].target, "",
            "an empty target lets the dispatcher choose the reply path"
        );
        assert!(outcome.records.is_empty());
    }

    #[tokio::test]
    async fn a_body_that_is_only_the_intent_echoes_nothing() {
        let outcome = Echo::new()
            .handle(task("echo", "  echo  "), &StubContext::new())
            .await
            .expect("handle");
        assert_eq!(outcome.egress[0].text, "");
    }

    #[tokio::test]
    async fn a_body_without_the_intent_word_is_echoed_whole() {
        // Reached when an adapter states the intent in `extra` rather than in the text.
        let outcome = Echo::new()
            .handle(task("echo", "ticket t-9 needs a look"), &StubContext::new())
            .await
            .expect("handle");
        assert_eq!(outcome.egress[0].text, "ticket t-9 needs a look");
    }

    #[tokio::test]
    async fn a_body_that_is_missing_entirely_is_not_a_panic() {
        let mut task = task("echo", "echo hi");
        task.args.remove("text");
        let outcome = Echo::new()
            .handle(task, &StubContext::new())
            .await
            .expect("handle");
        assert_eq!(outcome.egress[0].text, "");
    }

    #[tokio::test]
    async fn a_misrouted_intent_is_reported_rather_than_answered() {
        let error = Echo::new()
            .handle(task("summarise", "summarise it"), &StubContext::new())
            .await
            .expect_err("misrouted");
        assert_eq!(error.to_string(), "unsupported intent `summarise`");
    }

    #[tokio::test]
    async fn an_agent_is_exercisable_with_no_infrastructure_at_all() {
        // The reason `Context` is a trait: everything an agent may reach is four methods, and a
        // stub supplies all of them. No socket, no store, no clock.
        let ctx = StubContext::new();
        assert_eq!(ctx.correlation_id(), "t-1");
        assert!(!ctx.is_degraded());
        assert!(ctx.remaining_ms() > 0);
        assert!(
            ctx.memory()
                .history("order_ref", "ord-91h2", 5, ctx.remaining_ms())
                .await
                .expect("history")
                .is_empty()
        );
        ctx.memory()
            .record(harness_agent::ActionDraft {
                action: "echo".into(),
                outcome: Status::Succeeded,
                attrs: std::collections::BTreeMap::new(),
                entities: Vec::new(),
                summary: "echoed".into(),
            })
            .await
            .expect("record");
    }

    #[tokio::test]
    async fn it_declares_one_non_mutating_intent_and_is_ready() {
        let agent = Echo::default();
        assert_eq!(agent.id(), &AgentId("echo".into()));
        assert_eq!(agent.capabilities().len(), 1);
        assert_eq!(agent.capabilities()[0].intent, "echo");
        assert!(!agent.capabilities()[0].mutating);
        assert_eq!(agent.health().await, Health::Ready);
    }
}
