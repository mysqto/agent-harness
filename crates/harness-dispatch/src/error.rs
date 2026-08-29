//! Dispatch failures.

use thiserror::Error;

/// Result alias for dispatch operations.
pub type Result<T> = std::result::Result<T, Error>;

/// What can go wrong dispatching.
#[derive(Debug, Error)]
pub enum Error {
    /// No registered agent declares this intent.
    #[error("no agent handles intent `{0}`")]
    Unroutable(String),
    /// Two or more agents claim the same intent, so the choice would be arbitrary.
    #[error("intent `{intent}` is claimed by more than one agent: {agents}")]
    Ambiguous {
        /// The contested intent.
        intent: String,
        /// The competing agents, comma separated.
        agents: String,
    },
    /// Refused because the task mutates and the context was incomplete.
    ///
    /// Carries both halves of the reason. A refusal is the one outcome an operator has to act on,
    /// and "refused" on its own makes them go and reconstruct what was refused and what was missing.
    #[error(
        "refused `{intent}`: cannot act on partial context; omitted: {}",
        reasons(omitted)
    )]
    RefusedDegraded {
        /// The intent that was refused.
        intent: String,
        /// What the context bundle was missing, and why, as the store reported it.
        omitted: Vec<String>,
    },
    /// Refused because the handler said it cannot work.
    ///
    /// A refusal rather than a degrade, and the asymmetry with a degraded bundle is the point:
    /// context that arrives incomplete still yields an answer that can say what it could not see,
    /// while a worker that cannot be reached yields either silence or somebody else's answer under
    /// that worker's name. The second is worse than no answer, because afterwards it is
    /// indistinguishable from a real one.
    #[error("refused `{intent}`: worker `{worker}` is unavailable: {reason}")]
    Unreachable {
        /// The intent that was refused.
        intent: String,
        /// The worker that reported itself unable to work.
        worker: String,
        /// What it said, verbatim.
        reason: String,
    },
    /// Refused because the route did not carry an argument the worker declared it needs.
    ///
    /// The composer's mistake, named where it happened. Invoking anyway would turn one missing key
    /// into a worker-side failure that names nothing, and `args` is the one part of a route with no
    /// schema behind it — so a declaration the dispatcher checks is the only thing standing there.
    #[error("refused `{intent}`: worker `{worker}` needs {}, which the route did not carry", missing.join(", "))]
    Underspecified {
        /// The intent that was refused.
        intent: String,
        /// The worker that would have run it.
        worker: String,
        /// The argument keys it declared and did not receive.
        missing: Vec<String>,
    },
    /// A route and a handout that do not belong together.
    ///
    /// Either could be right on its own; what cannot be allowed is a worker running one decision
    /// over another decision's context, because every record it writes would then cite a bundle
    /// that never reached it.
    #[error("route `{route_id}` cannot run against bundle `{bundle_id}`: {detail}")]
    Mismatched {
        /// The decision that was to be run.
        route_id: String,
        /// The handout it was handed.
        bundle_id: String,
        /// Which way the pair disagreed.
        detail: String,
    },
    /// The agent itself failed.
    #[error(transparent)]
    Agent(#[from] harness_agent::Error),
}

/// The omissions as one phrase.
///
/// A store may report a bundle as partial without saying what it left out, and an empty list would
/// otherwise render as a message that trails off mid-sentence.
fn reasons(omitted: &[String]) -> String {
    if omitted.is_empty() {
        "not stated".to_string()
    } else {
        omitted.join("; ")
    }
}
