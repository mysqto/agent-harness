//! Per-harness glue, kept apart from everything that decides anything.
//!
//! A harness contributes exactly two functions and no policy: a **translator** from its tool-call
//! payload into [`crate::ToolCall`] (feeding layer 2, the hook), and a **generator** that writes its
//! own allow/deny config from the declared policy (layer 1). Adding a harness is one module here plus
//! one directory under `harnesses/`; it changes no rule and no decision.
//!
//! Generators are lossy in one direction only. A harness config that cannot express a rule simply
//! omits it — the hook still enforces it — but a generator must never emit an *allow* the policy does
//! not grant. That asymmetry is what lets layer 1 be a convenience and layer 2 be the control.

pub mod claude_code;

use crate::call::ToolCall;
use crate::error::{Error, Result};
use crate::policy::Policy;

/// Harness names this build knows.
///
/// `neutral` is the harness-agnostic shape from [`crate::call`]: any harness can adopt the guard by
/// emitting that JSON instead of contributing a translator.
pub const KNOWN: [&str; 2] = ["neutral", "claude-code"];

/// Translates a harness's tool-call payload into the neutral shape.
pub fn translate(harness: &str, payload: &str) -> Result<ToolCall> {
    match harness {
        "neutral" => ToolCall::parse(payload),
        "claude-code" => claude_code::translate(payload),
        other => Err(Error::UnknownHarness(other.to_string())),
    }
}

/// Generates a harness's own tool allow/deny config — layer 1 — from the declared policy.
///
/// `guard_command` is how that harness should invoke the hook, so the generated config wires both
/// layers from one place and they cannot drift apart.
pub fn generate(harness: &str, policy: &Policy, guard_command: &str) -> Result<String> {
    match harness {
        // The policy itself is the config: a harness reading this needs no translation, which is the
        // point of keeping the source of truth harness-agnostic.
        "neutral" => serde_json::to_string_pretty(policy).map_err(|why| Error::Malformed {
            what: "policy".to_string(),
            why: why.to_string(),
        }),
        "claude-code" => claude_code::settings(policy, guard_command),
        other => Err(Error::UnknownHarness(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{KNOWN, generate, translate};
    use crate::call::Intent;
    use crate::policy::Policy;

    #[test]
    fn the_neutral_shape_needs_no_translation() {
        let call = translate(
            "neutral",
            r#"{"tool":"shell","intents":[{"kind":"command","value":"ls"}]}"#,
        )
        .expect("translate");
        assert_eq!(call.intents, vec![Intent::Command("ls".to_string())]);
    }

    #[test]
    fn the_neutral_generator_emits_the_policy_itself() {
        let policy = Policy::baseline().expect("baseline");
        let emitted = generate("neutral", &policy, "harness-guard").expect("generate");
        let round_tripped = Policy::parse(&emitted, "emitted").expect("parse");
        assert_eq!(round_tripped.secret_paths.len(), policy.secret_paths.len());
    }

    #[test]
    fn an_unknown_harness_is_refused_in_both_directions() {
        let policy = Policy::baseline().expect("baseline");
        assert_eq!(
            translate("emacs", "{}").expect_err("unknown").to_string(),
            "unknown harness `emacs`"
        );
        assert_eq!(
            generate("emacs", &policy, "harness-guard")
                .expect_err("unknown")
                .to_string(),
            "unknown harness `emacs`"
        );
    }

    #[test]
    fn every_known_harness_can_do_both_jobs() {
        let policy = Policy::baseline().expect("baseline");
        for harness in KNOWN {
            assert!(
                generate(harness, &policy, "harness-guard").is_ok(),
                "{harness} has no generator"
            );
        }
    }
}
