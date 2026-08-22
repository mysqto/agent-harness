//! One declared tool policy, one guard that enforces it, one generator per harness.
//!
//! This is layers 1 and 2 of the plan's layered defence, built so they cannot drift apart: the
//! policy in `spec/tool-policy.json` is the only place a rule is written, a harness's own
//! allow/deny config is *generated* from it (layer 1), and the [`Guard`] evaluates the same document
//! at the tool-call boundary (layer 2).
//!
//! The two layers are independent on purpose. Layer 1 is whatever the harness can express and is
//! trivially bypassed by a harness that was never configured; layer 2 is a process that exits
//! non-zero, needs no model in the loop, and assumes nothing about layer 1 having run. Defence in
//! depth is the whole reason both exist, so nothing here is conditional on the other having worked.
//!
//! ```
//! use harness_policy::{Guard, Intent, Policy, ToolCall};
//!
//! let guard = Guard::from_env(Policy::baseline().expect("the shipped policy parses"));
//! let call = ToolCall::new("shell", Intent::Command("cat ~/.ssh/id_rsa".into()));
//! assert!(guard.check(&call).is_deny());
//! ```

#![forbid(unsafe_code)]

pub mod call;
pub mod cli;
pub mod command;
pub mod error;
pub mod eval;
pub mod fspath;
pub mod glob;
pub mod harness;
pub mod policy;

pub use call::{Intent, ToolCall};
pub use error::{Error, Result};
pub use eval::{Decision, Denial, Guard};
pub use policy::Policy;
