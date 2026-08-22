//! The egress screen: what a message may not carry out of the process.
//!
//! One job, and the position it runs from is the whole of it. A screen applies to the **rendered**
//! message — the finished bytes, immediately before they are handed to a transport — because a
//! secret reaches an outbound message by being interpolated into it. A check on the structured
//! fields, or on the template, runs before the value the template pulls in exists, and passes.
//!
//! Two properties follow from that position and are what the tests hold to:
//!
//! - **A clean message is unchanged**, byte for byte. Screening is not a reformatting pass.
//! - **A masked message comes back with an account** — [`Screened::masked`] names every span taken
//!   and the rule that took it. The caller is told what it actually sent. Masking and reporting
//!   nothing would leave a caller believing it sent what it wrote, which is worse than not masking:
//!   the operator who needs to rotate a leaked key never learns that it leaked.
//!
//! The pattern set is [data](Policy), not code. Credential shapes change on their issuers'
//! schedules, so the list lives in `spec/egress-screen.toml`, is compiled in as the shipped default
//! so the screen is on before anything is configured, and is replaceable from disk by a deployment
//! that needs a different one.
//!
//! ```
//! use harness_screen::Screen;
//!
//! let screened = Screen::shipped().screen("token xoxb-000000000000-secret please");
//! assert_eq!(screened.text(), "token [redacted:chat-token] please");
//! assert_eq!(screened.masked()[0].rule, "chat-token");
//! ```

#![forbid(unsafe_code)]

pub mod error;
pub mod policy;
pub mod screen;

pub use error::{Error, Result};
pub use policy::{Class, Policy, Rule};
pub use screen::{Masked, Screen, Screened};
