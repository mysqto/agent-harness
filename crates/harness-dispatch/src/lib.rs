//! The dispatcher.
//!
//! It owns four things agents deliberately do not: deduplication, routing, the decision about
//! whether it is safe to act on incomplete context, and delivery. The last is the one worth being
//! strict about — because only the dispatcher can deliver, an egress filter is a property of the
//! system rather than something each agent has to remember.
//!
//! Deduplication and delivery both need somewhere to remember what has already happened, so a
//! caller holds a [`Seen`] and an [`egress::Courier`] and passes them in. Keeping that state with
//! the caller rather than in a process-global is what lets two dispatchers share a process, and
//! what lets a test observe either ledger.

#![forbid(unsafe_code)]

pub mod egress;
pub mod error;
pub mod registry;
pub mod route;

#[cfg(test)]
mod fixtures;

pub use error::{Error, Result};
pub use registry::Registry;
pub use route::{ContextStore, Dispatched, Seen, dispatch};
