//! The dispatcher.
//!
//! It owns four things agents deliberately do not: deduplication, routing, the decision about
//! whether it is safe to act on incomplete context, and delivery. The last is the one worth being
//! strict about — because only the dispatcher can deliver, an egress filter is a property of the
//! system rather than something each agent has to remember.
//!
//! Deduplication and delivery both need somewhere to remember what has already happened, so a
//! [`Dispatcher`] owns both ledgers and is assembled once with the registry, the store and the one
//! courier it may post through. Keeping that state in an instance rather than in a process-global is
//! what lets two dispatchers share a process without sharing either ledger.

#![forbid(unsafe_code)]

pub mod egress;
pub mod error;
pub mod registry;
pub mod route;

#[cfg(test)]
mod fixtures;

pub use error::{Error, Result};
pub use registry::Registry;
pub use route::{ContextStore, Dispatched, Dispatcher};
