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
//!
//! There are two ways in, and they differ in one thing: what the handler is given.
//! [`Dispatcher::dispatch`] routes to an [`harness_agent::Agent`], which holds a context that can
//! read the store. [`Dispatcher::hand_off`] routes to a [`Worker`], which holds the [`Handout`] this
//! dispatcher composed and has no way to reach the store at all. Both take the same decision, and
//! both report it: a [`Route`] naming the worker, the bundle and the arguments, addressed so that
//! whoever receives it can check it rather than trust it.

#![forbid(unsafe_code)]

pub mod egress;
pub mod error;
pub mod registry;
pub mod route;
pub mod worker;

#[cfg(test)]
mod fixtures;

pub use error::{Error, Result};
pub use registry::{Registry, Routable};
pub use route::{ContextStore, Dispatched, Dispatcher};
pub use worker::{BUNDLE_VER, Handed, Handing, Handout, ROUTE_VER, Route, Worker, Workers};
