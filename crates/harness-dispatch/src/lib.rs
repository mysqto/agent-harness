//! The dispatcher.
//!
//! It owns four things agents deliberately do not: deduplication, routing, the decision about
//! whether it is safe to act on incomplete context, and delivery. The last is the one worth being
//! strict about — because only the dispatcher can deliver, an egress filter is a property of the
//! system rather than something each agent has to remember.

#![forbid(unsafe_code)]

pub mod egress;
pub mod error;
pub mod registry;
pub mod route;

pub use error::{Error, Result};
pub use registry::Registry;
