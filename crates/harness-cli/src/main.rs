//! Command-line entry point.
//!
//! Two modes, and the second exists because of how development actually goes: `run` serves a
//! dispatcher, and `once` feeds a single envelope from stdin and prints the result, so an agent can
//! be exercised without standing anything up.

#![forbid(unsafe_code)]

fn main() {
    eprintln!("harness: not yet implemented");
    std::process::exit(1);
}
