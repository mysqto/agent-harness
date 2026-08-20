//! Command-line entry point.
//!
//! Two modes, and the second exists because of how development actually goes: `run` serves a
//! dispatcher, and `once` feeds a single envelope from stdin and prints the result, so an agent can
//! be exercised without standing anything up.
//!
//! Argument parsing and an exit code, and nothing else: everything worth testing lives in the
//! library, because a binary-only crate cannot be unit tested.

#![forbid(unsafe_code)]

fn main() {
    std::process::exit(harness_cli::main(std::env::args_os()));
}
