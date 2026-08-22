//! Command-line entry point for the confinement layer.
//!
//! Argument parsing and an exit code, and nothing else: everything worth testing lives in the
//! library, because a binary-only crate cannot be unit tested.

#![forbid(unsafe_code)]

fn main() {
    std::process::exit(harness_sandbox::run(std::env::args_os()));
}
