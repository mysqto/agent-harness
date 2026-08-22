//! The guard executable: stdin in, an exit code out.
//!
//! Layer 2 of the plan's §10.2. It reads a tool call, consults the policy, and exits non-zero to
//! block. No model, no harness and no network are involved in that decision, which is the entire
//! point — the layer above it can be misconfigured or absent and this still refuses.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = harness_policy::cli::run(&args, || {
        let mut payload = String::new();
        std::io::stdin().read_to_string(&mut payload)?;
        Ok(payload)
    });

    // Written directly rather than through `println!`, which panics on a closed pipe — a guard that
    // panics on the way to reporting a refusal reports nothing.
    let _ = std::io::stdout().write_all(outcome.stdout.as_bytes());
    let _ = std::io::stderr().write_all(outcome.stderr.as_bytes());
    ExitCode::from(outcome.code)
}
