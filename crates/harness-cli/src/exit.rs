//! Exit codes.
//!
//! A script branches on these, so they are as much part of the interface as the output is and must
//! not shift. They are also why nothing here collapses onto 1: "it failed" and "you asked for an
//! intent nobody handles" call for different reactions from whatever ran the binary.

/// Everything asked for was done.
pub const OK: i32 = 0;

/// Something went wrong that none of the codes below describes.
pub const FAILED: i32 = 1;

/// The arguments, or the envelope on stdin, did not make sense.
pub const USAGE: i32 = 2;

/// The config file is missing, unreadable, or does not say what is needed.
pub const CONFIG: i32 = 3;

/// The dispatcher refused the task — a mutating intent on incomplete context.
pub const REFUSED: i32 = 4;

/// No registered agent handles the intent.
pub const UNROUTABLE: i32 = 5;

/// The list shown in `--help`, so the documented codes and the real ones cannot drift.
pub const HELP: &str = "\
Exit codes:
  0  success
  1  failed
  2  usage error — bad arguments, or an unparseable envelope on stdin
  3  config error — missing, unreadable, or incomplete config
  4  dispatch refused — a mutating intent on degraded context
  5  unroutable — no registered agent handles the intent";

#[cfg(test)]
mod tests {
    use super::{CONFIG, FAILED, HELP, OK, REFUSED, UNROUTABLE, USAGE};

    #[test]
    fn every_code_is_distinct_and_documented() {
        let codes = [OK, FAILED, USAGE, CONFIG, REFUSED, UNROUTABLE];
        for (position, code) in codes.iter().enumerate() {
            assert!(
                !codes[position + 1..].contains(code),
                "code {code} is used twice"
            );
            assert!(
                HELP.contains(&format!("  {code}  ")),
                "code {code} is missing from --help"
            );
        }
    }
}
