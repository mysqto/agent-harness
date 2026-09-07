//! Recognising a program handed to an interpreter as an argument.
//!
//! `sh -c '<line>'` and `python3 -c '<program>'` put a whole call inside one quoted word. Every rule
//! in the policy fires on something [`crate::command::parse`] found, and it finds one opaque token
//! here, so the line is admitted whatever it says while the same line typed directly is refused.
//!
//! The obvious fix is to recurse — read the word as another command line and check it. That is the
//! answer this module deliberately does not give. It would mean ruling on which programs take a
//! command *line* and which take a *program*, and the two are not the same language: `python3 -c
//! 'open(p)'` names a path no shell parser would find. Reading a program as a command line gets the
//! answer wrong in the permissive direction, and that is the one direction this guard does not err
//! in. So the shape is refused and nothing is claimed about the contents.
//!
//! What this does *not* refuse is an interpreter given a script file. That is argued in
//! `eval.rs`'s `an_interpreter_given_a_script_file_or_an_ordinary_flag_is_not_refused`, and the short
//! form is: a file is at a path the path rules already read, it got there through a write gate, and
//! a `#!` line runs it with no interpreter in the command at all — so refusing the spelling buys no
//! property. Inline eval has no second spelling.

use crate::command::{Invocation, basename};
use crate::glob;
use crate::policy::Interpreter;

/// Operands that name standard input, where a program leaves no artefact and no argument.
///
/// A bare `-` is handled with the flags, since it is the same token shape.
const STDIN_OPERANDS: [&str; 2] = ["/dev/stdin", "/dev/fd/0"];

/// The interpreter this invocation hands a program to, by the name that matched.
///
/// Two positions are looked at, because an interpreter is not always the program of its own
/// invocation. It is when the line runs it (`sh -c …`, and the same through every wrapper the policy
/// lists, since a wrapper's programs are kept beside the one it launches). It is *not* when a wrapper
/// carries an operand of its own (`timeout 5 sh -c …`) or when another program launches it
/// (`find . -exec sh -c … ;`) — there it is an argument, and only the tokens after it are its own.
///
/// The two positions are not read the same way, and the difference is the empty tail. An interpreter
/// the line *runs* with no arguments at all reads its program from standard input, which is
/// `echo '…' | sh` — the program is real and there is no token anywhere that names it. An
/// interpreter merely *named* with nothing after it is a word: `which bash` and `ls -la /bin/sh` say
/// nothing about running anything, and refusing them would be reading a mention as an execution.
///
/// That asymmetry had a gap in it, because the two positions are not as far apart as they look.
/// [`crate::command::parse`] finds the program by skipping a run of flags and assignments and taking
/// the next token, so a wrapper that spends that position on a *separated positional operand* —
/// `timeout 5`, `nice -n 5` — leaves the interpreter behind it in the arguments. `timeout 5 sh -c …`
/// still refuses, on the `-c`. `timeout 5 sh` did not: the program is on standard input, so there is
/// no token after the interpreter for the argument scan to find, and it read the empty tail as a
/// mention.
///
/// So the empty tail is a mention only while the program position is legible, and it stops being
/// legible the moment a wrapper has been walked. Once one has, this parse has already settled on a
/// token it cannot tell from an operand, and what sits between that token and the interpreter is
/// unread either way — `-k 1 5`, or a second wrapper carrying an operand of its own. Behind a
/// wrapper, therefore, an interpreter that *ends the line* is refused wherever it sits, and
/// `timeout 5 which bash` is refused with it. Counting a wrapper's operands would be the narrower
/// answer and it is not available: a parse that could count them would not have had the gap.
#[must_use]
pub fn handed_a_program(interpreters: &[Interpreter], found: &Invocation) -> Option<String> {
    for entry in interpreters {
        if let Some(name) = found
            .programs
            .iter()
            .find(|program| glob::any(&entry.programs, program))
            && (found.args.is_empty() || introduces_a_program(entry, &found.args))
        {
            return Some(name.clone());
        }
        for (at, token) in found.args.iter().enumerate() {
            let name = basename(token);
            let tail = &found.args[at + 1..];
            if glob::any(&entry.programs, name)
                && (introduces_a_program(entry, tail)
                    || (tail.is_empty() && behind_a_wrapper(found)))
            {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Whether the program position of this invocation was decided after walking a wrapper.
///
/// `programs` collects one entry per wrapper and one for the token the walk finally settled on, so
/// more than one entry means a wrapper was passed — and that the token it settled on may be that
/// wrapper's operand rather than a program. This is what the argument scan reads to know whether an
/// empty tail is a mention or the standard input of an interpreter the line runs.
fn behind_a_wrapper(found: &Invocation) -> bool {
    found.programs.len() > 1
}

/// Whether any of `tokens` says a program follows, is attached, or is on standard input.
fn introduces_a_program(entry: &Interpreter, tokens: &[String]) -> bool {
    tokens.iter().any(|token| is_program_source(entry, token))
}

/// Fail closed on the spelling: a token this cannot rule *out* is treated as an inline-program flag.
fn is_program_source(entry: &Interpreter, token: &str) -> bool {
    if let Some(long) = token.strip_prefix("--") {
        let name = long.split('=').next().unwrap_or(long);
        return entry
            .options
            .iter()
            .any(|option| !option.is_empty() && name.contains(option.as_str()));
    }
    if let Some(short) = token.strip_prefix('-') {
        // `-` alone: the program arrives on standard input and there is nothing else to see.
        if short.is_empty() {
            return true;
        }
        // Cluster semantics. `-lc` is three options and `-cSOMETHING` is one with its value
        // attached, so the letters are read until the first character that cannot be an option —
        // which is where the value starts, and where `-I/usr/include` stops being flags.
        return short
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .any(|letter| entry.flags.contains(letter));
    }
    STDIN_OPERANDS.contains(&token)
}

#[cfg(test)]
mod tests {
    use super::handed_a_program;
    use crate::command::parse;
    use crate::policy::{InlinePrograms, Interpreter};

    fn wrappers() -> Vec<String> {
        ["sudo", "env", "xargs", "timeout"]
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn matched(line: &str) -> Option<String> {
        let interpreters = InlinePrograms::default().interpreters;
        parse(line, &wrappers())
            .iter()
            .find_map(|found| handed_a_program(&interpreters, found))
    }

    #[test]
    fn the_interpreter_that_matched_is_the_one_reported() {
        assert_eq!(matched("sh -c true").as_deref(), Some("sh"));
        // Reported by the name the line used, so a refusal points at the token a person can see.
        assert_eq!(matched("/bin/bash -c true").as_deref(), Some("bash"));
        assert_eq!(matched("timeout 5 zsh -c true").as_deref(), Some("zsh"));
        assert_eq!(matched("python3 -c pass").as_deref(), Some("python3"));
    }

    #[test]
    fn a_letter_after_the_value_has_started_is_not_a_flag() {
        // The regression this guards: reading every character of a token as an option letter makes
        // `-I/usr/include` carry a `c`, and a compiler invocation becomes an inline program.
        let entry = Interpreter {
            programs: vec!["cc".to_string()],
            flags: "c".to_string(),
            options: Vec::new(),
        };
        let line = |line: &str| {
            parse(line, &[])
                .iter()
                .find_map(|found| handed_a_program(std::slice::from_ref(&entry), found))
        };
        assert_eq!(line("cc -I/usr/include -o out main.c"), None);
        assert_eq!(line("cc -c main.c").as_deref(), Some("cc"));
    }

    #[test]
    fn an_interpreter_run_with_nothing_reads_its_program_from_stdin_and_one_only_named_does_not() {
        assert_eq!(matched("sh").as_deref(), Some("sh"));
        assert_eq!(matched("echo hi | bash").as_deref(), Some("bash"));
        assert_eq!(matched("which bash"), None);
        assert_eq!(matched("ls -la /bin/sh"), None);
    }

    #[test]
    fn a_wrappers_operand_does_not_hide_the_interpreter_that_ends_the_line() {
        // The operand takes the program position, so the interpreter is read by the argument scan,
        // where the tail is empty because the program is on standard input.
        assert_eq!(matched("timeout 5 sh").as_deref(), Some("sh"));
        assert_eq!(matched("timeout 5 timeout 3 bash").as_deref(), Some("bash"));
        // Still a mention where no wrapper was walked, which is the whole of what this spends.
        assert_eq!(matched("which bash"), None);
        assert_eq!(matched("ls -la /bin/sh"), None);
        // And still not inline eval when the interpreter is given a file to run.
        assert_eq!(matched("timeout 5 sh script.sh"), None);
    }

    #[test]
    fn nothing_matches_when_the_interpreter_list_is_empty() {
        assert_eq!(
            parse("sh -c true", &[])
                .iter()
                .find_map(|found| handed_a_program(&[], found)),
            None
        );
    }
}
