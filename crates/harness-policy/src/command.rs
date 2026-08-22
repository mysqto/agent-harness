//! Reading a shell command line well enough to police it.
//!
//! A command string is not one command. `ls && sudo rm -rf ~` is two, one of them wrapped, and a
//! guard that inspects only the first word of the line has already lost. So the line is split on the
//! operators a shell splits on, quoting is respected, wrappers are seen through, and redirections
//! are recovered as writes — `echo x > ~/.bashrc` writes to a startup file with no write tool in
//! sight.
//!
//! This is not a shell parser and does not try to be. It is deliberately over-eager: an
//! unrecognised construct yields extra fragments rather than fewer, and extra fragments can only
//! ever cause a refusal, never permission.

/// One command found in a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// Program basenames this invocation runs, wrappers first, real program last.
    ///
    /// A rule matches if *any* of them matches, so `sudo` cannot launder `rm` and a rule naming
    /// `sudo` itself still fires.
    pub programs: Vec<String>,
    /// Arguments after the program, with redirection syntax removed.
    pub args: Vec<String>,
    /// Paths this invocation redirects output into.
    pub writes: Vec<String>,
}

/// Splits a command line into its invocations.
///
/// `wrappers` names programs that only launch another program (see
/// [`crate::Policy::command_wrappers`]).
#[must_use]
pub fn parse(line: &str, wrappers: &[String]) -> Vec<Invocation> {
    fragments(line)
        .into_iter()
        .map(|tokens| invocation(tokens, wrappers))
        .filter(|found| !(found.programs.is_empty() && found.writes.is_empty()))
        .collect()
}

/// Splits a line into token lists, one per command, honouring quotes and escapes.
fn fragments(line: &str) -> Vec<Vec<String>> {
    let mut fragments = Vec::new();
    let mut tokens: Vec<String> = Vec::new();
    let mut token = String::new();
    let mut quote: Option<char> = None;
    let mut chars = line.chars();

    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(open), c) if c == open => quote = None,
            (None, '\'' | '"') => quote = Some(c),
            // A backslash hides the next character from the splitter, whatever it is.
            (None, '\\') => {
                if let Some(escaped) = chars.next() {
                    token.push(escaped);
                }
            }
            // Every operator that starts a new command, plus the grouping and substitution
            // characters, which is why `$(...)` and backticks get inspected as commands too.
            (None, ';' | '|' | '&' | '\n' | '(' | ')' | '{' | '}' | '`') => {
                push(&mut tokens, &mut token);
                push_fragment(&mut fragments, &mut tokens);
            }
            (None, c) if c.is_whitespace() => push(&mut tokens, &mut token),
            // Anything else — and anything at all inside quotes — is part of the token.
            (_, c) => token.push(c),
        }
    }
    push(&mut tokens, &mut token);
    push_fragment(&mut fragments, &mut tokens);
    fragments
}

fn push(tokens: &mut Vec<String>, token: &mut String) {
    if !token.is_empty() {
        tokens.push(std::mem::take(token));
    }
}

fn push_fragment(fragments: &mut Vec<Vec<String>>, tokens: &mut Vec<String>) {
    if !tokens.is_empty() {
        fragments.push(std::mem::take(tokens));
    }
}

/// Turns one fragment's tokens into an invocation.
fn invocation(tokens: Vec<String>, wrappers: &[String]) -> Invocation {
    let (plain, writes) = split_redirections(tokens);
    let mut programs = Vec::new();
    let mut rest = plain.as_slice();

    loop {
        rest = skip_prelude(rest);
        match rest.split_first() {
            Some((first, tail)) if is_wrapper(first, wrappers) => {
                programs.push(basename(first).to_string());
                rest = tail;
            }
            Some((first, tail)) => {
                programs.push(basename(first).to_string());
                return Invocation {
                    programs,
                    args: tail.to_vec(),
                    writes,
                };
            }
            None => {
                return Invocation {
                    programs,
                    args: Vec::new(),
                    writes,
                };
            }
        }
    }
}

/// Drops leading environment assignments and a wrapper's own flags.
///
/// `TOKEN=x sudo -n rm` must still be seen as `rm`; without this the program would read as `TOKEN=x`.
fn skip_prelude(tokens: &[String]) -> &[String] {
    let skip = tokens
        .iter()
        .take_while(|token| token.starts_with('-') || is_assignment(token))
        .count();
    &tokens[skip..]
}

fn is_assignment(token: &str) -> bool {
    match token.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        }
        None => false,
    }
}

fn is_wrapper(token: &str, wrappers: &[String]) -> bool {
    let name = basename(token);
    wrappers.iter().any(|wrapper| wrapper == name)
}

/// The last path component of a program token, so `/usr/bin/rm` matches a rule naming `rm`.
fn basename(token: &str) -> &str {
    token.rsplit('/').next().unwrap_or(token)
}

/// Separates redirection targets from ordinary tokens.
fn split_redirections(tokens: Vec<String>) -> (Vec<String>, Vec<String>) {
    let mut plain = Vec::new();
    let mut writes = Vec::new();
    let mut target_next = false;

    for token in tokens {
        if target_next {
            target_next = false;
            writes.push(token);
            continue;
        }
        // A leading file descriptor number is part of the operator: `2>log` redirects too.
        let operator = token.trim_start_matches(|c: char| c.is_ascii_digit());
        if let Some(rest) = operator.strip_prefix('>') {
            let rest = rest.trim_start_matches('>');
            if rest.is_empty() {
                target_next = true;
            } else {
                writes.push(rest.to_string());
            }
        } else if let Some(rest) = operator.strip_prefix('<') {
            // An input redirection is still a read of whatever it names.
            let rest = rest.trim_start_matches('<');
            if !rest.is_empty() {
                plain.push(rest.to_string());
            }
        } else {
            plain.push(token);
        }
    }
    (plain, writes)
}

#[cfg(test)]
mod tests {
    use super::{Invocation, parse};

    fn wrappers() -> Vec<String> {
        ["sudo", "env", "xargs"]
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn parsed(line: &str) -> Vec<Invocation> {
        parse(line, &wrappers())
    }

    #[test]
    fn a_plain_command_yields_its_program_and_arguments() {
        let found = parsed("rm -rf build");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].programs, vec!["rm"]);
        assert_eq!(found[0].args, vec!["-rf", "build"]);
        assert!(found[0].writes.is_empty());
    }

    #[test]
    fn every_operator_starts_a_new_command() {
        for line in [
            "ls && rm -rf /",
            "ls; rm -rf /",
            "ls || rm -rf /",
            "ls | rm -rf /",
            "ls\nrm -rf /",
            "ls $(rm -rf /)",
            "ls `rm -rf /`",
        ] {
            let programs: Vec<String> = parsed(line)
                .iter()
                .flat_map(|found| found.programs.clone())
                .collect();
            assert!(
                programs.iter().any(|program| program == "rm"),
                "missed the second command in {line}"
            );
        }
    }

    #[test]
    fn a_wrapper_does_not_hide_the_program_it_launches() {
        let found = parsed("sudo -n /usr/bin/rm -rf /");
        assert_eq!(found[0].programs, vec!["sudo", "rm"]);
        assert_eq!(found[0].args, vec!["-rf", "/"]);
    }

    #[test]
    fn wrappers_nest() {
        let found = parsed("env FOO=bar xargs rm");
        assert_eq!(found[0].programs, vec!["env", "xargs", "rm"]);
    }

    #[test]
    fn leading_assignments_are_not_mistaken_for_the_program() {
        let found = parsed("TOKEN=abc curl http://example.test");
        assert_eq!(found[0].programs, vec!["curl"]);
    }

    #[test]
    fn quoting_hides_operators_from_the_splitter() {
        let found = parsed("echo 'a; b' \"c && d\"");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].args, vec!["a; b", "c && d"]);
    }

    #[test]
    fn an_escaped_character_is_taken_literally() {
        let found = parsed(r"echo a\;b");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].args, vec!["a;b"]);
    }

    #[test]
    fn redirections_are_recovered_as_writes() {
        for line in [
            "echo x > ~/.bashrc",
            "echo x >~/.bashrc",
            "echo x >> ~/.bashrc",
            "echo x 2>~/.bashrc",
        ] {
            let found = parsed(line);
            assert_eq!(found[0].writes, vec!["~/.bashrc"], "{line}");
        }
    }

    #[test]
    fn an_input_redirection_stays_an_argument() {
        let found = parsed("cat <~/.ssh/id_rsa");
        assert_eq!(found[0].args, vec!["~/.ssh/id_rsa"]);
    }

    #[test]
    fn a_redirection_with_no_program_is_still_a_write() {
        // `> file` is legal on its own, and truncates.
        let found = parsed("> ~/.bashrc");
        assert_eq!(found.len(), 1);
        assert!(found[0].programs.is_empty());
        assert_eq!(found[0].writes, vec!["~/.bashrc"]);
    }

    #[test]
    fn an_empty_line_yields_nothing() {
        assert!(parsed("   ").is_empty());
        assert!(parsed("").is_empty());
    }

    #[test]
    fn an_unterminated_quote_still_yields_the_command() {
        let found = parsed("rm -rf 'unclosed");
        assert_eq!(found[0].programs, vec!["rm"]);
        assert_eq!(found[0].args, vec!["-rf", "unclosed"]);
    }

    #[test]
    fn a_trailing_backslash_is_dropped_rather_than_panicking() {
        let found = parsed("rm x\\");
        assert_eq!(found[0].args, vec!["x"]);
    }
}
