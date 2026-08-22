//! The pattern language the policy is written in.
//!
//! Hand-rolled rather than taken from a crate: the policy is a security boundary, and a boundary
//! whose match semantics live in someone else's code is one nobody here can audit. It is also the
//! smaller risk — the whole matcher is thirty lines and every case below is a test.

/// Whether `candidate` matches glob `pattern`.
///
/// `*` matches any run of characters except `/`; `**` matches any run including `/`; `?` matches one
/// character except `/`; everything else is literal. A pattern ending in `/**` matches the directory
/// itself as well, so `~/.ssh/**` covers a read of `~/.ssh` and not only of the keys inside it.
#[must_use]
pub fn matches(pattern: &str, candidate: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**")
        && is_match(prefix.as_bytes(), candidate.as_bytes())
    {
        return true;
    }
    is_match(pattern.as_bytes(), candidate.as_bytes())
}

fn is_match(pattern: &[u8], candidate: &[u8]) -> bool {
    match pattern.first() {
        None => candidate.is_empty(),
        // `**` crosses separators, `*` does not. Both try every split, shortest first.
        Some(b'*') if pattern.starts_with(b"**") => {
            (0..=candidate.len()).any(|i| is_match(&pattern[2..], &candidate[i..]))
        }
        Some(b'*') => (0..=candidate.len())
            .take_while(|&i| !candidate[..i].contains(&b'/'))
            .any(|i| is_match(&pattern[1..], &candidate[i..])),
        Some(b'?') => {
            matches!(candidate.first(), Some(&c) if c != b'/')
                && is_match(&pattern[1..], &candidate[1..])
        }
        Some(&expected) => {
            candidate.first() == Some(&expected) && is_match(&pattern[1..], &candidate[1..])
        }
    }
}

/// Whether any of `patterns` matches `candidate`.
#[must_use]
pub fn any(patterns: &[String], candidate: &str) -> bool {
    patterns.iter().any(|pattern| matches(pattern, candidate))
}

#[cfg(test)]
mod tests {
    use super::{any, matches};

    #[test]
    fn a_literal_matches_only_itself() {
        assert!(matches("/etc/passwd", "/etc/passwd"));
        assert!(!matches("/etc/passwd", "/etc/passwd-"));
        assert!(!matches("/etc/passwd", "/etc/pass"));
    }

    #[test]
    fn a_single_star_stops_at_a_separator() {
        assert!(matches("/home/*/.netrc", "/home/a/.netrc"));
        assert!(!matches("/home/*/.netrc", "/home/a/b/.netrc"));
    }

    #[test]
    fn a_double_star_crosses_separators() {
        assert!(matches("**/.env", "/srv/work/deep/.env"));
        assert!(matches("**/.env", "/.env"));
        assert!(!matches("**/.env", "/srv/work/.environment"));
    }

    #[test]
    fn a_trailing_double_star_covers_the_directory_itself() {
        // Without this, listing `~/.ssh` would be allowed while reading its contents was not.
        assert!(matches("/home/a/.ssh/**", "/home/a/.ssh"));
        assert!(matches("/home/a/.ssh/**", "/home/a/.ssh/id_rsa"));
        assert!(!matches("/home/a/.ssh/**", "/home/a/.sshx"));
    }

    #[test]
    fn a_question_mark_takes_one_character_but_not_a_separator() {
        assert!(matches("/tmp/f?le", "/tmp/file"));
        assert!(!matches("/tmp/f?le", "/tmp/fle"));
        assert!(!matches("/tmp/?", "/tmp//"));
    }

    #[test]
    fn a_star_can_match_nothing() {
        assert!(matches("*.pem", ".pem"));
        assert!(matches("**", ""));
    }

    #[test]
    fn any_is_the_disjunction_of_its_patterns() {
        let patterns = vec!["**/*.pem".to_string(), "~/.netrc".to_string()];
        assert!(any(&patterns, "/srv/tls/server.pem"));
        assert!(!any(&patterns, "/srv/tls/server.crt"));
        assert!(!any(&[], "/anything"));
    }
}
