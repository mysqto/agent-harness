//! The screen: a policy applied to one rendered message.

use serde::Serialize;

use crate::policy::{Class, Policy, Shape};

/// One thing the screen took out.
///
/// The account names the rule and the span, never the text that was there. A record of a redaction
/// that quotes what it redacted is a copy of the secret in whatever reads the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Masked {
    /// Id of the rule that matched.
    pub rule: String,
    /// Byte offset of the match in the text as it arrived.
    pub at: usize,
    /// How many bytes the match covered.
    pub len: usize,
}

/// A screened message, and what screening it changed.
///
/// Both halves travel together on purpose: a caller that receives only the masked text cannot tell
/// whether it sent what it wrote, which is the failure mode this layer exists to avoid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screened {
    text: String,
    masked: Vec<Masked>,
    policy_version: String,
}

impl Screened {
    /// The text as it may leave the process.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The text, taken.
    #[must_use]
    pub fn into_text(self) -> String {
        self.text
    }

    /// Every match, in the order it appears in the message.
    #[must_use]
    pub fn masked(&self) -> &[Masked] {
        &self.masked
    }

    /// `true` when nothing matched, and so when the text is unchanged.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.masked.is_empty()
    }

    /// Which pattern set produced this.
    ///
    /// Kept with the outcome because the question asked after a rule turns out to over-mask is which
    /// messages went out under which version.
    #[must_use]
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// The account, as one line for a log.
    #[must_use]
    pub fn account(&self) -> String {
        if self.masked.is_empty() {
            return "nothing masked".to_string();
        }
        self.masked
            .iter()
            .map(|m| format!("{} at {} ({} bytes)", m.rule, m.at, m.len))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// A policy, ready to apply.
#[derive(Debug, Clone)]
pub struct Screen {
    policy: Policy,
}

impl Screen {
    /// A screen enforcing `policy`.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    /// A screen enforcing the pattern set shipped with this build.
    #[must_use]
    pub fn shipped() -> Self {
        Self::new(Policy::shipped())
    }

    /// The policy being enforced.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Screens one message.
    ///
    /// Runs on the finished bytes, which is the whole point of the layer: a secret interpolated into
    /// a template at render time is invisible to any check that ran on the fields beforehand.
    ///
    /// Text with no match comes back byte for byte, so a clean message is not reformatted, re-encoded
    /// or otherwise touched on its way out.
    #[must_use]
    pub fn screen(&self, text: &str) -> Screened {
        let hits = self.hits(text);
        let mut out = String::with_capacity(text.len());
        let mut masked = Vec::with_capacity(hits.len());
        let mut cursor = 0;
        for hit in hits {
            let rule = self.policy.rules()[hit.rule].id();
            out.push_str(&text[cursor..hit.start]);
            out.push_str(&self.policy.placeholder_for(rule));
            masked.push(Masked {
                rule: rule.to_string(),
                at: hit.start,
                len: hit.end - hit.start,
            });
            cursor = hit.end;
        }
        out.push_str(&text[cursor..]);
        Screened {
            text: out,
            masked,
            policy_version: self.policy.version().to_string(),
        }
    }

    /// Every match, overlaps resolved.
    ///
    /// Two rules can match overlapping spans — a key block's body contains digit runs, an address's
    /// local part can be a token. The earlier match wins, and the earlier *rule* wins a tie, which
    /// is why declaration order is part of the policy rather than incidental to it.
    fn hits(&self, text: &str) -> Vec<Hit> {
        let bytes = text.as_bytes();
        let mut found: Vec<Hit> = Vec::new();
        for (rule, spec) in self.policy.rules().iter().enumerate() {
            found.extend(
                find(bytes, spec.shape())
                    .into_iter()
                    .map(|(start, end)| Hit { rule, start, end }),
            );
        }
        // Longest first among equals, so a tie between two spans of one rule keeps the wider.
        found.sort_by_key(|hit| (hit.start, hit.rule, std::cmp::Reverse(hit.end)));
        let mut accepted: Vec<Hit> = Vec::with_capacity(found.len());
        let mut covered = 0;
        for hit in found {
            if hit.start >= covered {
                covered = hit.end;
                accepted.push(hit);
            }
        }
        accepted
    }
}

/// One match: which rule, and the byte span it covers.
#[derive(Debug, Clone, Copy)]
struct Hit {
    rule: usize,
    start: usize,
    end: usize,
}

/// Every span in `bytes` matching one shape.
///
/// Byte-wise throughout. Policy literals and classes are ASCII — checked when the policy loads — and
/// UTF-8 is self-synchronising, so no span can begin or end inside a multi-byte character.
fn find(bytes: &[u8], shape: &Shape) -> Vec<(usize, usize)> {
    match shape {
        Shape::Prefixed {
            prefixes,
            body,
            min,
            max,
        } => prefixed(bytes, prefixes, *body, *min, *max),
        Shape::Block { start, end } => block(bytes, start, end),
        Shape::Infix {
            infix,
            left,
            left_min,
            right,
            right_min,
            must_contain,
            trim,
        } => self::infix(
            bytes,
            &InfixShape {
                infix,
                left: *left,
                left_min: *left_min,
                right: *right,
                right_min: *right_min,
                must_contain,
                trim,
            },
        ),
        Shape::Grouped {
            min,
            max,
            separators,
        } => grouped(bytes, *min, *max, separators),
    }
}

/// A prefix, then a bounded run.
///
/// A match is not required to start at a word boundary. Requiring one would let a leak past by
/// prepending a letter to it, and a screen that can be dodged that easily is not one.
fn prefixed(
    bytes: &[u8],
    prefixes: &[Vec<u8>],
    body: Class,
    min: usize,
    max: usize,
) -> Vec<(usize, usize)> {
    let mut hits = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(prefix) = prefixes
            .iter()
            .find(|prefix| bytes[i..].starts_with(prefix))
        {
            let from = i + prefix.len();
            let mut to = from;
            while to < bytes.len() && to - from < max && body.holds(bytes[to]) {
                to += 1;
            }
            if to - from >= min {
                hits.push((i, to));
                i = to;
                continue;
            }
        }
        i += 1;
    }
    hits
}

/// A start marker through the end of the line its end marker sits on.
///
/// A block with no end marker runs to the end of the message. Failing open here would mean a
/// truncated key — the case where the end marker was cut off — went out in full.
fn block(bytes: &[u8], start: &[u8], end: &[u8]) -> Vec<(usize, usize)> {
    let mut hits = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(start) {
            let after = i + start.len();
            let stop = at(bytes, end, after).map_or(bytes.len(), |close| {
                let mut line_end = close + end.len();
                while line_end < bytes.len() && bytes[line_end] != b'\n' {
                    line_end += 1;
                }
                line_end
            });
            hits.push((i, stop));
            i = stop;
            continue;
        }
        i += 1;
    }
    hits
}

/// The parts of an infix shape, grouped so the matcher takes one argument rather than seven.
struct InfixShape<'a> {
    infix: &'a [u8],
    left: Class,
    left_min: usize,
    right: Class,
    right_min: usize,
    must_contain: &'a [u8],
    trim: &'a [u8],
}

/// A literal with a run on each side.
fn infix(bytes: &[u8], shape: &InfixShape<'_>) -> Vec<(usize, usize)> {
    let mut hits = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(shape.infix) {
            let mut from = i;
            while from > 0 && shape.left.holds(bytes[from - 1]) {
                from -= 1;
            }
            let right_from = i + shape.infix.len();
            let mut to = right_from;
            while to < bytes.len() && shape.right.holds(bytes[to]) {
                to += 1;
            }
            // Trailing punctuation belongs to the sentence, not to the match.
            while to > right_from && shape.trim.contains(&bytes[to - 1]) {
                to -= 1;
            }
            if i - from >= shape.left_min
                && to - right_from >= shape.right_min
                && at(&bytes[right_from..to], shape.must_contain, 0).is_some()
            {
                hits.push((from, to));
                i = to;
                continue;
            }
        }
        i += 1;
    }
    hits
}

/// A long digit run, optionally broken into groups.
///
/// Bounded above as well as below, and a run outside the bounds is skipped a group at a time rather
/// than a byte at a time: scanning by bytes would find a match of the maximum length inside any
/// longer run, so every over-long number would be masked all but its first digit.
fn grouped(bytes: &[u8], min: usize, max: usize, separators: &[u8]) -> Vec<(usize, usize)> {
    let mut hits = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let mut j = i;
        let mut digits = 0;
        let mut last_digit = i;
        let mut first_separator = None;
        while j < bytes.len() {
            if bytes[j].is_ascii_digit() {
                digits += 1;
                j += 1;
                last_digit = j;
            } else if separators.contains(&bytes[j])
                && j > i
                && bytes[j - 1].is_ascii_digit()
                && bytes.get(j + 1).is_some_and(u8::is_ascii_digit)
            {
                first_separator = first_separator.or(Some(j));
                j += 1;
            } else {
                break;
            }
        }
        if (min..=max).contains(&digits) {
            hits.push((i, last_digit));
            i = last_digit;
        } else {
            i = first_separator.map_or(last_digit, |separator| separator + 1);
        }
    }
    hits
}

/// The first offset at or after `from` where `needle` occurs, or `None`.
///
/// An empty needle occurs immediately, which is what makes an unset `must_contain` mean "no further
/// condition" rather than "nothing can match".
fn at(bytes: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(from);
    }
    if from >= bytes.len() {
        return None;
    }
    bytes[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

#[cfg(test)]
mod tests {
    use super::Screen;
    use crate::policy::Policy;

    /// A screen over a one-rule policy, for the shape tests.
    fn screen(rule: &str) -> Screen {
        Screen::new(
            Policy::parse(&format!(
                "version = \"t\"\nplaceholder = \"[{{rule}}]\"\n\n[[rule]]\n{rule}\n"
            ))
            .expect("policy"),
        )
    }

    #[test]
    fn a_prefixed_shape_is_masked_whole() {
        let screened = screen(
            "id = \"tok\"\nkind = \"prefixed\"\nprefixes = [\"tk-\"]\nbody = \"token\"\n\
             min = 8\nmax = 64",
        )
        .screen("use tk-abcdefgh12 to post");

        assert_eq!(screened.text(), "use [tok] to post");
        assert_eq!(screened.masked().len(), 1);
        assert_eq!(screened.masked()[0].at, 4);
        assert_eq!(screened.masked()[0].len, "tk-abcdefgh12".len());
    }

    #[test]
    fn a_prefix_followed_by_too_little_is_left_alone() {
        // The prefix appears in prose far more often than a token does; `min` is what tells them
        // apart.
        let text = "the tk- prefix, as in tk-short";
        let screened = screen(
            "id = \"tok\"\nkind = \"prefixed\"\nprefixes = [\"tk-\"]\nbody = \"token\"\n\
             min = 8\nmax = 64",
        )
        .screen(text);

        assert_eq!(screened.text(), text);
        assert!(screened.is_clean());
    }

    #[test]
    fn a_run_longer_than_max_is_masked_up_to_max() {
        // Truncating the match rather than dropping it: a bounded prefix rule must not be defeated
        // by appending characters.
        let screened = screen(
            "id = \"tok\"\nkind = \"prefixed\"\nprefixes = [\"tk-\"]\nbody = \"token\"\n\
             min = 4\nmax = 6",
        )
        .screen("tk-abcdefghij");

        assert_eq!(screened.text(), "[tok]ghij");
        assert_eq!(screened.masked()[0].len, "tk-abcdef".len());
    }

    #[test]
    fn every_prefix_of_a_rule_matches() {
        let screened = screen(
            "id = \"tok\"\nkind = \"prefixed\"\nprefixes = [\"aa-\", \"bb-\"]\nbody = \"token\"\n\
             min = 4\nmax = 64",
        )
        .screen("aa-1234 and bb-5678");

        assert_eq!(screened.text(), "[tok] and [tok]");
        assert_eq!(screened.masked().len(), 2);
    }

    #[test]
    fn a_block_is_masked_through_its_end_marker() {
        let screened = screen("id = \"blk\"\nkind = \"block\"\nstart = \"<<B\"\nend = \">>E\"")
            .screen("before\n<<B\nbody\n>>E---\nafter");

        assert_eq!(screened.text(), "before\n[blk]\nafter");
    }

    #[test]
    fn a_block_with_no_end_marker_is_masked_to_the_end() {
        // Fail closed: a truncated block is the case where letting it through leaks the whole body.
        let screened = screen("id = \"blk\"\nkind = \"block\"\nstart = \"<<B\"\nend = \">>E\"")
            .screen("before\n<<B\nbody without a terminator\n");

        assert_eq!(screened.text(), "before\n[blk]");
    }

    #[test]
    fn an_infix_shape_takes_both_sides() {
        let screened = screen(
            "id = \"addr\"\nkind = \"infix\"\ninfix = \"@\"\nleft = \"local\"\nleft_min = 1\n\
             right = \"host\"\nright_min = 4\nright_must_contain = \".\"\nright_trim = \".-\"",
        )
        .screen("write to ada.lovelace@example.test.");

        assert_eq!(screened.text(), "write to [addr].");
        assert_eq!(screened.masked()[0].len, "ada.lovelace@example.test".len());
    }

    #[test]
    fn an_infix_shape_needs_what_its_policy_requires_on_the_right() {
        let text = "mention @someone and host@localhost";
        let screened = screen(
            "id = \"addr\"\nkind = \"infix\"\ninfix = \"@\"\nleft = \"local\"\nleft_min = 1\n\
             right = \"host\"\nright_min = 4\nright_must_contain = \".\"\nright_trim = \".-\"",
        )
        .screen(text);

        assert_eq!(screened.text(), text, "neither is an address");
    }

    #[test]
    fn a_grouped_run_is_masked_with_its_separators() {
        let screened =
            screen("id = \"digits\"\nkind = \"grouped\"\nmin = 13\nmax = 19\nseparators = \" -\"")
                .screen("ref 4111 1111 1111 1111 end");

        assert_eq!(screened.text(), "ref [digits] end");
        assert_eq!(screened.masked()[0].len, "4111 1111 1111 1111".len());
    }

    #[test]
    fn short_and_over_long_digit_runs_are_left_alone() {
        let text = "in 2024 we saw 987654 of them, id 123456789012345678901234";
        let screened =
            screen("id = \"digits\"\nkind = \"grouped\"\nmin = 13\nmax = 19\nseparators = \" -\"")
                .screen(text);

        assert_eq!(screened.text(), text);
        assert!(screened.is_clean(), "{}", screened.account());
    }

    #[test]
    fn a_qualifying_group_after_an_over_long_one_is_still_found() {
        // The skip on rejection is by group, not by byte: a run that fails the bounds must not hide
        // the number after it.
        let screened =
            screen("id = \"digits\"\nkind = \"grouped\"\nmin = 13\nmax = 19\nseparators = \" -\"")
                .screen("12345678901234567890 4111111111111111");

        assert_eq!(screened.text(), "12345678901234567890 [digits]");
    }

    #[test]
    fn a_clean_message_comes_back_byte_identical() {
        let text = "Deploy 3 finished in 42s. Notes: sk-, xox, AKIA, 2024-08-01, @here — all fine.";
        let screened = Screen::shipped().screen(text);

        assert_eq!(screened.text(), text);
        assert_eq!(screened.text().as_bytes(), text.as_bytes());
        assert!(screened.is_clean());
        assert_eq!(screened.account(), "nothing masked");
    }

    #[test]
    fn text_that_is_not_ascii_survives_screening() {
        // Matching is byte-wise, so this is the case that would corrupt output if a span could land
        // inside a character.
        let text = "réf 4111 1111 1111 1111 — прочитано ✅";
        let screened = Screen::shipped().screen(text);

        assert_eq!(
            screened.text(),
            "réf [redacted:long-digit-run] — прочитано ✅"
        );
    }

    #[test]
    fn the_earlier_rule_wins_an_overlap() {
        let screen = Screen::new(
            Policy::parse(
                "version = \"t\"\nplaceholder = \"[{rule}]\"\n\
                 [[rule]]\nid = \"first\"\nkind = \"prefixed\"\nprefixes = [\"tk-\"]\n\
                 body = \"token\"\nmin = 4\nmax = 64\n\
                 [[rule]]\nid = \"second\"\nkind = \"prefixed\"\nprefixes = [\"tk-\"]\n\
                 body = \"token\"\nmin = 4\nmax = 64\n",
            )
            .expect("policy"),
        );
        let screened = screen.screen("tk-abcd");

        assert_eq!(screened.text(), "[first]");
        assert_eq!(screened.masked().len(), 1);
    }

    #[test]
    fn the_account_names_every_match_in_order() {
        let screened = Screen::shipped().screen("key xoxb-1234567890 for team@example.test");

        assert_eq!(
            screened.account(),
            "chat-token at 4 (15 bytes), address at 24 (17 bytes)"
        );
        assert_eq!(screened.policy_version(), "egress-v1");
    }

    #[test]
    fn the_masked_text_can_be_taken() {
        let screened = Screen::shipped().screen("plain");
        assert_eq!(screened.into_text(), "plain");
    }

    #[test]
    fn a_screen_reports_the_policy_it_enforces() {
        assert_eq!(Screen::shipped().policy().version(), "egress-v1");
    }

    #[test]
    fn a_policy_with_no_rules_masks_nothing() {
        let text = "xoxb-1234567890 and 4111 1111 1111 1111";
        let empty = Screen::new(
            Policy::parse("version = \"none\"\nplaceholder = \"[x]\"\n").expect("policy"),
        );
        let screened = empty.screen(text);

        assert_eq!(screened.text(), text);
        assert!(screened.is_clean());
    }
}
