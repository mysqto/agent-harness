//! The pattern set, as data.
//!
//! A policy is a list of *shapes*: a literal anchor and bounded runs of a named character class.
//! Shapes rather than regular expressions, for two reasons. Matching stays linear and cannot be made
//! expensive by whatever wrote the text being screened, and every match carries the id of the rule
//! that produced it — which is what lets the screen account for a redaction instead of just
//! performing one.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

use crate::error::{Error, Result};

/// The pattern set shipped with the harness.
///
/// Compiled in so the screen is on before anything is configured: a security layer that needs a file
/// to be in the right place is a layer that is off on the host where it is not.
const SHIPPED: &str = include_str!("../../../spec/egress-screen.toml");

/// A named set of ASCII bytes a run may consist of.
///
/// ASCII only, and that is load-bearing: UTF-8 is self-synchronising, so a shape built from ASCII
/// literals and ASCII classes can be matched byte by byte without a match ever landing inside a
/// multi-byte character.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Letters, digits, `-` and `_` — what issuers put after a token prefix.
    Token,
    /// Base64 and its URL-safe variant, with padding.
    Base64,
    /// Hexadecimal digits, either case.
    Hex,
    /// Decimal digits.
    Digit,
    /// Capitals and digits.
    Upper,
    /// The characters an address's local part may carry.
    Local,
    /// Host characters: letters, digits, `.` and `-`.
    Host,
    /// Anything but a newline.
    Line,
}

impl Class {
    /// Resolves a class name from a policy file.
    fn parse(name: &str) -> Option<Self> {
        match name {
            "token" => Some(Self::Token),
            "base64" => Some(Self::Base64),
            "hex" => Some(Self::Hex),
            "digit" => Some(Self::Digit),
            "upper" => Some(Self::Upper),
            "local" => Some(Self::Local),
            "host" => Some(Self::Host),
            "line" => Some(Self::Line),
            _ => None,
        }
    }

    /// Whether `byte` belongs to this class.
    #[must_use]
    pub fn holds(self, byte: u8) -> bool {
        match self {
            Self::Token => byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_',
            Self::Base64 => {
                byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
            }
            Self::Hex => byte.is_ascii_hexdigit(),
            Self::Digit => byte.is_ascii_digit(),
            Self::Upper => byte.is_ascii_uppercase() || byte.is_ascii_digit(),
            Self::Local => {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
            }
            Self::Host => byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-',
            Self::Line => byte != b'\n',
        }
    }
}

/// One shape the screen looks for.
#[derive(Debug, Clone)]
pub(crate) enum Shape {
    /// An issuer prefix followed by a bounded run of class bytes.
    Prefixed {
        prefixes: Vec<Vec<u8>>,
        body: Class,
        min: usize,
        max: usize,
    },
    /// Everything from a start marker through the end of the line the end marker sits on.
    Block { start: Vec<u8>, end: Vec<u8> },
    /// A literal with a run on each side of it.
    Infix {
        infix: Vec<u8>,
        left: Class,
        left_min: usize,
        right: Class,
        right_min: usize,
        must_contain: Vec<u8>,
        trim: Vec<u8>,
    },
    /// A long digit run, optionally broken into groups by separators.
    Grouped {
        min: usize,
        max: usize,
        separators: Vec<u8>,
    },
}

/// A shape, and the name a match reports itself under.
#[derive(Debug, Clone)]
pub struct Rule {
    id: String,
    shape: Shape,
}

impl Rule {
    /// What a match by this rule is called in the account and in the placeholder.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn shape(&self) -> &Shape {
        &self.shape
    }
}

/// A pattern set, validated.
///
/// Constructing one is the only way to get past the checks below, so the matcher never has to ask
/// whether a rule is usable.
#[derive(Debug, Clone)]
pub struct Policy {
    version: String,
    placeholder: String,
    rules: Vec<Rule>,
}

impl Policy {
    /// The pattern set compiled into this build.
    ///
    /// The same bytes as `spec/egress-screen.toml`, which is what makes the shipped default
    /// reviewable as configuration rather than buried in code.
    ///
    /// # Panics
    ///
    /// Never at runtime: the shipped policy is validated by this crate's own tests, so a fault in it
    /// fails the build rather than a deployment.
    #[must_use]
    pub fn shipped() -> Self {
        Self::parse(SHIPPED).expect("the shipped policy is checked by this crate's tests")
    }

    /// Reads a policy from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|why| Error::unreadable(path, &why))?;
        Self::parse(&text)
    }

    /// Parses and validates policy text.
    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawPolicy = toml::from_str(text).map_err(|err| {
            // `toml` renders a multi-line snippet with a caret. On one line of stderr that is noise;
            // the message is what a reader acts on.
            Error::Unparseable(
                err.message()
                    .lines()
                    .next()
                    .unwrap_or("unparseable")
                    .to_string(),
            )
        })?;
        raw.validate()
    }

    /// The policy's own version string, recorded alongside anything it masked.
    ///
    /// Reported rather than inferred: when a rule turns out to over-mask, the question asked
    /// afterwards is which messages went out under which pattern set.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The rules, in the order they were declared.
    ///
    /// Order is a tie-break, not a filter: two rules matching at the same offset resolve to the one
    /// declared first.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// What replaces a match by `rule`.
    #[must_use]
    pub fn placeholder_for(&self, rule: &str) -> String {
        self.placeholder.replace("{rule}", rule)
    }
}

/// The policy file's shape, before validation.
#[derive(Debug, Deserialize)]
struct RawPolicy {
    version: String,
    placeholder: String,
    /// Named `rule` in the file, because TOML spells a list of tables `[[rule]]`.
    #[serde(default, rename = "rule")]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    id: String,
    #[serde(flatten)]
    shape: RawShape,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum RawShape {
    Prefixed {
        prefixes: Vec<String>,
        body: String,
        min: usize,
        max: usize,
    },
    Block {
        start: String,
        end: String,
    },
    Infix {
        infix: String,
        left: String,
        left_min: usize,
        right: String,
        right_min: usize,
        #[serde(default)]
        right_must_contain: String,
        #[serde(default)]
        right_trim: String,
    },
    Grouped {
        min: usize,
        max: usize,
        separators: String,
    },
}

impl RawPolicy {
    /// Turns a parsed file into a policy, or says why it cannot be one.
    ///
    /// Every check here is a way a rule could load and then never match. Rejecting at load is the
    /// difference between a screen that is missing a pattern class and a screen that reports itself
    /// as covering one it does not.
    fn validate(self) -> Result<Policy> {
        if self.version.trim().is_empty() {
            return Err(Error::Unparseable("policy has no version".to_string()));
        }
        let mut ids = BTreeSet::new();
        let mut rules = Vec::with_capacity(self.rules.len());
        for raw in self.rules {
            let id = raw.id;
            if id.trim().is_empty() {
                return Err(Error::Unparseable("a rule has no id".to_string()));
            }
            if !ids.insert(id.clone()) {
                // Ids name rules in the account, so two rules cannot share one.
                return Err(Error::unusable(&id, "declared twice"));
            }
            let shape = shape(&id, raw.shape)?;
            rules.push(Rule { id, shape });
        }
        Ok(Policy {
            version: self.version,
            placeholder: self.placeholder,
            rules,
        })
    }
}

/// Validates one rule body.
fn shape(id: &str, raw: RawShape) -> Result<Shape> {
    match raw {
        RawShape::Prefixed {
            prefixes,
            body,
            min,
            max,
        } => {
            if prefixes.is_empty() {
                return Err(Error::unusable(id, "needs at least one prefix"));
            }
            let prefixes = prefixes
                .iter()
                .map(|prefix| literal(id, "prefix", prefix))
                .collect::<Result<Vec<_>>>()?;
            Ok(Shape::Prefixed {
                prefixes,
                body: class(id, "body", &body)?,
                min,
                max: bounds(id, min, max)?,
            })
        }
        RawShape::Block { start, end } => Ok(Shape::Block {
            start: literal(id, "start", &start)?,
            end: literal(id, "end", &end)?,
        }),
        RawShape::Infix {
            infix,
            left,
            left_min,
            right,
            right_min,
            right_must_contain,
            right_trim,
        } => {
            if left_min == 0 || right_min == 0 {
                // A zero minimum on either side turns the rule into "mask every occurrence of the
                // infix", which is not a shape.
                return Err(Error::unusable(
                    id,
                    "left_min and right_min must be at least 1",
                ));
            }
            Ok(Shape::Infix {
                infix: literal(id, "infix", &infix)?,
                left: class(id, "left", &left)?,
                left_min,
                right: class(id, "right", &right)?,
                right_min,
                must_contain: ascii(id, "right_must_contain", &right_must_contain)?,
                trim: ascii(id, "right_trim", &right_trim)?,
            })
        }
        RawShape::Grouped {
            min,
            max,
            separators,
        } => {
            if min == 0 {
                return Err(Error::unusable(id, "min must be at least 1"));
            }
            Ok(Shape::Grouped {
                min,
                max: bounds(id, min, max)?,
                separators: ascii(id, "separators", &separators)?,
            })
        }
    }
}

/// Checks a run's bounds.
fn bounds(id: &str, min: usize, max: usize) -> Result<usize> {
    if max < min {
        return Err(Error::unusable(
            id,
            format!("max ({max}) is below min ({min}), so nothing can match"),
        ));
    }
    Ok(max)
}

/// Checks a class name.
fn class(id: &str, field: &str, name: &str) -> Result<Class> {
    Class::parse(name).ok_or_else(|| {
        Error::unusable(
            id,
            format!(
                "{field} names an unknown class `{name}`; known: token, base64, hex, digit, upper, \
                 local, host, line"
            ),
        )
    })
}

/// Checks a literal that has to be present to anchor a match.
fn literal(id: &str, field: &str, value: &str) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Err(Error::unusable(id, format!("{field} cannot be empty")));
    }
    ascii(id, field, value)
}

/// Checks that a policy literal is ASCII, which is what makes byte-wise matching UTF-8 safe.
fn ascii(id: &str, field: &str, value: &str) -> Result<Vec<u8>> {
    if value.is_ascii() {
        Ok(value.as_bytes().to_vec())
    } else {
        Err(Error::unusable(
            id,
            format!("{field} must be ASCII; `{value}` is not"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{Class, Policy};

    /// A policy with one rule of the named kind, for the validation cases below.
    fn parse(rule: &str) -> crate::Result<Policy> {
        Policy::parse(&format!(
            "version = \"t\"\nplaceholder = \"[x]\"\n\n[[rule]]\n{rule}\n"
        ))
    }

    #[test]
    fn the_shipped_policy_is_usable() {
        // The one test that has to exist: `Policy::shipped` unwraps, so a fault in the file it
        // embeds has to fail here rather than at startup.
        let policy = Policy::shipped();
        assert_eq!(policy.version(), "egress-v1");
        assert!(
            policy.rules().len() >= 6,
            "the shipped policy should cover every pattern class the plan names"
        );
    }

    #[test]
    fn a_placeholder_names_the_rule_that_matched() {
        assert_eq!(
            Policy::shipped().placeholder_for("chat-token"),
            "[redacted:chat-token]"
        );
    }

    #[test]
    fn rules_keep_the_order_they_were_declared_in() {
        let ids: Vec<_> = Policy::shipped()
            .rules()
            .iter()
            .map(|rule| rule.id().to_string())
            .collect();
        assert_eq!(ids.first().map(String::as_str), Some("chat-token"));
    }

    #[test]
    fn a_policy_that_is_not_toml_is_refused() {
        let error = Policy::parse("this is not toml").expect_err("parse fails");
        assert!(
            error.to_string().starts_with("cannot parse policy:"),
            "{error}"
        );
    }

    #[test]
    fn a_policy_with_no_version_is_refused() {
        let error =
            Policy::parse("version = \" \"\nplaceholder = \"[x]\"\n").expect_err("parse fails");
        assert_eq!(
            error.to_string(),
            "cannot parse policy: policy has no version"
        );
    }

    #[test]
    fn a_policy_with_no_rules_parses_and_masks_nothing() {
        let policy = Policy::parse("version = \"t\"\nplaceholder = \"[x]\"\n").expect("parse");
        assert!(policy.rules().is_empty());
    }

    #[test]
    fn a_rule_with_no_id_is_refused() {
        let error = parse("id = \"\"\nkind = \"block\"\nstart = \"a\"\nend = \"b\"")
            .expect_err("parse fails");
        assert_eq!(error.to_string(), "cannot parse policy: a rule has no id");
    }

    #[test]
    fn two_rules_cannot_share_an_id() {
        let error = Policy::parse(
            "version = \"t\"\nplaceholder = \"[x]\"\n\
             [[rule]]\nid = \"dup\"\nkind = \"block\"\nstart = \"a\"\nend = \"b\"\n\
             [[rule]]\nid = \"dup\"\nkind = \"block\"\nstart = \"c\"\nend = \"d\"\n",
        )
        .expect_err("parse fails");
        assert_eq!(error.to_string(), "rule `dup`: declared twice");
    }

    #[test]
    fn a_prefixed_rule_needs_a_prefix() {
        let error = parse(
            "id = \"r\"\nkind = \"prefixed\"\nprefixes = []\nbody = \"token\"\nmin = 1\nmax = 2",
        )
        .expect_err("parse fails");
        assert_eq!(error.to_string(), "rule `r`: needs at least one prefix");
    }

    #[test]
    fn an_empty_prefix_is_refused() {
        let error = parse(
            "id = \"r\"\nkind = \"prefixed\"\nprefixes = [\"\"]\nbody = \"token\"\nmin = 1\n\
             max = 2",
        )
        .expect_err("parse fails");
        assert_eq!(error.to_string(), "rule `r`: prefix cannot be empty");
    }

    #[test]
    fn a_non_ascii_literal_is_refused() {
        // Matching runs byte-wise, so a non-ASCII literal is the one way a match could land inside
        // a character. Refused at load instead.
        let error = parse(
            "id = \"r\"\nkind = \"prefixed\"\nprefixes = [\"kée-\"]\nbody = \"token\"\nmin = 1\n\
             max = 2",
        )
        .expect_err("parse fails");
        assert_eq!(
            error.to_string(),
            "rule `r`: prefix must be ASCII; `kée-` is not"
        );
    }

    #[test]
    fn an_unknown_class_is_refused() {
        let error = parse(
            "id = \"r\"\nkind = \"prefixed\"\nprefixes = [\"p-\"]\nbody = \"runes\"\nmin = 1\n\
             max = 2",
        )
        .expect_err("parse fails");
        assert!(
            error
                .to_string()
                .starts_with("rule `r`: body names an unknown class `runes`"),
            "{error}"
        );
    }

    #[test]
    fn bounds_that_cannot_be_met_are_refused() {
        let error = parse(
            "id = \"r\"\nkind = \"prefixed\"\nprefixes = [\"p-\"]\nbody = \"token\"\nmin = 9\n\
             max = 4",
        )
        .expect_err("parse fails");
        assert_eq!(
            error.to_string(),
            "rule `r`: max (4) is below min (9), so nothing can match"
        );
    }

    #[test]
    fn an_empty_block_marker_is_refused() {
        let error =
            parse("id = \"r\"\nkind = \"block\"\nstart = \"\"\nend = \"e\"").expect_err("fails");
        assert_eq!(error.to_string(), "rule `r`: start cannot be empty");
    }

    #[test]
    fn an_infix_rule_with_a_zero_minimum_is_refused() {
        let error = parse(
            "id = \"r\"\nkind = \"infix\"\ninfix = \"@\"\nleft = \"local\"\nleft_min = 0\n\
             right = \"host\"\nright_min = 4",
        )
        .expect_err("parse fails");
        assert_eq!(
            error.to_string(),
            "rule `r`: left_min and right_min must be at least 1"
        );
    }

    #[test]
    fn a_grouped_rule_with_a_zero_minimum_is_refused() {
        let error = parse("id = \"r\"\nkind = \"grouped\"\nmin = 0\nmax = 4\nseparators = \" \"")
            .expect_err("parse fails");
        assert_eq!(error.to_string(), "rule `r`: min must be at least 1");
    }

    #[test]
    fn a_non_ascii_separator_is_refused() {
        let error = parse("id = \"r\"\nkind = \"grouped\"\nmin = 2\nmax = 4\nseparators = \"·\"")
            .expect_err("parse fails");
        assert_eq!(
            error.to_string(),
            "rule `r`: separators must be ASCII; `·` is not"
        );
    }

    #[test]
    fn an_unreadable_policy_names_the_path_it_tried() {
        let error =
            Policy::load(std::path::Path::new("/nonexistent/egress.toml")).expect_err("load fails");
        assert!(
            error
                .to_string()
                .starts_with("cannot read policy /nonexistent/egress.toml:"),
            "{error}"
        );
    }

    #[test]
    fn a_policy_on_disk_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("egress.toml");
        std::fs::write(&path, "version = \"disk-v1\"\nplaceholder = \"[x]\"\n").expect("write");
        let policy = Policy::load(&path).expect("load");
        assert_eq!(policy.version(), "disk-v1");
    }

    #[test]
    fn classes_hold_what_they_say_they_do() {
        assert!(Class::Token.holds(b'-') && !Class::Token.holds(b'.'));
        assert!(Class::Base64.holds(b'+') && Class::Base64.holds(b'='));
        assert!(Class::Hex.holds(b'f') && !Class::Hex.holds(b'g'));
        assert!(Class::Digit.holds(b'7') && !Class::Digit.holds(b'x'));
        assert!(Class::Upper.holds(b'Q') && !Class::Upper.holds(b'q'));
        assert!(Class::Local.holds(b'%') && !Class::Local.holds(b'@'));
        assert!(Class::Host.holds(b'.') && !Class::Host.holds(b'_'));
        assert!(Class::Line.holds(b' ') && !Class::Line.holds(b'\n'));
    }
}
