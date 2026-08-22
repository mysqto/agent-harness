//! Canonicalisation: the pluggable, versioned front half of pseudonym derivation.

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::error::{Error, Result};

/// Version of the canonicalisation ruleset that produced a subject hash.
///
/// Stamped per subject rather than per record: one re-keyed record can legitimately carry subjects
/// resolved under different rulesets, so a per-record field could not describe it.
///
/// It is not decoration. The pseudonym is a pure function of the canonical identifier, so a change
/// to the rules makes the same person hash differently before and after — and hashes already
/// embedded in paths and in never-deleted tombstones cannot be recomputed. What makes that a priced
/// migration rather than silent data loss is being able to say *which* function produced a given
/// hash, so a lookup can enumerate the live versions instead of guessing. Records written without a
/// version are the unrecoverable case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CanonVer(pub u32);

/// A versioned rule for reducing a raw subject identifier to its canonical form.
///
/// Pluggable because what a subject *is* is not settled, and a rule set that has to serve an
/// identifier shape nobody has chosen yet is better swapped than widened. Implementations are
/// type-agnostic: they see a string, not a kind.
///
/// # Implementing one
///
/// Two obligations, and both are about versioning rather than about text:
///
/// - [`Canonicaliser::version`] must be **constant for a given rule set** and must change whenever
///   the rules change, however slightly. Editing an existing implementation's behaviour without
///   bumping its version is the one-way door: old records keep a hash the new rules can no longer
///   reproduce, and nothing marks them as unreachable.
/// - The output must be **idempotent** — canonicalising a canonical form returns it unchanged.
///   Without that, a re-derivation on a value already through the pipe yields a second pseudonym for
///   one subject. [`Minimal`] is tested for it and a new implementation should be too.
///
/// Old versions are never retired: they stay registered so [`Registry::derive_all`] can still
/// produce the hashes under which historical records were filed.
pub trait Canonicaliser {
    /// The ruleset version this implementation realises.
    ///
    /// Owned by the implementation, never by the caller. A caller able to pass a version in could
    /// stamp a record with a number that does not describe how its hash was produced, which is
    /// exactly the state the field exists to rule out.
    fn version(&self) -> CanonVer;

    /// Reduces a raw identifier to its canonical form.
    ///
    /// # Errors
    /// [`Error::Empty`] if nothing survives the rules.
    fn canonicalise(&self, raw: &str) -> Result<String>;
}

/// The minimal ruleset: trim, NFC, lowercase, NFC again.
///
/// Minimal on purpose. Every live version is fan-out paid on every subject lookup and every erasure
/// sweep, forever, so the rules stop at the three differences that are pure spelling — surrounding
/// whitespace, letter case, and which Unicode encoding of the same character was typed.
///
/// # What it deliberately does not do
///
/// Each of these would be a real improvement for some identifier shape and a `canon_ver` bump to
/// add. They are listed because the omissions are choices, and a later reader needs to know they
/// were not oversights:
///
/// - **Interior whitespace is preserved.** `"a b"` and `"a  b"` stay distinct subjects.
/// - **Compatibility normalisation (NFK*) is not applied.** A non-breaking space inside the value,
///   or a full-width digit, stays as typed. NFKC would fold those, and would also fold distinctions
///   that matter in some identifier spaces, which is not a trade to make before knowing the space.
/// - **This is Unicode lowercasing, not Unicode case folding.** They differ for a small set of
///   characters — `ß` lowercases to itself where case folding maps it to `ss`. Lowercasing is the
///   conservative half: it merges strictly fewer identifiers, so switching to case folding later
///   merges subjects that version 1 kept apart, which is a migration and not a repair.
#[derive(Debug, Clone, Copy, Default)]
pub struct Minimal;

impl Minimal {
    /// The version [`Minimal`] realises.
    ///
    /// A `const` so it can be named without an instance — a registry, a test, or a migration script
    /// referring to "version 1" should not have to construct a canonicaliser to say so.
    pub const VERSION: CanonVer = CanonVer(1);
}

impl Canonicaliser for Minimal {
    fn version(&self) -> CanonVer {
        Self::VERSION
    }

    fn canonicalise(&self, raw: &str) -> Result<String> {
        // NFC runs twice because lowercasing is not guaranteed to preserve normalisation: it maps
        // per character and can emit a sequence with a composed form. Normalising last makes "the
        // output is NFC" a property of this function rather than an observation about the current
        // Unicode tables. NFC is idempotent, so the second pass costs a scan and changes nothing
        // when the first already settled it.
        let out: String = raw
            .trim()
            .nfc()
            .collect::<String>()
            .to_lowercase()
            .nfc()
            .collect();

        if out.is_empty() {
            return Err(Error::empty(Self::VERSION));
        }
        Ok(out)
    }
}

/// Every canonicalisation version that has ever been live, in one place.
///
/// A subject lookup cannot be an equality check once a second version exists: the same person holds
/// a different hash on either side of the bump, and everything that groups by pseudonym — the erasure
/// sweep, the key-minting blocklist, the tombstone check — has to fan out across the versions or it
/// fragments. The blocklist is the sharpest case: a record arriving under an *old* hash must still be
/// recognised, or it mints a fresh key for a subject already erased. Holding the versions together
/// makes that fan-out enumeration rather than something each call site remembers to do.
pub struct Registry {
    /// Superseded rulesets, ascending by version. Kept for the fan-out, never written under.
    older: Vec<Box<dyn Canonicaliser + Send + Sync>>,
    /// The highest version, split out so "there is always a current ruleset" is a property of the
    /// type rather than a comment beside an `expect`.
    current: Box<dyn Canonicaliser + Send + Sync>,
}

impl Registry {
    /// Builds a registry from every live ruleset.
    ///
    /// # Errors
    /// [`Error::EmptyRegistry`] if none are supplied, [`Error::DuplicateVersion`] if two claim the
    /// same version.
    pub fn new(rules: Vec<Box<dyn Canonicaliser + Send + Sync>>) -> Result<Self> {
        let mut sorted = rules;
        sorted.sort_by_key(|r| r.version());
        if let Some(pair) = sorted.windows(2).find(|w| w[0].version() == w[1].version()) {
            return Err(Error::DuplicateVersion(pair[0].version().0));
        }
        let current = sorted.pop().ok_or(Error::EmptyRegistry)?;
        Ok(Self {
            older: sorted,
            current,
        })
    }

    /// The highest version present — the one new records are written under.
    #[must_use]
    pub fn current(&self) -> &(dyn Canonicaliser + Send + Sync) {
        self.current.as_ref()
    }

    /// Every live version, ascending.
    pub fn versions(&self) -> impl Iterator<Item = CanonVer> + '_ {
        self.rulesets().map(Canonicaliser::version)
    }

    /// Every live ruleset, ascending by version.
    fn rulesets(&self) -> impl Iterator<Item = &(dyn Canonicaliser + Send + Sync)> + '_ {
        self.older
            .iter()
            .chain(core::iter::once(&self.current))
            .map(AsRef::as_ref)
    }

    /// Canonicalises under every live ruleset, ascending by version.
    ///
    /// The current ruleset must accept: a new record is filed under it, so its refusal is the
    /// identifier's refusal. A superseded ruleset that refuses is skipped instead — it could never
    /// have produced a hash for this subject, so there is nothing for a sweep to reach under it, and
    /// failing the whole lookup would make an old ruleset able to block an erasure.
    ///
    /// # Errors
    /// Whatever the current ruleset refuses.
    pub fn canonicalise_all(&self, raw: &str) -> Result<Vec<(CanonVer, String)>> {
        let current = self.current.canonicalise(raw)?;
        let mut out: Vec<_> = self
            .older
            .iter()
            .filter_map(|r| r.canonicalise(raw).ok().map(|c| (r.version(), c)))
            .collect();
        out.push((self.current.version(), current));
        Ok(out)
    }
}

impl core::fmt::Debug for Registry {
    /// Prints the versions, since a boxed trait object has nothing else to show.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Registry")
            .field("versions", &self.versions().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A second ruleset, so version behaviour can be tested without waiting for a real one.
    #[derive(Debug)]
    struct Stub(u32);

    impl Canonicaliser for Stub {
        fn version(&self) -> CanonVer {
            CanonVer(self.0)
        }
        fn canonicalise(&self, raw: &str) -> Result<String> {
            if raw.trim().is_empty() {
                return Err(Error::empty(self.version()));
            }
            Ok(raw.trim().to_owned())
        }
    }

    #[test]
    fn version_is_one_and_comes_from_the_ruleset() {
        assert_eq!(Minimal.version(), CanonVer(1));
        assert_eq!(Minimal::VERSION, CanonVer(1));
    }

    #[test]
    fn surrounding_whitespace_is_removed() {
        for raw in [
            "  subject-a  ",
            "\tsubject-a\n",
            "\u{a0}subject-a\u{a0}", // non-breaking space is White_Space, so trim reaches it
            "\u{2009}subject-a",     // thin space
            "subject-a\r\n",
        ] {
            assert_eq!(
                Minimal.canonicalise(raw).expect("non-empty"),
                "subject-a",
                "{raw:?}"
            );
        }
    }

    #[test]
    fn case_is_folded() {
        assert_eq!(Minimal.canonicalise("SUBJECT-A").unwrap(), "subject-a");
        assert_eq!(Minimal.canonicalise("Subject-A").unwrap(), "subject-a");
        // Non-ASCII case mapping, not just the 26 letters.
        assert_eq!(Minimal.canonicalise("ÉLÈVE").unwrap(), "élève");
    }

    #[test]
    fn unicode_forms_converge() {
        let composed = "\u{e9}"; // é
        let decomposed = "e\u{301}"; // e + combining acute
        assert_ne!(composed, decomposed);
        assert_eq!(
            Minimal.canonicalise(composed).unwrap(),
            Minimal.canonicalise(decomposed).unwrap()
        );
        // And a form difference behind a case difference and padding, which is where the three
        // rules have to compose rather than merely each work.
        assert_eq!(
            Minimal.canonicalise("  E\u{301}LE\u{300}VE\t").unwrap(),
            Minimal.canonicalise("\u{e9}l\u{e8}ve").unwrap()
        );
    }

    #[test]
    fn output_is_nfc_and_idempotent() {
        for raw in [
            " E\u{301}Le\u{300}ve ",
            "SUBJECT-A",
            "\u{1e9e}", // capital sharp s, which lowercases to ß
            "\u{130}",  // capital I with dot above, which lowercases to a two-code-point sequence
            "\u{fb01}", // ﬁ ligature: NFC leaves it alone, NFKC would not
        ] {
            let once = Minimal.canonicalise(raw).expect("non-empty");
            let twice = Minimal.canonicalise(&once).expect("non-empty");
            assert_eq!(once, twice, "not idempotent for {raw:?}");
            assert_eq!(
                once.nfc().collect::<String>(),
                once,
                "output not NFC for {raw:?}"
            );
        }
    }

    #[test]
    fn distinct_identifiers_stay_distinct() {
        let mut seen = std::collections::BTreeSet::new();
        for raw in [
            "subject-a",
            "subject-b",
            "subject-a1",
            "a b",
            "a  b", // interior whitespace is preserved: documented, and asserted so it stays true
            "\u{fb01}x",
            "fix",
        ] {
            assert!(
                seen.insert(Minimal.canonicalise(raw).expect("non-empty")),
                "{raw:?} collided with an earlier identifier"
            );
        }
    }

    #[test]
    fn empty_and_blank_are_refused() {
        for raw in ["", " ", "\t\n", "\u{a0}", "   \u{2009} "] {
            assert_eq!(
                Minimal.canonicalise(raw),
                Err(Error::Empty { ver: 1 }),
                "{raw:?} must be refused, not collapsed to a shared pseudonym"
            );
        }
    }

    #[test]
    fn registry_orders_by_version_and_reports_the_current_one() {
        let reg = Registry::new(vec![
            Box::new(Stub(3)),
            Box::new(Minimal),
            Box::new(Stub(2)),
        ])
        .expect("distinct versions");
        assert_eq!(
            reg.versions().collect::<Vec<_>>(),
            vec![CanonVer(1), CanonVer(2), CanonVer(3)]
        );
        assert_eq!(reg.current().version(), CanonVer(3));
        assert!(format!("{reg:?}").contains("CanonVer(3)"));
    }

    #[test]
    fn registry_refuses_a_duplicated_version() {
        let err = Registry::new(vec![Box::new(Minimal), Box::new(Stub(1))]).expect_err("duplicate");
        assert_eq!(err, Error::DuplicateVersion(1));
        assert_eq!(
            Registry::new(vec![]).expect_err("empty"),
            Error::EmptyRegistry
        );
    }

    #[test]
    fn canonicalise_all_covers_every_version() {
        let reg = Registry::new(vec![Box::new(Minimal), Box::new(Stub(2))]).unwrap();
        // Stub does not lowercase, so the two versions genuinely disagree — which is the point.
        assert_eq!(
            reg.canonicalise_all(" Subject-A ").unwrap(),
            vec![
                (CanonVer(1), "subject-a".to_owned()),
                (CanonVer(2), "Subject-A".to_owned())
            ]
        );
    }

    #[test]
    fn canonicalise_all_fails_when_the_current_version_refuses() {
        let reg = Registry::new(vec![Box::new(Minimal), Box::new(Stub(2))]).unwrap();
        assert_eq!(
            reg.canonicalise_all("  ").unwrap_err(),
            Error::Empty { ver: 2 }
        );
    }

    #[test]
    fn canonicalise_all_skips_a_version_that_refuses() {
        /// A superseded ruleset that refuses everything, standing in for one an identifier shape
        /// postdates.
        #[derive(Debug)]
        struct Refuses;
        impl Canonicaliser for Refuses {
            fn version(&self) -> CanonVer {
                CanonVer(0)
            }
            fn canonicalise(&self, _raw: &str) -> Result<String> {
                Err(Error::empty(self.version()))
            }
        }
        let reg = Registry::new(vec![Box::new(Minimal), Box::new(Refuses)]).unwrap();
        assert_eq!(
            reg.canonicalise_all("subject-a").unwrap(),
            vec![(CanonVer(1), "subject-a".to_owned())]
        );
    }

    #[test]
    fn canon_ver_serialises_as_a_bare_integer() {
        // The store's schema types it `integer`, not an object wrapping one.
        assert_eq!(serde_json::to_string(&CanonVer(1)).unwrap(), "1");
        assert_eq!(serde_json::from_str::<CanonVer>("7").unwrap(), CanonVer(7));
    }
}
