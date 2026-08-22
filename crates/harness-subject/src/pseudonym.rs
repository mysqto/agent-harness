//! Derivation: the keyed back half, and the wire shape the store accepts.

use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::canon::{CanonVer, Canonicaliser, Registry};
use crate::error::{Error, Result};

/// Required length of the keying secret, in bytes — SHA-256's output size.
///
/// Fixed rather than "at least": a fixed size is what lets the secret live in an array whose `Drop`
/// can reliably clear it, where a `Vec` may already have been reallocated and left a copy behind.
pub const KEY_LEN: usize = 32;

/// The set a derived pseudonym belongs to, as the store's schema spells it.
///
/// Restated here rather than shared, because the two sides deliberately do not link: this repo
/// depends on no crate of the store's, and they talk over a socket. A copy that drifts is the cost;
/// a shared mount that bypasses every control at the boundary is the alternative.
pub const SUBJECT_HASH_PATTERN: &str = "^s_[0-9a-f]{64}$";

/// Prefix that marks a string as a pseudonym rather than a raw identifier.
const PREFIX: &str = "s_";

/// Lowercase hex alphabet. The store's pattern admits no other case.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Domain separator, so this HMAC key cannot be made to produce a tag another use of the same key
/// would also produce. Fixed length, which is what makes the framing below unambiguous.
const DOMAIN: &[u8; 16] = b"subject-pseudo:1";

/// The keying secret that turns a canonical identifier into a pseudonym.
///
/// It never leaves this side. The store is handed the tag and the version; it is never handed, and
/// has no use for, the means to compute either. That asymmetry is the whole reason canonicalisation
/// and derivation sit in the writer rather than in the store.
///
/// Not rotatable in practice, once its outputs are embedded in paths and in tombstones that are
/// never deleted. It follows that a leak is retroactive across every backup ever taken, and that
/// this type should be as hard to print as it is easy to use:
///
/// - [`Debug`] is hand-written and redacts. A derived `Debug` on a struct holding this would
///   otherwise dump the secret into the first log line that formatted it.
/// - There is no [`Display`], no `as_bytes`, and no [`Clone`]. The bytes go in and tags come out.
/// - The bytes are cleared on drop.
///
/// [`Display`]: core::fmt::Display
#[derive(ZeroizeOnDrop)]
pub struct SubjectKey {
    /// Raw HMAC key material.
    key: [u8; KEY_LEN],
}

impl SubjectKey {
    /// Takes the secret from raw bytes.
    ///
    /// # Errors
    /// [`Error::KeyLength`] unless exactly [`KEY_LEN`] bytes are supplied. Padding a short secret
    /// to length would hide that the deployment is running on less entropy than it thinks.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key: [u8; KEY_LEN] = bytes.try_into().map_err(|_| Error::KeyLength {
            expected: KEY_LEN,
            got: bytes.len(),
        })?;
        Ok(Self { key })
    }

    /// Takes the secret from lowercase hex, which is how a key store hands one over.
    ///
    /// # Errors
    /// [`Error::KeyNotHex`] on a non-hex digit or an odd length, [`Error::KeyLength`] on the wrong
    /// number of bytes.
    pub fn from_hex(hex: &str) -> Result<Self> {
        if !hex.len().is_multiple_of(2) {
            return Err(Error::KeyNotHex);
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        let digits = hex.as_bytes();
        for pair in digits.chunks_exact(2) {
            let hi = hex_digit(pair[0]).ok_or(Error::KeyNotHex)?;
            let lo = hex_digit(pair[1]).ok_or(Error::KeyNotHex)?;
            bytes.push(hi << 4 | lo);
        }
        let out = Self::from_bytes(&bytes);
        // The decode buffer held the secret too, and it outlives the borrow above.
        bytes.zeroize();
        out
    }

    /// Canonicalises under `canon`, then derives the pseudonym.
    ///
    /// The version is read off the canonicaliser that actually ran and travels with the tag, so a
    /// hash cannot be recorded under a version that did not produce it.
    ///
    /// # Errors
    /// Whatever `canon` refuses.
    pub fn derive<C>(&self, canon: &C, raw: &str) -> Result<Pseudonym>
    where
        C: Canonicaliser + ?Sized,
    {
        let ver = canon.version();
        Ok(self.tag(ver, &canon.canonicalise(raw)?))
    }

    /// Derives under every live ruleset in `registry`, ascending by version.
    ///
    /// This is the fan-out an erasure sweep, a key-minting blocklist check, or any other lookup that
    /// groups by pseudonym has to perform once a second version exists.
    ///
    /// # Errors
    /// The first refusal, when every ruleset refuses.
    pub fn derive_all(&self, registry: &Registry, raw: &str) -> Result<Vec<Pseudonym>> {
        Ok(registry
            .canonicalise_all(raw)?
            .iter()
            .map(|(ver, canon)| self.tag(*ver, canon))
            .collect())
    }

    /// HMAC-SHA256 over the version and the canonical identifier.
    ///
    /// The version is an *input*, not just a label. Two rulesets that happened to agree on some
    /// identifier would otherwise emit the same tag for it, and a version bump would be a real
    /// migration for some subjects and a no-op for others — which is worse than either, because the
    /// fan-out would silently return one hash where callers reason about two. Folding the version in
    /// makes a bump uniformly a migration.
    ///
    /// Framing is by fixed width rather than by separator: the first 16 bytes are the domain, the
    /// next 4 are the version big-endian, the rest is the identifier. A separator byte would have to
    /// be one the identifier cannot contain, and nothing about the identifier space is settled.
    fn tag(&self, ver: CanonVer, canonical: &str) -> Pseudonym {
        let mut mac = <Hmac<Sha256>>::new_from_slice(&self.key)
            .expect("HMAC-SHA256 accepts a key of any length");
        mac.update(DOMAIN);
        mac.update(&ver.0.to_be_bytes());
        mac.update(canonical.as_bytes());

        let mut hash = String::with_capacity(PREFIX.len() + 64);
        hash.push_str(PREFIX);
        for byte in mac.finalize().into_bytes() {
            // Lowercase hex, untruncated: one spelling per hash is what lets it serve as a map key
            // and a path component with no normalisation step a caller could forget.
            hash.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            hash.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
        Pseudonym {
            hash: SubjectHash(hash),
            canon_ver: ver,
        }
    }
}

/// Decodes one lowercase hex digit.
const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

impl core::fmt::Debug for SubjectKey {
    /// Redacts. The length is safe to print and is the thing an operator is actually debugging.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SubjectKey({KEY_LEN} bytes, redacted)")
    }
}

/// A keyed pseudonym for an erasable data subject.
///
/// Never a direct identifier: an HMAC over a canonical subject identifier, so it is safe in paths,
/// indexes and tombstones. Pseudonymous, not anonymous — whoever holds the keying secret can still
/// relink it, which is a property callers must reason about rather than forget.
///
/// The only way to obtain one is to derive it. There is no parse path, because on this side of the
/// boundary every hash is minted here; a constructor taking a string would be a way for an
/// unvalidated identifier to arrive wearing a pseudonym's type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct SubjectHash(String);

impl SubjectHash {
    /// The hash as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for SubjectHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A derived pseudonym together with the ruleset version that produced it.
///
/// The pair is the unit, and that is the point of the type: a `SubjectHash` on its own cannot say
/// which function made it, and a hash whose function is unknown is the one state no migration
/// recovers from. Keeping them together means the version cannot be dropped on the floor between
/// derivation and the wire.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pseudonym {
    /// The tag.
    hash: SubjectHash,
    /// The ruleset that produced it.
    canon_ver: CanonVer,
}

impl Pseudonym {
    /// The pseudonym.
    #[must_use]
    pub const fn hash(&self) -> &SubjectHash {
        &self.hash
    }

    /// The ruleset version that produced it.
    #[must_use]
    pub const fn canon_ver(&self) -> CanonVer {
        self.canon_ver
    }

    /// Attaches a role, giving the object the store's schema expects inside `subjects`.
    #[must_use]
    pub fn with_role(self, role: SubjectRole) -> SubjectRef {
        SubjectRef {
            hash: self.hash,
            role,
            canon_ver: self.canon_ver,
        }
    }
}

/// How a subject relates to the record naming it.
///
/// Not what the subject *is* — that is unsettled, and nothing here depends on it. These two spellings
/// are the store's schema, which refuses anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectRole {
    /// Acted, or was acted for.
    Principal,
    /// Named by the record without being its subject.
    Party,
}

/// One entry of a record's `subjects` list, as the store accepts it.
///
/// Serialise-only, deliberately. This side writes records and never reads one back, and a
/// deserialiser would be a second, untested way for a hash to enter the system — the one thing the
/// absence of a `SubjectHash` parse path is there to prevent.
///
/// The store refuses unknown fields inside `subjects`, so the field set here is exact rather than a
/// superset: three fields, all required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SubjectRef {
    /// The pseudonym.
    pub hash: SubjectHash,
    /// How the subject relates to the record.
    pub role: SubjectRole,
    /// Which ruleset produced `hash`.
    pub canon_ver: CanonVer,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::Minimal;

    /// Test key. Non-uniform so a byte-order bug in derivation shows up as a changed tag.
    const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    /// A second key, to prove the tag is keyed rather than a plain hash.
    const OTHER_HEX: &str = "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// Stands in for any struct that ends up holding the secret and deriving `Debug`.
    #[derive(Debug)]
    struct Holder {
        #[expect(
            dead_code,
            reason = "only the derived Debug reads it, which is the point"
        )]
        key: SubjectKey,
    }

    fn key() -> SubjectKey {
        SubjectKey::from_hex(KEY_HEX).expect("32 bytes of hex")
    }

    /// Checks a string against [`SUBJECT_HASH_PATTERN`] by hand, so the crate carries no regex
    /// dependency for one assertion — and so the pattern the store publishes is actually exercised
    /// here rather than merely quoted in a doc comment.
    fn matches_wire_pattern(s: &str) -> bool {
        assert_eq!(SUBJECT_HASH_PATTERN, "^s_[0-9a-f]{64}$", "pattern edited");
        let Some(digits) = s.strip_prefix("s_") else {
            return false;
        };
        digits.len() == 64
            && digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    #[test]
    fn the_derived_hash_matches_the_shape_the_store_accepts() {
        let p = key().derive(&Minimal, "subject-a").expect("derivable");
        assert!(
            matches_wire_pattern(p.hash().as_str()),
            "{} is not accepted by {SUBJECT_HASH_PATTERN}",
            p.hash()
        );
        assert_eq!(p.hash().as_str().len(), 66);
        assert_eq!(p.canon_ver(), CanonVer(1));
    }

    #[test]
    fn spelling_differences_derive_one_pseudonym() {
        let key = key();
        let expected = key.derive(&Minimal, "subject-a").unwrap();
        for variant in [
            "  subject-a  ",
            "SUBJECT-A",
            "\tSubject-A\n",
            "\u{a0}subject-a",
        ] {
            assert_eq!(
                key.derive(&Minimal, variant).unwrap(),
                expected,
                "{variant:?} must not be a second subject"
            );
        }

        // The Unicode-form case, which is the one no amount of ASCII care would have caught.
        assert_eq!(
            key.derive(&Minimal, "\u{e9}lève").unwrap(),
            key.derive(&Minimal, " E\u{301}L\u{c8}VE ").unwrap()
        );
    }

    #[test]
    fn genuinely_different_identifiers_do_not_collide() {
        let key = key();
        let mut seen = std::collections::BTreeSet::new();
        for raw in [
            "subject-a",
            "subject-b",
            "subject-a1",
            "1subject-a",
            "a b",
            "a  b",
            "subject_a",
        ] {
            let p = key.derive(&Minimal, raw).unwrap();
            assert!(seen.insert(p.hash().clone()), "{raw:?} collided");
        }
    }

    #[test]
    fn a_different_canon_ver_derives_a_different_pseudonym() {
        /// Version 2 with version 1's rules, so only the version differs.
        #[derive(Debug)]
        struct SameRulesNewVersion;
        impl Canonicaliser for SameRulesNewVersion {
            fn version(&self) -> CanonVer {
                CanonVer(2)
            }
            fn canonicalise(&self, raw: &str) -> Result<String> {
                Minimal.canonicalise(raw)
            }
        }

        let key = key();
        let v1 = key.derive(&Minimal, "subject-a").unwrap();
        let v2 = key.derive(&SameRulesNewVersion, "subject-a").unwrap();
        assert_eq!(
            v1.hash().as_str().len(),
            v2.hash().as_str().len(),
            "both are still wire-shaped"
        );
        // This is what makes a version bump a migration rather than a relabelling: identical rules
        // and identical input still land on a different pseudonym.
        assert_ne!(v1.hash(), v2.hash());
        assert_eq!(v2.canon_ver(), CanonVer(2));
    }

    #[test]
    fn the_tag_is_keyed() {
        let other = SubjectKey::from_hex(OTHER_HEX).unwrap();
        assert_ne!(
            key().derive(&Minimal, "subject-a").unwrap().hash(),
            other.derive(&Minimal, "subject-a").unwrap().hash()
        );
    }

    #[test]
    fn derivation_is_a_pure_function() {
        // The property the whole design rests on: no state, so nothing to restore wrong and no way
        // for one subject to acquire two pseudonyms under one version.
        assert_eq!(
            key().derive(&Minimal, "subject-a").unwrap(),
            key().derive(&Minimal, "subject-a").unwrap()
        );
    }

    #[test]
    fn the_hash_is_stable_across_runs() {
        // A golden vector. Without it a refactor of the framing in `tag` would rewrite every
        // pseudonym the deployment has ever emitted, and every test above would still pass.
        assert_eq!(
            key()
                .derive(&Minimal, " Subject-A ")
                .unwrap()
                .hash()
                .as_str(),
            "s_a3d76dc902b38605bdde755c1b13e0a8215a82a003e74d3d815b98376b09ead0"
        );
    }

    #[test]
    fn derive_all_fans_out_across_versions() {
        /// A second live ruleset that trims but does not fold case.
        #[derive(Debug)]
        struct V2;
        impl Canonicaliser for V2 {
            fn version(&self) -> CanonVer {
                CanonVer(2)
            }
            fn canonicalise(&self, raw: &str) -> Result<String> {
                let out = raw.trim();
                if out.is_empty() {
                    return Err(Error::Empty { ver: 2 });
                }
                Ok(out.to_owned())
            }
        }

        let reg = Registry::new(vec![Box::new(Minimal), Box::new(V2)]).unwrap();
        let key = key();
        let all = key.derive_all(&reg, " Subject-A ").unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].canon_ver(), CanonVer(1));
        assert_eq!(all[1].canon_ver(), CanonVer(2));
        assert_ne!(all[0].hash(), all[1].hash());
        // The current version's hash is the one a new record is filed under.
        assert_eq!(&all[1], &key.derive(reg.current(), " Subject-A ").unwrap());

        assert_eq!(
            key.derive_all(&reg, "   ").unwrap_err(),
            Error::Empty { ver: 2 },
            "the current ruleset's refusal is the identifier's refusal"
        );
    }

    #[test]
    fn the_keying_secret_is_absent_from_debug_output() {
        let key = key();
        let printed = format!("{key:?}");
        assert_eq!(printed, "SubjectKey(32 bytes, redacted)");
        // Every spelling the secret could plausibly have been rendered in.
        assert!(!printed.contains(KEY_HEX));
        assert!(!printed.contains("0001020304"));
        assert!(!printed.contains(&KEY_HEX.to_uppercase()));
        assert!(
            !printed.contains("0, 1, 2"),
            "not the array debug form either"
        );

        // And inside a struct that holds it, which is how a leak would actually happen: not by
        // printing the secret, but by printing something that contains it.
        let held = format!("{:?}", Holder { key });
        assert!(!held.contains(KEY_HEX), "{held}");
        assert!(!held.contains("0001020304"), "{held}");
    }

    #[test]
    fn a_pseudonym_never_carries_the_identifier_it_came_from() {
        let p = key().derive(&Minimal, "subject-a").unwrap();
        let printed = format!("{p:?}");
        assert!(!printed.contains("subject-a"), "{printed}");
        assert_eq!(p.hash().to_string(), p.hash().as_str());
    }

    #[test]
    fn key_length_is_enforced() {
        assert_eq!(
            SubjectKey::from_bytes(&[0; 31]).unwrap_err(),
            Error::KeyLength {
                expected: 32,
                got: 31
            }
        );
        assert_eq!(
            SubjectKey::from_bytes(&[0; 33]).unwrap_err(),
            Error::KeyLength {
                expected: 32,
                got: 33
            }
        );
        assert!(SubjectKey::from_bytes(&[0; 32]).is_ok());
    }

    #[test]
    fn hex_decoding_refuses_what_it_cannot_decode() {
        assert_eq!(SubjectKey::from_hex("abc").unwrap_err(), Error::KeyNotHex);
        assert_eq!(
            SubjectKey::from_hex(&"z".repeat(64)).unwrap_err(),
            Error::KeyNotHex
        );
        // Uppercase is refused rather than accepted, so one secret has one spelling.
        assert_eq!(
            SubjectKey::from_hex(&KEY_HEX.to_uppercase()).unwrap_err(),
            Error::KeyNotHex
        );
        assert_eq!(
            SubjectKey::from_hex("00").unwrap_err(),
            Error::KeyLength {
                expected: 32,
                got: 1
            }
        );
        // Hex and raw bytes are two spellings of one secret, and must agree.
        let raw: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            SubjectKey::from_bytes(&raw)
                .unwrap()
                .derive(&Minimal, "subject-a")
                .unwrap(),
            key().derive(&Minimal, "subject-a").unwrap()
        );
    }

    #[test]
    fn a_subject_ref_serialises_to_exactly_the_three_fields_the_store_requires() {
        let json = serde_json::to_value(
            key()
                .derive(&Minimal, "subject-a")
                .unwrap()
                .with_role(SubjectRole::Principal),
        )
        .unwrap();

        let object = json.as_object().expect("an object");
        // The store refuses unknown fields inside `subjects`, so an extra key is a 422, not a
        // field the reader ignores.
        assert_eq!(object.len(), 3);
        assert!(matches_wire_pattern(object["hash"].as_str().unwrap()));
        assert_eq!(object["role"], "principal");
        assert_eq!(object["canon_ver"], 1);

        assert_eq!(
            serde_json::to_value(SubjectRole::Party).unwrap(),
            "party",
            "role spellings are the store's enum, not this crate's"
        );
    }
}
