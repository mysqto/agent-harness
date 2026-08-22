//! Per-agent signing keys, and the overlap that makes rotation survivable.
//!
//! A key here answers one question: *which agent produced this*. It answers nothing about whether
//! that agent may do what it asked — that is [`crate::authorize`], with the caller's role as its
//! input. Keeping the two apart is what stops key possession from becoming permission.
//!
//! Rotation overlaps on purpose. Replacing a key instantly means every request already in flight,
//! spooled, or retried under the old key fails at exactly the moment an operator is rotating
//! because they think something has leaked. So the retired key stays acceptable for
//! [`OVERLAP_MS`], and [`Keyring::verify`] says which key matched, so the lag is observable
//! instead of assumed.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::workspace::{MODE_KEY_FILE, mode_of};
use crate::{Error, Result, io};

/// How long a retired key stays acceptable: 24 hours, matching the design's rotation window.
pub const OVERLAP_MS: u64 = 24 * 60 * 60 * 1000;

/// Key length. 32 bytes, the block-independent output size of the hash underneath.
const KEY_LEN: usize = 32;

/// HMAC over SHA-256, which is what the store verifies against.
type Signer = Hmac<Sha256>;

/// Raw key material.
///
/// `Debug` prints the length and nothing else: a key in a log line is a leaked key, and this type
/// ends up inside structs that are otherwise natural to debug-print.
#[derive(Clone, PartialEq, Eq)]
struct Secret([u8; KEY_LEN]);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({KEY_LEN} bytes, redacted)")
    }
}

impl Secret {
    /// A fresh key from the system CSPRNG.
    fn generate() -> Result<Self> {
        let mut bytes = [0_u8; KEY_LEN];
        getrandom::fill(&mut bytes)
            .map_err(|err| Error::Key(format!("no randomness available: {err}")))?;
        Ok(Self(bytes))
    }

    /// Parses a hex key, rejecting anything that is not exactly one key's worth.
    fn parse(hex: &str) -> Result<Self> {
        if hex.len() != KEY_LEN * 2 {
            return Err(Error::Key(format!(
                "a key is {} hex characters, this is {}",
                KEY_LEN * 2,
                hex.len()
            )));
        }
        let mut bytes = [0_u8; KEY_LEN];
        for (slot, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
            let pair =
                std::str::from_utf8(pair).map_err(|_| Error::Key("key is not hex".to_owned()))?;
            *slot = u8::from_str_radix(pair, 16)
                .map_err(|_| Error::Key("key is not hex".to_owned()))?;
        }
        Ok(Self(bytes))
    }

    fn to_hex(&self) -> String {
        encode(&self.0)
    }

    /// The tag this key produces over `message`.
    fn tag(&self, message: &[u8]) -> Vec<u8> {
        // HMAC accepts a key of any length, so this cannot fail for a fixed-size key.
        let mut signer = <Signer as KeyInit>::new_from_slice(&self.0)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        signer.update(message);
        signer.finalize().into_bytes().to_vec()
    }

    /// Whether `tag` is this key's tag for `message`, compared in constant time.
    fn matches(&self, message: &[u8], tag: &[u8]) -> bool {
        // HMAC accepts a key of any length, so this cannot fail for a fixed-size key.
        let mut signer = <Signer as KeyInit>::new_from_slice(&self.0)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        signer.update(message);
        signer.verify_slice(tag).is_ok()
    }
}

/// A key that has been replaced but is still accepted, and until when.
#[derive(Debug, Clone)]
struct Retired {
    key: Secret,
    accepted_until_ms: u64,
}

/// Which key a signature came from.
///
/// Origin only. A [`Verified`] says the request came from the agent whose keyring this is; it says
/// nothing about what that agent may do, and it is not an input to [`crate::authorize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    /// Signed with the current key.
    Current,
    /// Signed with the retired key, inside its overlap window. Worth logging: it means a caller has
    /// not picked up the new key yet, and the window will close on it.
    Previous,
}

/// One agent's signing key, plus the key it replaced while that is still accepted.
#[derive(Debug, Clone)]
pub struct Keyring {
    agent: String,
    current: Secret,
    previous: Option<Retired>,
}

impl Keyring {
    /// A new keyring with a freshly generated key and no history.
    pub fn provision(agent: &str) -> Result<Self> {
        Ok(Self {
            agent: crate::workspace::identity(agent)?.to_owned(),
            current: Secret::generate()?,
            previous: None,
        })
    }

    /// The agent this keyring belongs to.
    #[must_use]
    pub fn agent(&self) -> &str {
        &self.agent
    }

    /// When the retired key stops being accepted, if there is one.
    #[must_use]
    pub fn accepts_previous_until(&self) -> Option<u64> {
        self.previous.as_ref().map(|old| old.accepted_until_ms)
    }

    /// Signs `message` with the current key. Always the current key: signing with a retired one
    /// would extend its life past the window.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> String {
        encode(&self.current.tag(message))
    }

    /// Establishes which key signed `message`, or refuses.
    ///
    /// The retired key is accepted strictly before its deadline. `now_ms` is passed in rather than
    /// read from the clock so that a caller verifying a batch uses one instant for all of it — and
    /// so the window is testable at its edge.
    pub fn verify(&self, message: &[u8], mac: &str, now_ms: u64) -> Result<Verified> {
        let tag = decode(mac)?;
        if self.current.matches(message, &tag) {
            return Ok(Verified::Current);
        }
        match &self.previous {
            Some(old) if old.key.matches(message, &tag) => {
                if now_ms < old.accepted_until_ms {
                    Ok(Verified::Previous)
                } else {
                    // Named separately from a wrong signature: this one was valid and is now
                    // outside its window, which is a caller to chase rather than an attacker.
                    Err(Error::Denied(format!(
                        "signed with the retired key of {}, whose overlap ended at {}",
                        self.agent, old.accepted_until_ms
                    )))
                }
            }
            _ => Err(Error::Denied(format!(
                "signature does not match any key of {}",
                self.agent
            ))),
        }
    }

    /// Rotates: the current key is retired for [`OVERLAP_MS`] and a fresh one takes over.
    ///
    /// Any key already retired is dropped rather than kept — two overlapping predecessors would
    /// mean a key from two rotations ago still worked, which is not what "previous" promises.
    pub fn rotate(&mut self, now_ms: u64) -> Result<()> {
        let replaced = std::mem::replace(&mut self.current, Secret::generate()?);
        self.previous = Some(Retired {
            key: replaced,
            accepted_until_ms: now_ms + OVERLAP_MS,
        });
        Ok(())
    }

    /// Reads a keyring, refusing one whose file anybody else can read.
    ///
    /// The mode check is here rather than only in the audit because this is the moment the key
    /// would be used: loading it after noticing it is world-readable would be reading a key that
    /// must be treated as exposed.
    pub fn load(path: &Path) -> Result<Self> {
        let mode = mode_of(path)?;
        if mode & 0o077 != 0 {
            return Err(Error::Permissions(format!(
                "{} is {mode:04o}: a key readable beyond its owner must be rotated, not loaded",
                path.display()
            )));
        }
        let text = fs::read_to_string(path).map_err(|err| io("read", path, &err))?;
        let mut agent = None;
        let mut current = None;
        let mut previous = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some("agent"), Some(name), None) => agent = Some(name.to_owned()),
                (Some("current"), Some(hex), None) => current = Some(Secret::parse(hex)?),
                (Some("previous"), Some(hex), Some(until)) => {
                    previous = Some(Retired {
                        key: Secret::parse(hex)?,
                        accepted_until_ms: until.parse().map_err(|_| {
                            Error::Key(format!("previous key deadline {until} is not a number"))
                        })?,
                    });
                }
                _ => return Err(Error::Key(format!("key file line is not a field: {line}"))),
            }
        }
        Ok(Self {
            agent: crate::workspace::identity(
                &agent.ok_or_else(|| Error::Key("key file names no agent".to_owned()))?,
            )?
            .to_owned(),
            current: current.ok_or_else(|| Error::Key("key file has no current key".to_owned()))?,
            previous,
        })
    }

    /// Writes the keyring at [`MODE_KEY_FILE`], replacing whatever was there.
    ///
    /// Written beside the target and renamed over it, so a rotation interrupted halfway leaves the
    /// old key readable rather than a truncated file no signature can be checked against.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut body = format!(
            "# Signing key for agent {}. Mode {MODE_KEY_FILE:04o}, one agent per file, never copied\n\
             # between agents: a shared key makes attribution meaningless.\n\
             agent {}\n\
             current {}\n",
            self.agent,
            self.agent,
            self.current.to_hex()
        );
        if let Some(old) = &self.previous {
            use std::fmt::Write as _;
            let _ = writeln!(
                body,
                "previous {} {}",
                old.key.to_hex(),
                old.accepted_until_ms
            );
        }

        let staged = path.with_extension("staged");
        // Created with the mode rather than chmodded into it: a key that exists for even an
        // instant at the umask's default is a key that was readable.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(MODE_KEY_FILE)
            .open(&staged)
            .map_err(|err| io("create", &staged, &err))?;
        file.write_all(body.as_bytes())
            .map_err(|err| io("write", &staged, &err))?;
        file.sync_all().map_err(|err| io("sync", &staged, &err))?;
        drop(file);
        // A umask can only remove bits, so a re-used staged file is the case this covers.
        fs::set_permissions(&staged, fs::Permissions::from_mode(MODE_KEY_FILE))
            .map_err(|err| io("chmod", &staged, &err))?;
        fs::rename(&staged, path).map_err(|err| io("rename onto", path, &err))
    }
}

/// Hex, lowercase.
fn encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Parses a hex tag of any length; the comparison rejects a wrong length.
fn decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Denied("signature is not hex".to_owned()));
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| Error::Denied("signature is not hex".to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::{Keyring, OVERLAP_MS, Secret, Verified};
    use crate::workspace::{Layout, MODE_KEY_FILE, mode_of};

    /// A provisioned layout with a key file written for `agent`.
    fn keyed(agent: &str) -> (TempDir, Layout, Keyring) {
        let dir = TempDir::new().expect("tempdir");
        let layout = Layout::new(dir.path().join("state"));
        layout.provision(&[agent.to_owned()]).expect("provision");
        let keyring = Keyring::provision(agent).expect("provision key");
        keyring
            .save(&layout.key_file(agent).expect("path"))
            .expect("save");
        (dir, layout, keyring)
    }

    #[test]
    fn a_provisioned_key_file_is_readable_only_by_its_owner() {
        let (_dir, layout, _keyring) = keyed("alpha");
        let path = layout.key_file("alpha").expect("path");

        assert_eq!(mode_of(&path).expect("mode"), MODE_KEY_FILE);
        assert_eq!(MODE_KEY_FILE, 0o600);
    }

    #[test]
    fn two_agents_get_two_different_keys() {
        // One key per file is the whole basis of attribution: a shared key means any holder can
        // sign as any of them.
        let alpha = Keyring::provision("alpha").expect("alpha");
        let beta = Keyring::provision("beta").expect("beta");
        assert_ne!(alpha.sign(b"record"), beta.sign(b"record"));
    }

    #[test]
    fn a_signature_verifies_against_the_key_that_made_it() {
        let keyring = Keyring::provision("alpha").expect("provision");
        let mac = keyring.sign(b"POST /records");

        assert_eq!(
            keyring.verify(b"POST /records", &mac, 0).expect("verify"),
            Verified::Current
        );
    }

    #[test]
    fn a_signature_over_different_bytes_is_refused() {
        let keyring = Keyring::provision("alpha").expect("provision");
        let mac = keyring.sign(b"POST /records");

        let error = keyring
            .verify(b"DELETE /records", &mac, 0)
            .expect_err("tampered");
        assert_eq!(
            error.to_string(),
            "denied: signature does not match any key of alpha"
        );
    }

    #[test]
    fn another_agents_signature_is_refused() {
        let alpha = Keyring::provision("alpha").expect("alpha");
        let beta = Keyring::provision("beta").expect("beta");

        let forged = beta.sign(b"record from alpha");
        assert!(alpha.verify(b"record from alpha", &forged, 0).is_err());
    }

    #[test]
    fn the_previous_key_is_accepted_inside_the_window_and_refused_outside_it() {
        let mut keyring = Keyring::provision("alpha").expect("provision");
        let old = keyring.sign(b"in flight");
        let rotated_at = 1_000_000;
        keyring.rotate(rotated_at).expect("rotate");

        assert_eq!(
            keyring.accepts_previous_until(),
            Some(rotated_at + OVERLAP_MS)
        );
        assert_eq!(
            keyring
                .verify(b"in flight", &old, rotated_at + 1)
                .expect("just after rotation"),
            Verified::Previous
        );
        assert_eq!(
            keyring
                .verify(b"in flight", &old, rotated_at + OVERLAP_MS - 1)
                .expect("last millisecond of the window"),
            Verified::Previous
        );

        let expired = keyring
            .verify(b"in flight", &old, rotated_at + OVERLAP_MS)
            .expect_err("the window is closed");
        assert!(expired.to_string().contains("overlap ended"), "{expired}");
        assert!(matches!(expired, crate::Error::Denied(_)));
    }

    #[test]
    fn rotation_produces_a_new_key_and_keeps_signing_with_it() {
        let mut keyring = Keyring::provision("alpha").expect("provision");
        let before = keyring.sign(b"same bytes");
        keyring.rotate(0).expect("rotate");
        let after = keyring.sign(b"same bytes");

        assert_ne!(before, after, "signing must use the new key");
        assert_eq!(
            keyring.verify(b"same bytes", &after, 0).expect("verify"),
            Verified::Current
        );
    }

    #[test]
    fn a_key_from_two_rotations_ago_is_not_accepted() {
        let mut keyring = Keyring::provision("alpha").expect("provision");
        let oldest = keyring.sign(b"ancient");
        keyring.rotate(0).expect("first");
        keyring.rotate(1).expect("second");

        assert!(keyring.verify(b"ancient", &oldest, 2).is_err());
    }

    #[test]
    fn a_keyring_survives_a_round_trip_through_its_file() {
        let (_dir, layout, keyring) = keyed("alpha");
        let path = layout.key_file("alpha").expect("path");
        let mac = keyring.sign(b"record");

        let loaded = Keyring::load(&path).expect("load");
        assert_eq!(loaded.agent(), "alpha");
        assert_eq!(
            loaded.verify(b"record", &mac, 0).expect("verify"),
            Verified::Current
        );
    }

    #[test]
    fn a_rotated_keyring_survives_a_round_trip_with_its_window() {
        let (_dir, layout, mut keyring) = keyed("alpha");
        let path = layout.key_file("alpha").expect("path");
        let old = keyring.sign(b"in flight");
        keyring.rotate(500).expect("rotate");
        keyring.save(&path).expect("save");

        let loaded = Keyring::load(&path).expect("load");
        assert_eq!(loaded.accepts_previous_until(), Some(500 + OVERLAP_MS));
        assert_eq!(
            loaded.verify(b"in flight", &old, 600).expect("verify"),
            Verified::Previous
        );
        assert!(loaded.verify(b"in flight", &old, 500 + OVERLAP_MS).is_err());
        assert_eq!(mode_of(&path).expect("mode"), MODE_KEY_FILE);
    }

    #[test]
    fn a_key_file_anybody_can_read_is_refused_rather_than_loaded() {
        let (_dir, layout, _keyring) = keyed("alpha");
        let path = layout.key_file("alpha").expect("path");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen");

        let error = Keyring::load(&path).expect_err("world-readable key");
        assert!(matches!(error, crate::Error::Permissions(_)), "{error}");
        assert!(error.to_string().contains("must be rotated"), "{error}");
    }

    #[test]
    fn a_malformed_key_file_is_reported_rather_than_guessed() {
        let dir = TempDir::new().expect("tempdir");
        for (body, expected) in [
            ("agent alpha\n", "no current key"),
            ("current abcd\n", "hex characters"),
            ("agent alpha\ncurrent 00\n", "hex characters"),
            ("current 0x\n", "hex characters"),
            (&format!("current {}\n", "zz".repeat(32)), "not hex"),
            ("nonsense\n", "not a field"),
            (
                &format!(
                    "agent alpha\ncurrent {}\nprevious {} soon\n",
                    "aa".repeat(32),
                    "bb".repeat(32)
                ),
                "not a number",
            ),
            (&format!("current {}\n", "aa".repeat(32)), "names no agent"),
        ] {
            let path = dir.path().join("key");
            fs::write(&path, body).expect("write");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");

            let error = Keyring::load(&path).expect_err(body);
            assert!(
                error.to_string().contains(expected),
                "{body:?} gave {error}, wanted {expected}"
            );
        }
    }

    #[test]
    fn a_missing_key_file_is_an_io_error() {
        let dir = TempDir::new().expect("tempdir");
        let error = Keyring::load(&dir.path().join("absent")).expect_err("absent");
        assert!(matches!(error, crate::Error::Io(_)), "{error}");
    }

    #[test]
    fn an_agent_id_that_is_a_path_never_becomes_a_keyring() {
        assert!(Keyring::provision("../escape").is_err());
    }

    #[test]
    fn a_signature_that_is_not_hex_is_refused_without_a_comparison() {
        let keyring = Keyring::provision("alpha").expect("provision");
        for bad in ["zz", "abc"] {
            let error = keyring.verify(b"record", bad, 0).expect_err(bad);
            assert!(error.to_string().contains("not hex"), "{bad}: {error}");
        }
    }

    #[test]
    fn a_key_never_prints_itself() {
        // This type ends up inside structs that are natural to debug-print, and a key in a log
        // line is a leaked key.
        let secret = Secret::parse(&"ab".repeat(32)).expect("parse");
        let printed = format!("{secret:?}");
        assert!(!printed.contains("abab"), "{printed}");
        assert!(printed.contains("redacted"), "{printed}");
    }

    #[test]
    fn a_key_file_written_over_an_existing_one_keeps_its_mode() {
        let (_dir, layout, keyring) = keyed("alpha");
        let path = layout.key_file("alpha").expect("path");
        keyring.save(&path).expect("save again");
        assert_eq!(mode_of(&path).expect("mode"), MODE_KEY_FILE);
    }

    #[test]
    fn saving_into_a_directory_that_is_not_there_is_an_io_error() {
        let dir = TempDir::new().expect("tempdir");
        let keyring = Keyring::provision("alpha").expect("provision");
        let error = keyring
            .save(&dir.path().join("absent").join("alpha"))
            .expect_err("no directory");
        assert!(matches!(error, crate::Error::Io(_)), "{error}");
    }
}
