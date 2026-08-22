//! The tree, and the permissions that make the access model a control rather than a convention.
//!
//! The design says the memory service is the only cross-agent interface. On a host that also runs
//! the agents, that is true only if an agent process cannot open the tree directly — so `memory/`
//! is [`MODE_SHARED`] and owned by a group the agent users are not in, and owner-visibility records
//! live under `memory/private/<owner>/` at [`MODE_PRIVATE`], where an operator shell without that
//! identity cannot open them either.
//!
//! Ownership is the installer's to set: creating a directory owned by another user needs privileges
//! this process does not have and should not want. What this module owns is the layout and the mode
//! bits, and [`Layout::audit`] is what notices when either has drifted.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::{Error, Result, io};

/// Shared directories: the owning service reads and writes, its group reads, nobody else sees it.
pub const MODE_SHARED: u32 = 0o750;

/// One identity's directories. No group access at all, which is the point of `private/`.
pub const MODE_PRIVATE: u32 = 0o700;

/// A signing key. Readable by its owner and nothing else.
pub const MODE_KEY_FILE: u32 = 0o600;

/// Directory holding the per-agent signing keys, under the layout root.
const KEY_DIR: &str = ".secrets/memory-keys";

/// What provisioning did. Reported rather than summarised, so re-running the installer says what
/// it changed instead of what it intended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The path was not there.
    Created(PathBuf),
    /// The path was there with a mode that granted more than the policy allows.
    Corrected {
        /// The path whose mode was reset.
        path: PathBuf,
        /// The mode found.
        was: u32,
        /// The mode set.
        now: u32,
    },
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created(path) => write!(f, "created {}", path.display()),
            Self::Corrected { path, was, now } => {
                write!(
                    f,
                    "corrected {} from {was:04o} to {now:04o}",
                    path.display()
                )
            }
        }
    }
}

/// The tree a deployment lives in.
#[derive(Debug, Clone)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    /// A layout rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The shared memory tree. Not an agent path: the group on it is the service's, not theirs.
    #[must_use]
    pub fn memory(&self) -> PathBuf {
        self.root.join("memory")
    }

    /// Where one identity's owner-visibility records are physically segregated.
    pub fn private(&self, owner: &str) -> Result<PathBuf> {
        Ok(self.memory().join("private").join(identity(owner)?))
    }

    /// One agent's own scratch workspace.
    pub fn agent_workspace(&self, agent: &str) -> Result<PathBuf> {
        Ok(self.root.join("agents").join(identity(agent)?))
    }

    /// Where the emitted sandbox artefacts live: the unit, the container profile, and the policy
    /// they were both generated from. Kept beside the deployment rather than in the repo, because
    /// what a host runs is the copy on that host.
    #[must_use]
    pub fn sandbox(&self) -> PathBuf {
        self.root.join("sandbox")
    }

    /// The signing key directory.
    #[must_use]
    pub fn key_dir(&self) -> PathBuf {
        self.root.join(KEY_DIR)
    }

    /// One agent's signing key file.
    pub fn key_file(&self, agent: &str) -> Result<PathBuf> {
        Ok(self.key_dir().join(identity(agent)?))
    }

    /// Creates the tree for `agents`, or corrects it. Idempotent: a second run reports nothing.
    pub fn provision(&self, agents: &[String]) -> Result<Vec<Change>> {
        let mut changes = Vec::new();
        let mut shared = vec![
            self.root.clone(),
            self.memory(),
            self.memory().join("private"),
            self.root.join("agents"),
            self.sandbox(),
        ];
        // The secrets directory is private even though the key files are what actually matter:
        // a listable key directory tells an attacker exactly which identities exist.
        let mut private = vec![self.root.join(".secrets"), self.key_dir()];
        for agent in agents {
            private.push(self.private(agent)?);
            private.push(self.agent_workspace(agent)?);
        }
        shared.sort();
        private.sort();
        for (paths, mode) in [(shared, MODE_SHARED), (private, MODE_PRIVATE)] {
            for path in paths {
                changes.extend(ensure_dir(&path, mode)?);
            }
        }
        changes.sort_by_key(|change| match change {
            Change::Created(path) | Change::Corrected { path, .. } => path.clone(),
        });
        Ok(changes)
    }

    /// Everything in the tree whose mode grants more than the policy allows.
    ///
    /// Reports rather than fixes: an operator wants to know what happened before it is repaired,
    /// and `provision` is the call that repairs.
    pub fn audit(&self) -> Result<Vec<String>> {
        let mut findings = Vec::new();
        for (path, mode) in [
            (self.root.clone(), MODE_SHARED),
            (self.memory(), MODE_SHARED),
            (self.memory().join("private"), MODE_SHARED),
            (self.root.join("agents"), MODE_SHARED),
            (self.sandbox(), MODE_SHARED),
            (self.root.join(".secrets"), MODE_PRIVATE),
            (self.key_dir(), MODE_PRIVATE),
        ] {
            findings.extend(check(&path, mode)?);
        }
        // Per-identity directories and key files are discovered rather than passed in, so a stale
        // one left behind by a decommissioned agent is audited too.
        for parent in [self.memory().join("private"), self.root.join("agents")] {
            for entry in children(&parent)? {
                findings.extend(check(&entry, MODE_PRIVATE)?);
            }
        }
        for key in children(&self.key_dir())? {
            findings.extend(check(&key, MODE_KEY_FILE)?);
        }
        Ok(findings)
    }

    /// The private directory of `owner`, if `requester` is allowed to open it.
    ///
    /// Only the owner is. There is deliberately no operator override: `private/` exists so that a
    /// reader holding the operator role but not the identity cannot open the records, and an
    /// override here would hand back exactly what the mode bits are refusing.
    pub fn open_private(&self, owner: &str, requester: &str) -> Result<PathBuf> {
        let owner = identity(owner)?;
        let requester = identity(requester)?;
        if owner != requester {
            return Err(Error::Denied(format!(
                "{requester} may not read the private workspace of {owner}"
            )));
        }
        let path = self.private(owner)?;
        let mode = mode_of(&path)?;
        if mode != MODE_PRIVATE {
            // A private directory with the wrong mode is not private; handing back the path would
            // let a caller read records the layout promised were segregated.
            return Err(Error::Permissions(format!(
                "{} is {mode:04o}, not {MODE_PRIVATE:04o}",
                path.display()
            )));
        }
        Ok(path)
    }
}

/// Rejects anything that is not a single safe path component.
///
/// An agent id reaches this from configuration, and `../../etc` as an id would otherwise place a
/// workspace outside the tree the modes are set on.
pub(crate) fn identity(name: &str) -> Result<&str> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(name)
    } else {
        Err(Error::Denied(format!(
            "{name:?} is not a usable identity: letters, digits, `-` and `_`, up to 64"
        )))
    }
}

/// Creates a directory with `mode`, or corrects a mode that grants more than `mode` does.
///
/// A stricter mode than asked for is left alone: an operator who narrowed something further meant
/// it, and re-widening it on every install would be this function undoing that.
fn ensure_dir(path: &Path, mode: u32) -> Result<Option<Change>> {
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => {
            let was = meta.permissions().mode() & 0o7777;
            if was & !mode == 0 {
                return Ok(None);
            }
            set_mode(path, mode)?;
            Ok(Some(Change::Corrected {
                path: path.to_path_buf(),
                was,
                now: mode,
            }))
        }
        Ok(_) => Err(Error::Permissions(format!(
            "{} is not a directory",
            path.display()
        ))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|err| io("create", path, &err))?;
            // Created first and chmodded second: `create_dir_all` applies the umask, so the mode
            // is set explicitly rather than hoped for.
            set_mode(path, mode)?;
            Ok(Some(Change::Created(path.to_path_buf())))
        }
        Err(err) => Err(io("stat", path, &err)),
    }
}

/// Sets a mode, naming the path on failure.
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| io("chmod", path, &err))
}

/// The permission bits on a path.
pub(crate) fn mode_of(path: &Path) -> Result<u32> {
    Ok(fs::metadata(path)
        .map_err(|err| io("stat", path, &err))?
        .permissions()
        .mode()
        & 0o7777)
}

/// One finding if `path` grants more than `mode`, nothing if it is at least as tight, and nothing
/// at all if it is absent — an audit reports what is wrong with what exists, and a missing
/// directory is provisioning's business.
fn check(path: &Path, mode: u32) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let was = mode_of(path)?;
    Ok((was & !mode != 0)
        .then(|| format!("{} is {was:04o}, wider than {mode:04o}", path.display())))
}

/// Entries directly under `parent`, or nothing when it does not exist.
fn children(parent: &Path) -> Result<Vec<PathBuf>> {
    if !parent.exists() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    for entry in fs::read_dir(parent).map_err(|err| io("read", parent, &err))? {
        found.push(entry.map_err(|err| io("read", parent, &err))?.path());
    }
    found.sort();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use tempfile::TempDir;

    use super::{Change, Layout, MODE_KEY_FILE, MODE_PRIVATE, MODE_SHARED, mode_of};

    /// A provisioned layout with two agents in it.
    fn provisioned() -> (TempDir, Layout) {
        let dir = TempDir::new().expect("tempdir");
        let layout = Layout::new(dir.path().join("state"));
        layout
            .provision(&["alpha".to_owned(), "beta".to_owned()])
            .expect("provision");
        (dir, layout)
    }

    /// The real uid, or `None` where `/proc` is not there to ask.
    fn uid() -> Option<u32> {
        use std::os::unix::fs::MetadataExt;
        fs::metadata("/proc/self").ok().map(|meta| meta.uid())
    }

    #[test]
    fn provisioning_sets_the_modes_the_access_model_needs() {
        let (_dir, layout) = provisioned();

        assert_eq!(mode_of(&layout.memory()).expect("memory"), MODE_SHARED);
        assert_eq!(mode_of(&layout.key_dir()).expect("keys"), MODE_PRIVATE);
        for agent in ["alpha", "beta"] {
            let private = layout.private(agent).expect("private");
            let workspace = layout.agent_workspace(agent).expect("workspace");
            assert_eq!(mode_of(&private).expect("mode"), MODE_PRIVATE, "{agent}");
            assert_eq!(mode_of(&workspace).expect("mode"), MODE_PRIVATE, "{agent}");
        }
    }

    #[test]
    fn provisioning_twice_changes_nothing_the_second_time() {
        let (_dir, layout) = provisioned();
        let again = layout
            .provision(&["alpha".to_owned(), "beta".to_owned()])
            .expect("provision");
        assert_eq!(again, Vec::new());
    }

    #[test]
    fn a_loosened_directory_is_corrected_and_reported() {
        let (_dir, layout) = provisioned();
        let private = layout.private("alpha").expect("private");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).expect("loosen");

        let changes = layout
            .provision(&["alpha".to_owned(), "beta".to_owned()])
            .expect("provision");

        assert_eq!(
            changes,
            vec![Change::Corrected {
                path: private.clone(),
                was: 0o755,
                now: MODE_PRIVATE,
            }]
        );
        assert_eq!(mode_of(&private).expect("mode"), MODE_PRIVATE);
    }

    #[test]
    fn a_directory_tightened_further_by_hand_is_left_alone() {
        // An operator who narrowed something meant it; re-widening on every install would undo it.
        let (_dir, layout) = provisioned();
        let memory = layout.memory();
        fs::set_permissions(&memory, fs::Permissions::from_mode(0o700)).expect("tighten");

        let changes = layout.provision(&["alpha".to_owned()]).expect("provision");

        assert_eq!(changes, Vec::new());
        assert_eq!(mode_of(&memory).expect("mode"), 0o700);
    }

    #[test]
    fn an_audit_names_a_key_file_anybody_can_read() {
        let (_dir, layout) = provisioned();
        let key = layout.key_file("alpha").expect("key path");
        fs::write(&key, "current 00").expect("write");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("loosen");

        let findings = layout.audit().expect("audit");

        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].contains("0644"), "{findings:?}");
        assert!(
            findings[0].contains(&format!("{MODE_KEY_FILE:04o}")),
            "{findings:?}"
        );
    }

    #[test]
    fn a_clean_tree_audits_clean() {
        let (_dir, layout) = provisioned();
        assert_eq!(layout.audit().expect("audit"), Vec::<String>::new());
    }

    #[test]
    fn an_audit_of_an_unprovisioned_root_finds_nothing_to_report() {
        let dir = TempDir::new().expect("tempdir");
        let layout = Layout::new(dir.path().join("absent"));
        assert_eq!(layout.audit().expect("audit"), Vec::<String>::new());
    }

    #[test]
    fn one_agent_may_not_open_another_agents_private_workspace() {
        let (_dir, layout) = provisioned();

        let own = layout.open_private("alpha", "alpha").expect("own");
        assert_eq!(own, layout.private("alpha").expect("path"));

        let error = layout
            .open_private("beta", "alpha")
            .expect_err("cross-agent read");
        assert_eq!(
            error.to_string(),
            "denied: alpha may not read the private workspace of beta"
        );
    }

    #[test]
    fn holding_the_operator_role_is_not_an_identity() {
        // `private/` exists so that a reader with the operator role but not the identity cannot
        // open the records. There is no override to pass, and that is the assertion.
        let (_dir, layout) = provisioned();
        let error = layout
            .open_private("alpha", "operator")
            .expect_err("operator read");
        assert!(matches!(error, crate::Error::Denied(_)), "{error}");
    }

    #[test]
    fn a_private_directory_with_the_wrong_mode_is_refused_rather_than_returned() {
        let (_dir, layout) = provisioned();
        let private = layout.private("alpha").expect("private");
        fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).expect("loosen");

        let error = layout
            .open_private("alpha", "alpha")
            .expect_err("loose mode");
        assert!(matches!(error, crate::Error::Permissions(_)), "{error}");
    }

    #[test]
    fn the_kernel_enforces_the_mode_bits_this_layout_relies_on() {
        // The layout's claim is that mode bits keep another uid out. This process cannot become
        // another uid, so what is tested is the half that is testable: that on this filesystem the
        // kernel refuses a read the mode does not grant. Root bypasses mode checks, so a root test
        // run would prove the opposite of what it asserts and is skipped instead.
        if uid() != Some(0) {
            let dir = TempDir::new().expect("tempdir");
            let closed = dir.path().join("closed");
            fs::create_dir(&closed).expect("create");
            fs::write(closed.join("record.md"), "owner-visibility body").expect("write");
            fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).expect("close");

            let denied = fs::read_to_string(closed.join("record.md"))
                .expect_err("a mode with no read bit must deny");
            assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);

            // Left readable, or the tempdir cannot be cleaned up.
            fs::set_permissions(&closed, fs::Permissions::from_mode(MODE_PRIVATE)).expect("reopen");
        }
    }

    #[test]
    fn an_identity_that_is_a_path_is_refused() {
        let layout = Layout::new("/tmp/nothing-here");
        for bad in ["..", "a/b", "", "alpha beta", &"x".repeat(65)] {
            let error = layout.private(bad).expect_err(bad);
            assert!(matches!(error, crate::Error::Denied(_)), "{bad}: {error}");
        }
        assert!(layout.key_file("../escape").is_err());
        assert!(layout.agent_workspace("..").is_err());
    }

    #[test]
    fn a_file_where_a_directory_belongs_is_an_error_rather_than_a_chmod() {
        let dir = TempDir::new().expect("tempdir");
        let root = dir.path().join("state");
        fs::create_dir_all(&root).expect("root");
        fs::write(root.join("memory"), "not a directory").expect("write");

        let error = Layout::new(&root).provision(&[]).expect_err("provision");
        assert!(matches!(error, crate::Error::Permissions(_)), "{error}");
    }

    #[test]
    fn a_change_says_what_it_did() {
        assert_eq!(
            Change::Created(Path::new("/x").to_path_buf()).to_string(),
            "created /x"
        );
        assert_eq!(
            Change::Corrected {
                path: Path::new("/x").to_path_buf(),
                was: 0o755,
                now: 0o700,
            }
            .to_string(),
            "corrected /x from 0755 to 0700"
        );
    }

    #[test]
    fn a_root_that_cannot_be_read_is_an_io_error() {
        if uid() != Some(0) {
            let dir = TempDir::new().expect("tempdir");
            let closed = dir.path().join("closed");
            fs::create_dir(&closed).expect("create");
            fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).expect("close");

            let error = Layout::new(closed.join("state"))
                .provision(&[])
                .expect_err("provision under an unreadable parent");
            assert!(matches!(error, crate::Error::Io(_)), "{error}");

            fs::set_permissions(&closed, fs::Permissions::from_mode(0o700)).expect("reopen");
        }
    }
}
