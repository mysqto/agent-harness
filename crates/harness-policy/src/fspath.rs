//! Turning what a tool call said into a path the policy can be compared against.
//!
//! Two jobs, and they are separate on purpose: policy *patterns* get `~` and `${workspace}`
//! substituted once when a guard is built, while a *candidate* path from a tool call is resolved per
//! check. Comparing an unresolved candidate against a resolved pattern is the classic hole —
//! `~/proj/../.ssh/id_rsa` is a read of a private key that no literal pattern matches.

use std::path::{Component, Path, PathBuf};

/// Substitutes `~` and `${workspace}` in a policy pattern.
///
/// Done once at construction so a check never has to; a pattern that expands differently between
/// two checks would make the policy depend on the environment of whoever ran the guard.
#[must_use]
pub fn expand(pattern: &str, home: &Path, workspace: &Path) -> String {
    let workspace = workspace.to_string_lossy();
    let home = home.to_string_lossy();
    let with_workspace = pattern.replace("${workspace}", &workspace);
    match with_workspace.strip_prefix('~') {
        // Only a leading `~` is a home reference; `~` elsewhere is a legitimate filename character.
        Some(rest) => format!("{home}{rest}"),
        None => with_workspace,
    }
}

/// Resolves a candidate path from a tool call to an absolute, `..`-free form.
///
/// Canonicalises when the path exists, so a symlink pointing at a denied location is compared as its
/// target rather than as its name. When it does not exist — a write to a file not yet created —
/// resolution is lexical, which is why the guard is one layer of five: a symlink planted at a path
/// that is created later is beyond what any string comparison can see (§10.2 layer 4).
#[must_use]
pub fn resolve(raw: &str, home: &Path, cwd: &Path) -> PathBuf {
    let expanded = match raw.strip_prefix('~') {
        Some(rest) => PathBuf::from(format!("{}{rest}", home.to_string_lossy())),
        None => PathBuf::from(raw),
    };
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    };
    std::fs::canonicalize(&absolute).unwrap_or_else(|_| lexical(&absolute))
}

/// Collapses `.` and `..` without touching the filesystem.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            // `..` above the root stays at the root, matching how the kernel resolves it.
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Whether `path` is `root` or lies underneath it.
#[must_use]
pub fn contains(root: &Path, path: &Path) -> bool {
    path == root || path.starts_with(root)
}

/// Whether `path` lies under any of `roots`. Empty `roots` contains nothing.
#[must_use]
pub fn within_any(roots: &[PathBuf], path: &Path) -> bool {
    roots.iter().any(|root| contains(root, path))
}

/// Whether a command token looks like a filesystem path rather than a flag or a bare word.
///
/// Used to decide which arguments of a destructive command to test for workspace containment. Bare
/// words are excluded deliberately: `rm build` inside the workspace is ordinary work, and treating
/// every word as a path would deny it.
#[must_use]
pub fn looks_like_path(token: &str) -> bool {
    token.starts_with('/') || token.starts_with('~') || token.contains('/')
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{contains, expand, looks_like_path, resolve, within_any};

    fn home() -> PathBuf {
        PathBuf::from("/home/a")
    }

    #[test]
    fn a_leading_tilde_expands_and_a_later_one_does_not() {
        assert_eq!(
            expand("~/.ssh/**", &home(), Path::new("/srv/work")),
            "/home/a/.ssh/**"
        );
        assert_eq!(
            expand("**/backup~/*", &home(), Path::new("/srv/work")),
            "**/backup~/*"
        );
    }

    #[test]
    fn the_workspace_token_expands_anywhere_in_a_pattern() {
        assert_eq!(
            expand("${workspace}/out/**", &home(), Path::new("/srv/work")),
            "/srv/work/out/**"
        );
    }

    #[test]
    fn a_relative_candidate_resolves_against_the_working_directory() {
        assert_eq!(
            resolve("sub/.env", &home(), Path::new("/srv/work")),
            PathBuf::from("/srv/work/sub/.env")
        );
    }

    #[test]
    fn parent_segments_are_collapsed_before_comparison() {
        // The escape a naive matcher misses.
        assert_eq!(
            resolve("~/proj/../.ssh/id_rsa", &home(), Path::new("/srv/work")),
            PathBuf::from("/home/a/.ssh/id_rsa")
        );
        assert_eq!(
            resolve("./a/./b/../c", &home(), Path::new("/srv/work")),
            PathBuf::from("/srv/work/a/c")
        );
    }

    #[test]
    fn climbing_past_the_root_stays_at_the_root() {
        assert_eq!(
            resolve("/../../etc/shadow", &home(), Path::new("/srv/work")),
            PathBuf::from("/etc/shadow")
        );
    }

    #[test]
    fn a_symlink_resolves_to_its_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let secret = dir.path().join("real.env");
        std::fs::write(&secret, "TOKEN=1").expect("write");
        let link = dir.path().join("innocent.txt");
        std::os::unix::fs::symlink(&secret, &link).expect("symlink");

        let resolved = resolve(&link.to_string_lossy(), &home(), dir.path());
        assert_eq!(
            resolved,
            std::fs::canonicalize(&secret).expect("canonicalize")
        );
    }

    #[test]
    fn containment_is_by_component_not_by_prefix_string() {
        let root = PathBuf::from("/srv/work");
        assert!(contains(&root, Path::new("/srv/work")));
        assert!(contains(&root, Path::new("/srv/work/sub/file")));
        assert!(!contains(&root, Path::new("/srv/workshop/file")));
    }

    #[test]
    fn no_roots_contains_nothing() {
        assert!(!within_any(&[], Path::new("/srv/work/file")));
        assert!(within_any(
            &[PathBuf::from("/tmp"), PathBuf::from("/srv/work")],
            Path::new("/tmp/x")
        ));
    }

    #[test]
    fn path_shaped_tokens_are_distinguished_from_words_and_flags() {
        assert!(looks_like_path("/etc/hosts"));
        assert!(looks_like_path("~/notes"));
        assert!(looks_like_path("build/out"));
        assert!(!looks_like_path("-rf"));
        assert!(!looks_like_path("build"));
    }
}
