//! The declared sandbox, and the two artefacts generated from it.
//!
//! A production host runs a systemd unit and the lab runs a container. Writing both by hand is the
//! failure this module exists to prevent: the two drift, and then the lab proves the lab. Here the
//! policy is declared once, both artefacts are rendered from it, and each artefact can be read back
//! into the same [`Hardening`] — so "they agree" is a test rather than a claim.
//!
//! Both readers *require* every property. That is the load-bearing detail: a property added to
//! [`Hardening`] and rendered by only one emitter fails the other's read instead of quietly
//! defaulting, which is exactly how a hand-maintained pair of files goes wrong.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// A confinement policy: what runs, and how tightly.
///
/// Serialisable so a deployment can keep it in version control and pass it to both emitters,
/// which is the only way "one source of truth" survives contact with two runtimes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Service name. Names the unit and the container.
    pub name: String,
    /// The command the sandbox runs, as it appears in `ExecStart`.
    pub exec_start: String,
    /// The hardening properties both artefacts must express.
    pub hardening: Hardening,
}

/// Every property the two artefacts have to agree on.
///
/// Deliberately small: each field is here because both a systemd unit and a container runtime can
/// express it honestly. A property only one side can enforce would make the equivalence test a
/// fiction, so it does not belong in this struct.
// Six of these are booleans because six of the properties are on-or-off. Grouping them into
// sub-structs would only move the count around, and the equivalence test reads better as a flat
// list of properties than as a tree of them.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hardening {
    /// Root filesystem is read-only (`ProtectSystem=strict`, `--read-only`).
    pub read_only_root: bool,
    /// A child cannot gain privileges its parent lacked (`NoNewPrivileges`, `no-new-privileges`).
    pub no_new_privileges: bool,
    /// `/tmp` is private to the sandbox (`PrivateTmp`, a `tmpfs` mount).
    pub private_tmp: bool,
    /// No capabilities at all (`CapabilityBoundingSet=`, `--cap-drop=ALL`).
    pub drop_all_capabilities: bool,
    /// `setuid`/`setgid` bits are inert (`RestrictSUIDSGID`, `nosuid` on every mount).
    pub restrict_suid_sgid: bool,
    /// Nothing under a writable path may be executed (`NoExecPaths`, `noexec` on every mount).
    pub no_exec_writable: bool,
    /// Unprivileged user the sandbox runs as. A name, not a uid: a container image resolves the
    /// same name, and comparing a name against a number is how the two artefacts stop matching.
    pub user: String,
    /// Group the sandbox runs as.
    pub group: String,
    /// The only paths that stay writable under a read-only root.
    pub read_write_paths: Vec<PathBuf>,
    /// Egress destinations. Everything not listed is denied; an empty list denies all egress.
    pub egress_allow: Vec<String>,
    /// Ceiling on tasks (`TasksMax`, `--pids-limit`).
    pub pids_max: u32,
    /// Ceiling on memory (`MemoryMax`, `--memory`).
    pub memory_max_bytes: u64,
}

impl Policy {
    /// The Phase 0 policy for a deployment rooted at `root`.
    ///
    /// Writable paths are the two trees the runtime actually writes to. The key directory is not
    /// among them on purpose: keys are written at provisioning time by an operator, so a running
    /// agent that can rewrite its own key is a capability nobody asked for.
    #[must_use]
    pub fn phase0(name: &str, exec_start: &str, root: &Path) -> Self {
        Self {
            name: name.to_owned(),
            exec_start: exec_start.to_owned(),
            hardening: Hardening {
                read_only_root: true,
                no_new_privileges: true,
                private_tmp: true,
                drop_all_capabilities: true,
                restrict_suid_sgid: true,
                no_exec_writable: true,
                user: "harness".to_owned(),
                group: "harness".to_owned(),
                read_write_paths: vec![root.join("memory"), root.join("agents")],
                egress_allow: Vec::new(),
                pids_max: 64,
                memory_max_bytes: 512 * 1024 * 1024,
            },
        }
    }

    /// Refuses a policy weaker than the Phase 0 floor.
    ///
    /// Called before either artefact is emitted, because the cheapest place to catch a softened
    /// sandbox is before it is written to a file that looks authoritative.
    pub fn validate(&self) -> Result<()> {
        let h = &self.hardening;
        let missing: Vec<&str> = [
            (h.read_only_root, "read_only_root"),
            (h.no_new_privileges, "no_new_privileges"),
            (h.private_tmp, "private_tmp"),
            (h.drop_all_capabilities, "drop_all_capabilities"),
            (h.restrict_suid_sgid, "restrict_suid_sgid"),
        ]
        .into_iter()
        .filter_map(|(set, name)| (!set).then_some(name))
        .collect();
        if !missing.is_empty() {
            return Err(Error::Policy(format!(
                "below the Phase 0 floor: {}",
                missing.join(", ")
            )));
        }
        if h.user == "root" || h.group == "root" {
            return Err(Error::Policy("runs as root".to_owned()));
        }
        if h.pids_max == 0 || h.memory_max_bytes == 0 {
            return Err(Error::Policy(
                "a zero pids or memory ceiling would refuse to start".to_owned(),
            ));
        }
        if self.name.is_empty() || self.exec_start.is_empty() {
            return Err(Error::Policy("needs a name and a command".to_owned()));
        }
        Ok(())
    }

    /// Renders the systemd unit.
    #[must_use]
    pub fn systemd_unit(&self) -> String {
        let h = &self.hardening;
        let no_exec = if h.no_exec_writable {
            paths(&h.read_write_paths)
        } else {
            String::new()
        };
        format!(
            "# Generated by harness-sandbox from one declared policy. Do not edit: change the\n\
             # policy and re-emit, or this unit and the container profile beside it stop\n\
             # describing the same sandbox.\n\
             [Unit]\n\
             Description=harness sandbox ({name})\n\
             After=network.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={exec}\n\
             User={user}\n\
             Group={group}\n\
             ProtectSystem={protect}\n\
             NoNewPrivileges={nnp}\n\
             PrivateTmp={tmp}\n\
             CapabilityBoundingSet={caps}\n\
             AmbientCapabilities=\n\
             RestrictSUIDSGID={suid}\n\
             NoExecPaths={noexec}\n\
             ReadWritePaths={rw}\n\
             TasksMax={pids}\n\
             MemoryMax={memory}\n\
             IPAddressDeny=any\n\
             IPAddressAllow={egress}\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            name = self.name,
            exec = self.exec_start,
            user = h.user,
            group = h.group,
            protect = if h.read_only_root { "strict" } else { "no" },
            nnp = h.no_new_privileges,
            tmp = h.private_tmp,
            // An empty bounding set drops everything; `~` inverts an empty removal, which is
            // systemd's only way to spell "keep the default set" once the directive is present.
            caps = if h.drop_all_capabilities { "" } else { "~" },
            suid = h.restrict_suid_sgid,
            noexec = no_exec,
            rw = paths(&h.read_write_paths),
            pids = h.pids_max,
            memory = h.memory_max_bytes,
            egress = h.egress_allow.join(" "),
        )
    }

    /// Renders the container profile: the same policy, plus the runtime flags derived from it.
    ///
    /// # Panics
    ///
    /// Never in practice — the profile is a plain struct of owned data, so serialising it cannot
    /// fail; the expectation is there because the alternative is an error variant no caller can hit.
    #[must_use]
    pub fn container_profile(&self) -> String {
        let profile = ContainerProfile::from(self);
        serde_json::to_string_pretty(&profile).expect("a plain struct always serialises")
    }

    /// Reads a systemd unit back into the properties it expresses.
    pub fn read_systemd(unit: &str) -> Result<Hardening> {
        let mut fields: Vec<(&str, &str)> = Vec::new();
        for line in unit.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(Error::Policy(format!(
                    "unit line is not a directive: {line}"
                )));
            };
            let key = key.trim();
            if fields.iter().any(|(seen, _)| *seen == key) {
                // systemd appends to a repeated list directive; guessing which wins would make the
                // read disagree with the running service.
                return Err(Error::Policy(format!("unit repeats {key}")));
            }
            fields.push((key, value.trim()));
        }
        let get = |key: &str| -> Result<&str> {
            fields
                .iter()
                .find_map(|(seen, value)| (*seen == key).then_some(*value))
                .ok_or_else(|| Error::Policy(format!("unit has no {key}")))
        };
        let read_write_paths = split_paths(get("ReadWritePaths")?);
        // Equal to the writable set means every writable path is `noexec`; empty means none is.
        // Anything between is a unit somebody edited by hand, and we refuse to interpret it.
        let no_exec = split_paths(get("NoExecPaths")?);
        let no_exec_writable = match () {
            () if no_exec == read_write_paths => !no_exec.is_empty(),
            () if no_exec.is_empty() => false,
            () => {
                return Err(Error::Policy(
                    "NoExecPaths covers only some writable paths".to_owned(),
                ));
            }
        };
        if get("IPAddressDeny")? != "any" {
            return Err(Error::Policy(
                "egress is not default-deny: IPAddressDeny must be any".to_owned(),
            ));
        }
        Ok(Hardening {
            read_only_root: match get("ProtectSystem")? {
                "strict" => true,
                "no" => false,
                other => {
                    return Err(Error::Policy(format!(
                        "ProtectSystem={other} is not a mode we emit"
                    )));
                }
            },
            no_new_privileges: flag("NoNewPrivileges", get("NoNewPrivileges")?)?,
            private_tmp: flag("PrivateTmp", get("PrivateTmp")?)?,
            drop_all_capabilities: match get("CapabilityBoundingSet")? {
                "" => true,
                "~" => false,
                other => {
                    return Err(Error::Policy(format!(
                        "CapabilityBoundingSet={other} is a partial set"
                    )));
                }
            },
            restrict_suid_sgid: flag("RestrictSUIDSGID", get("RestrictSUIDSGID")?)?,
            no_exec_writable,
            user: get("User")?.to_owned(),
            group: get("Group")?.to_owned(),
            read_write_paths,
            egress_allow: get("IPAddressAllow")?
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            pids_max: number("TasksMax", get("TasksMax")?)?,
            memory_max_bytes: number("MemoryMax", get("MemoryMax")?)?,
        })
    }

    /// Reads a container profile back into the properties it expresses.
    ///
    /// The profile declares each property *and* carries the mounts and flags that implement it, and
    /// this checks the two against each other. A profile whose `--read-only` was deleted while the
    /// field stayed `true` is a lie a lab would otherwise run happily.
    pub fn read_container(profile: &str) -> Result<Hardening> {
        let profile: ContainerProfile = serde_json::from_str(profile)
            .map_err(|err| Error::Policy(format!("container profile: {err}")))?;
        profile.check()?;
        profile.hardening()
    }
}

/// Renders a path list the way both `ReadWritePaths=` and `NoExecPaths=` take one.
fn paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Splits a systemd path list.
fn split_paths(value: &str) -> Vec<PathBuf> {
    value.split_whitespace().map(PathBuf::from).collect()
}

/// Reads a systemd boolean, refusing the spellings we never emit so a hand-edit is visible.
fn flag(key: &str, value: &str) -> Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(Error::Policy(format!("{key}={other} is not true or false"))),
    }
}

/// Reads a numeric directive.
fn number<T: std::str::FromStr>(key: &str, value: &str) -> Result<T> {
    value
        .parse()
        .map_err(|_| Error::Policy(format!("{key}={value} is not a number")))
}

/// One bind mount, with the options that carry two of the hardening properties.
#[derive(Debug, Serialize, Deserialize)]
struct Mount {
    /// Host path.
    source: PathBuf,
    /// Path inside the sandbox. Always the same as `source`, so a path in a record means the same
    /// thing whichever artefact is running.
    target: PathBuf,
    /// Mount options, `rw` plus whatever the policy adds.
    options: Vec<String>,
}

/// Egress policy, in the shape the launcher reads.
#[derive(Debug, Serialize, Deserialize)]
struct Egress {
    /// Always `deny`; the field exists so a reader can check it rather than assume it.
    default: String,
    /// Destinations allowed out.
    allow: Vec<String>,
    /// Network the launcher attaches, and programs the allowlist on. `none` when nothing is
    /// allowed out, which needs no network at all.
    network: String,
}

/// The container-side rendering of a [`Policy`].
///
/// Field names follow container vocabulary rather than systemd's, because this file is read by a
/// launcher; the *properties* are the same ones, which is what [`Policy::read_container`] checks.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Serialize, Deserialize)]
struct ContainerProfile {
    /// Schema marker, so a launcher can refuse a shape it does not know.
    schema: String,
    /// Container name, from the policy name.
    name: String,
    /// The command to run, split on whitespace from `ExecStart`.
    command: Vec<String>,
    /// `user:group`, by name.
    user: String,
    /// Read-only root filesystem.
    read_only_root_filesystem: bool,
    /// No privilege escalation.
    no_new_privileges: bool,
    /// A private `/tmp`.
    private_tmp: bool,
    /// `setuid`/`setgid` inert on every mount.
    restrict_suid_sgid: bool,
    /// No execution from a writable mount.
    no_exec_writable: bool,
    /// Capabilities dropped. `["ALL"]` or empty.
    cap_drop: Vec<String>,
    /// Writable bind mounts.
    mounts: Vec<Mount>,
    /// Tmpfs mounts. Holds `/tmp` when the policy asks for a private one.
    tmpfs: Vec<Mount>,
    /// Egress policy.
    egress: Egress,
    /// Task ceiling.
    pids_limit: u32,
    /// Memory ceiling.
    memory_limit_bytes: u64,
    /// The flags a launcher passes, derived from the fields above and checked against them.
    ///
    /// Spelled for a runtime that takes mount options — `nosuid`, `noexec`, `nodev` — on
    /// `--mount`, which is what makes two of the properties enforceable there at all. A runtime
    /// without them can still read the fields above; what it cannot do is claim this policy.
    runtime_args: Vec<String>,
}

impl ContainerProfile {
    /// The network name for an egress policy: none at all when nothing may leave.
    fn network(name: &str, allow: &[String]) -> String {
        if allow.is_empty() {
            "none".to_owned()
        } else {
            format!("{name}-egress")
        }
    }

    /// Mount options implied by the policy. `nodev` is unconditional: no policy here asks for
    /// device nodes on a data mount, so making it a property would be a knob with one setting.
    fn options(h: &Hardening) -> Vec<String> {
        let mut options = vec!["rw".to_owned(), "nodev".to_owned()];
        if h.restrict_suid_sgid {
            options.push("nosuid".to_owned());
        }
        if h.no_exec_writable {
            options.push("noexec".to_owned());
        }
        options
    }

    /// Checks the declared properties against the mounts and flags meant to implement them.
    fn check(&self) -> Result<()> {
        if self.schema != SCHEMA {
            return Err(Error::Policy(format!(
                "container profile schema {} is not {SCHEMA}",
                self.schema
            )));
        }
        if self.egress.default != "deny" {
            return Err(Error::Policy(
                "container egress is not default-deny".to_owned(),
            ));
        }
        for mount in self.mounts.iter().chain(&self.tmpfs) {
            if mount.source != mount.target {
                return Err(Error::Policy(format!(
                    "mount {} is remapped to {}, so a path means two things",
                    mount.source.display(),
                    mount.target.display()
                )));
            }
            for (option, declared) in [
                ("nosuid", self.restrict_suid_sgid),
                ("noexec", self.no_exec_writable),
            ] {
                if mount.options.iter().any(|o| o == option) != declared {
                    return Err(Error::Policy(format!(
                        "mount {} does not implement {option}={declared}",
                        mount.target.display()
                    )));
                }
            }
        }
        if self.private_tmp != self.tmpfs.iter().any(|m| m.target == Path::new("/tmp")) {
            return Err(Error::Policy(
                "private_tmp does not match the tmpfs mounts".to_owned(),
            ));
        }
        self.check_args()
    }

    /// Checks that the runtime flags are the ones this profile's properties imply.
    fn check_args(&self) -> Result<()> {
        let expected = Self::args(
            &self.name,
            &self.user,
            &self.hardening()?,
            &self.mounts,
            &self.tmpfs,
        );
        if expected == self.runtime_args {
            return Ok(());
        }
        Err(Error::Policy(
            "runtime_args are not the flags this profile's properties imply".to_owned(),
        ))
    }

    /// The launcher flags for a policy. The image and command are appended by the launcher, so
    /// this list is only the confinement.
    fn args(
        name: &str,
        user: &str,
        h: &Hardening,
        mounts: &[Mount],
        tmpfs: &[Mount],
    ) -> Vec<String> {
        let mut args = vec![
            "--name".to_owned(),
            name.to_owned(),
            "--user".to_owned(),
            user.to_owned(),
        ];
        if h.read_only_root {
            args.push("--read-only".to_owned());
        }
        if h.no_new_privileges {
            args.push("--security-opt".to_owned());
            args.push("no-new-privileges=true".to_owned());
        }
        if h.drop_all_capabilities {
            args.push("--cap-drop".to_owned());
            args.push("ALL".to_owned());
        }
        for mount in tmpfs {
            args.push("--tmpfs".to_owned());
            args.push(format!(
                "{}:{}",
                mount.target.display(),
                mount.options.join(",")
            ));
        }
        for mount in mounts {
            args.push("--mount".to_owned());
            args.push(format!(
                "type=bind,source={},target={},{}",
                mount.source.display(),
                mount.target.display(),
                mount.options.join(",")
            ));
        }
        args.push("--pids-limit".to_owned());
        args.push(h.pids_max.to_string());
        args.push("--memory".to_owned());
        args.push(h.memory_max_bytes.to_string());
        args.push("--network".to_owned());
        args.push(Self::network(name, &h.egress_allow));
        args
    }

    /// The properties this profile declares.
    fn hardening(&self) -> Result<Hardening> {
        let (user, group) = self
            .user
            .split_once(':')
            .ok_or_else(|| Error::Policy(format!("user {} is not user:group", self.user)))?;
        let expected = Self::network(&self.name, &self.egress.allow);
        if self.egress.network != expected {
            return Err(Error::Policy(format!(
                "egress network {} does not match the allowlist",
                self.egress.network
            )));
        }
        Ok(Hardening {
            read_only_root: self.read_only_root_filesystem,
            no_new_privileges: self.no_new_privileges,
            private_tmp: self.private_tmp,
            drop_all_capabilities: self.cap_drop.iter().any(|cap| cap == "ALL"),
            restrict_suid_sgid: self.restrict_suid_sgid,
            no_exec_writable: self.no_exec_writable,
            user: user.to_owned(),
            group: group.to_owned(),
            read_write_paths: self.mounts.iter().map(|m| m.target.clone()).collect(),
            egress_allow: self.egress.allow.clone(),
            pids_max: self.pids_limit,
            memory_max_bytes: self.memory_limit_bytes,
        })
    }
}

/// Schema marker a launcher checks before trusting a profile's shape.
const SCHEMA: &str = "harness.sandbox.container/v1";

impl From<&Policy> for ContainerProfile {
    fn from(policy: &Policy) -> Self {
        let h = &policy.hardening;
        let options = Self::options(h);
        let mounts: Vec<Mount> = h
            .read_write_paths
            .iter()
            .map(|path| Mount {
                source: path.clone(),
                target: path.clone(),
                options: options.clone(),
            })
            .collect();
        let tmpfs = if h.private_tmp {
            vec![Mount {
                source: PathBuf::from("/tmp"),
                target: PathBuf::from("/tmp"),
                options: options.clone(),
            }]
        } else {
            Vec::new()
        };
        let user = format!("{}:{}", h.user, h.group);
        let runtime_args = Self::args(&policy.name, &user, h, &mounts, &tmpfs);
        Self {
            schema: SCHEMA.to_owned(),
            name: policy.name.clone(),
            command: policy
                .exec_start
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            user,
            read_only_root_filesystem: h.read_only_root,
            no_new_privileges: h.no_new_privileges,
            private_tmp: h.private_tmp,
            restrict_suid_sgid: h.restrict_suid_sgid,
            no_exec_writable: h.no_exec_writable,
            cap_drop: if h.drop_all_capabilities {
                vec!["ALL".to_owned()]
            } else {
                Vec::new()
            },
            mounts,
            tmpfs,
            egress: Egress {
                default: "deny".to_owned(),
                allow: h.egress_allow.clone(),
                network: Self::network(&policy.name, &h.egress_allow),
            },
            pids_limit: h.pids_max,
            memory_limit_bytes: h.memory_max_bytes,
            runtime_args,
        }
    }
}
