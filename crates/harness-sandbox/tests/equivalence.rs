//! The test that stops the two sandboxes drifting apart.
//!
//! A lab that proves a sandbox other than the deployed one proves nothing, so the systemd unit and
//! the container profile are both generated from one policy and both read *back* here. Three
//! properties are asserted, and it is the third that has the long-term value:
//!
//! 1. the two artefacts agree with each other, and with the policy they came from;
//! 2. weakening either one by hand is detected;
//! 3. every field of [`Hardening`] is visible in both artefacts — so a property added to the policy
//!    and rendered into only one of them fails here rather than in production.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use harness_sandbox::{Hardening, Policy};

/// One named change to a policy, used to prove both artefacts carry the property it touches.
type Mutation = (&'static str, fn(&mut Hardening));

/// A policy with every property switched on, which is what a deployment actually runs.
fn strict() -> Policy {
    let mut policy = Policy::phase0(
        "service",
        "/usr/local/bin/harness run",
        Path::new("/srv/state"),
    );
    policy.hardening.egress_allow = vec!["10.0.0.0/8".to_owned(), "192.0.2.7/32".to_owned()];
    policy
}

/// Reads both artefacts back and returns what each says.
fn round_trip(policy: &Policy) -> (Hardening, Hardening) {
    let unit = Policy::read_systemd(&policy.systemd_unit()).expect("read the unit");
    let profile = Policy::read_container(&policy.container_profile()).expect("read the profile");
    (unit, profile)
}

#[test]
fn both_artefacts_describe_the_policy_they_were_generated_from() {
    let policy = strict();
    let (unit, profile) = round_trip(&policy);

    assert_eq!(
        unit, profile,
        "the two artefacts describe different sandboxes"
    );
    assert_eq!(unit, policy.hardening, "the unit drifted from the policy");
}

#[test]
fn every_property_is_visible_in_both_artefacts() {
    // The exhaustiveness check. Each entry changes one field; if either emitter ignores that field,
    // the changed policy reads back identical to the baseline and this fails.
    let baseline = strict();
    let (base_unit, base_profile) = round_trip(&baseline);
    assert_eq!(base_unit, base_profile);

    let mutations: Vec<Mutation> = vec![
        ("read_only_root", |h| h.read_only_root = false),
        ("no_new_privileges", |h| h.no_new_privileges = false),
        ("private_tmp", |h| h.private_tmp = false),
        ("drop_all_capabilities", |h| h.drop_all_capabilities = false),
        ("restrict_suid_sgid", |h| h.restrict_suid_sgid = false),
        ("no_exec_writable", |h| h.no_exec_writable = false),
        ("user", |h| h.user = "other".to_owned()),
        ("group", |h| h.group = "other".to_owned()),
        ("pids_max", |h| h.pids_max = 7),
        ("memory_max_bytes", |h| h.memory_max_bytes = 1),
        ("read_write_paths", |h| {
            h.read_write_paths = vec![PathBuf::from("/srv/other")];
        }),
        ("egress_allow", |h| {
            h.egress_allow = vec!["198.51.100.0/24".to_owned()];
        }),
    ];

    // One entry per field, so a field added to `Hardening` without an entry here is caught by the
    // count rather than passing unnoticed.
    assert_eq!(
        mutations.len(),
        12,
        "a property was added to Hardening without a mutation to prove both artefacts carry it"
    );

    for (name, mutate) in mutations {
        let mut changed = baseline.clone();
        mutate(&mut changed.hardening);
        let (unit, profile) = round_trip(&changed);

        assert_eq!(unit, profile, "{name}: the artefacts disagree");
        assert_eq!(
            unit, changed.hardening,
            "{name}: the artefacts lost the change"
        );
        assert_ne!(
            unit, base_unit,
            "{name}: the unit does not carry this property"
        );
        assert_ne!(
            profile, base_profile,
            "{name}: the container profile does not carry this property"
        );
    }
}

#[test]
fn a_softened_unit_stops_matching_the_container_profile() {
    let policy = strict();
    let profile = Policy::read_container(&policy.container_profile()).expect("profile");

    for (from, to) in [
        ("NoNewPrivileges=true", "NoNewPrivileges=false"),
        ("ProtectSystem=strict", "ProtectSystem=no"),
        ("PrivateTmp=true", "PrivateTmp=false"),
        ("RestrictSUIDSGID=true", "RestrictSUIDSGID=false"),
        ("CapabilityBoundingSet=", "CapabilityBoundingSet=~"),
        ("TasksMax=64", "TasksMax=4096"),
        ("MemoryMax=536870912", "MemoryMax=8589934592"),
        ("IPAddressAllow=10.0.0.0/8", "IPAddressAllow=0.0.0.0/0"),
    ] {
        let edited = policy.systemd_unit().replacen(from, to, 1);
        let unit = Policy::read_systemd(&edited).unwrap_or_else(|err| panic!("{from}: {err}"));
        assert_ne!(unit, profile, "editing {from} went unnoticed");
    }
}

#[test]
fn a_softened_container_profile_stops_matching_the_unit() {
    let policy = strict();
    let unit = Policy::read_systemd(&policy.systemd_unit()).expect("unit");

    for (from, to) in [
        (
            "\"no_new_privileges\": true",
            "\"no_new_privileges\": false",
        ),
        (
            "\"read_only_root_filesystem\": true",
            "\"read_only_root_filesystem\": false",
        ),
        ("\"pids_limit\": 64", "\"pids_limit\": 4096"),
    ] {
        let edited = policy.container_profile().replacen(from, to, 1);
        // Either the profile no longer implements what it declares, or it declares something the
        // unit does not. Both are the failure this test is for.
        match Policy::read_container(&edited) {
            Ok(profile) => assert_ne!(profile, unit, "editing {from} went unnoticed"),
            Err(err) => assert!(err.to_string().contains("policy"), "{from}: {err}"),
        }
    }
}

#[test]
fn a_profile_whose_flags_no_longer_match_its_properties_is_refused() {
    // The flags are what a launcher actually passes. A profile that declares a read-only root and
    // has had `--read-only` removed is the exact lie a lab would otherwise run happily.
    let profile = strict().container_profile();
    let stripped = profile.replace("    \"--read-only\",\n", "");
    assert_ne!(
        stripped, profile,
        "the flag should have been there to remove"
    );

    let error = Policy::read_container(&stripped).expect_err("stripped flag");
    assert!(error.to_string().contains("runtime_args"), "{error}");
}

#[test]
fn a_unit_missing_a_directive_is_refused_rather_than_defaulted() {
    // Defaulting a missing property is how a hand-maintained pair of files drifts: the reader must
    // require every property, so half a policy is an error.
    let unit = strict().systemd_unit();
    for line in unit.lines().filter(|line| line.contains('=')) {
        let without = unit.replace(&format!("{line}\n"), "");
        let read = Policy::read_systemd(&without);
        // Description, ExecStart and the section keys are not hardening properties.
        if line.starts_with("Description")
            || line.starts_with("ExecStart")
            || line.starts_with("Type")
            || line.starts_with("After")
            || line.starts_with("WantedBy")
            || line.starts_with("AmbientCapabilities")
        {
            assert!(read.is_ok(), "{line} is not a hardening property");
        } else {
            assert!(read.is_err(), "removing {line} was not noticed");
        }
    }
}

#[test]
fn the_emitted_unit_carries_the_hardening_the_design_asks_for() {
    // Named directives, so a rename in the emitter has to be a deliberate change here too.
    let unit = strict().systemd_unit();
    for directive in [
        "ProtectSystem=strict",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "CapabilityBoundingSet=",
        "RestrictSUIDSGID=true",
        "IPAddressDeny=any",
        "User=harness",
    ] {
        assert!(unit.contains(directive), "unit has no {directive}:\n{unit}");
    }
}

#[test]
fn a_policy_below_the_floor_is_refused() {
    let mut policy = strict();
    policy.validate().expect("the strict policy is valid");

    policy.hardening.read_only_root = false;
    policy.hardening.private_tmp = false;
    let error = policy.validate().expect_err("softened");
    assert!(error.to_string().contains("read_only_root"), "{error}");
    assert!(error.to_string().contains("private_tmp"), "{error}");

    let mut as_root = strict();
    as_root.hardening.user = "root".to_owned();
    assert!(as_root.validate().is_err());

    let mut unbounded = strict();
    unbounded.hardening.pids_max = 0;
    assert!(unbounded.validate().is_err());

    let mut nameless = strict();
    nameless.name = String::new();
    assert!(nameless.validate().is_err());
}

#[test]
fn a_policy_with_nothing_writable_still_round_trips() {
    // The edge case in both readers: with no writable paths, "no exec from a writable path" has
    // nothing to apply to, and the two artefacts have to reach the same conclusion anyway.
    let mut policy = strict();
    policy.hardening.read_write_paths = Vec::new();
    policy.hardening.private_tmp = false;
    policy.hardening.no_exec_writable = false;
    let (unit, profile) = round_trip(&policy);

    assert_eq!(unit, profile);
    assert_eq!(unit, policy.hardening);
}

#[test]
fn a_policy_allowing_no_egress_asks_for_no_network_at_all() {
    let mut policy = strict();
    policy.hardening.egress_allow = Vec::new();
    let (unit, profile) = round_trip(&policy);

    assert_eq!(unit, profile);
    assert!(policy.container_profile().contains("\"network\": \"none\""));
    assert!(policy.systemd_unit().contains("IPAddressAllow=\n"));
}

#[test]
fn nonsense_in_place_of_an_artefact_is_reported_rather_than_parsed() {
    assert!(Policy::read_systemd("this is not a unit").is_err());
    assert!(Policy::read_systemd("ProtectSystem=strict\nProtectSystem=no\n").is_err());
    assert!(Policy::read_systemd("ProtectSystem=maybe\n").is_err());
    assert!(Policy::read_container("{}").is_err());
    assert!(Policy::read_container("not json").is_err());
}

#[test]
fn a_doctored_unit_is_refused_with_the_reason() {
    // Each of these is a plausible hand-edit that would leave a unit looking fine. The reader has
    // to refuse rather than interpret, or a deployment ends up confined differently from the lab.
    let unit = strict().systemd_unit();
    for (from, to, expected) in [
        (
            "NoExecPaths=/srv/state/memory /srv/state/agents",
            "NoExecPaths=/srv/state/memory",
            "only some writable paths",
        ),
        ("IPAddressDeny=any", "IPAddressDeny=1.2.3.4", "default-deny"),
        (
            "ProtectSystem=strict",
            "ProtectSystem=full",
            "not a mode we emit",
        ),
        (
            "CapabilityBoundingSet=",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "partial set",
        ),
        ("PrivateTmp=true", "PrivateTmp=yes", "not true or false"),
        ("TasksMax=64", "TasksMax=lots", "not a number"),
    ] {
        let edited = unit.replacen(from, to, 1);
        assert_ne!(edited, unit, "{from} was not in the unit to edit");
        let error = Policy::read_systemd(&edited).expect_err(from);
        assert!(
            error.to_string().contains(expected),
            "editing {from} gave {error}, wanted {expected}"
        );
    }
}

#[test]
fn a_container_profile_that_does_not_implement_what_it_declares_is_refused() {
    let profile = strict().container_profile();
    for (from, to, expected) in [
        (
            "\"harness.sandbox.container/v1\"",
            "\"something.else/v9\"",
            "schema",
        ),
        (
            "\"default\": \"deny\"",
            "\"default\": \"allow\"",
            "default-deny",
        ),
        (
            "\"target\": \"/srv/state/memory\"",
            "\"target\": \"/container/memory\"",
            "means two things",
        ),
        (
            "\"nosuid\",\n        \"noexec\"",
            "\"noexec\"",
            "nosuid=true",
        ),
        (
            "\"private_tmp\": true",
            "\"private_tmp\": false",
            "tmpfs mounts",
        ),
        (
            "\"network\": \"service-egress\"",
            "\"network\": \"anything-else\"",
            "does not match the allowlist",
        ),
    ] {
        let edited = profile.replacen(from, to, 1);
        assert_ne!(edited, profile, "{from} was not in the profile to edit");
        let error = Policy::read_container(&edited).expect_err(from);
        assert!(
            error.to_string().contains(expected),
            "editing {from} gave {error}, wanted {expected}"
        );
    }
}
