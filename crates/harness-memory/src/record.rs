//! Turning a draft into the complete record the store requires.
//!
//! The store refuses an incomplete record on purpose: a caller able to leave `visibility` or
//! `data_class` off would be choosing a record's read scope and its erasability by omission. So the
//! missing half is stamped here, where the identity, the clock and the attribution live and where
//! an agent cannot reach them. The alternative — teaching the store to fill the gaps — would also
//! hand it a caller's word on who performed an action, which is the one thing its socket ownership
//! is there to establish.
//!
//! The wire shape is `spec/schemas/action-record.v1.json` in the store's repository. Two spellings
//! of one contract only agree until one is edited alone, so the field names, the enum spellings and
//! every default below are stated as constants with the reason attached.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use harness_agent::{ActionDraft, Status};
use serde::Serialize;

/// Milliseconds in a day.
const MS_PER_DAY: i64 = 86_400_000;

/// Record schema version this client writes under.
const SCHEMA_VER: u32 = 1;

/// Redaction policy declared on every record.
///
/// The store compares this against the policy the deployment actually applies and refuses a
/// mismatch, so a deployment that renames its policy gets a permanent rejection naming both
/// spellings rather than a record filed under a policy nothing applied. Loud is the recoverable
/// direction here: the record never lands, and the operator is told which two names disagree.
const REDACTION_POLICY: &str = "default-v1";

/// Read scope for a stamped record.
///
/// The narrowest scope that needs no configuration this side does not have: `team` requires a team
/// name the harness is never told, `org` would widen the audience of every record the harness
/// writes, and `operator` is the audit trail, which is not ours to write into. Widening later is a
/// re-classification; narrowing later cannot un-read what has already been read.
const VISIBILITY: &str = "owner";

/// Erasability class for a stamped record.
///
/// `internal` is the only class this client can write: `subject_derived` seals the body and makes it
/// erasable by destroying subject keys, and the store refuses a subject-derived record that names no
/// subject — which this side cannot do, having no subject resolver. So the erasable class is not
/// available rather than not chosen, and the consequence is stated in [`Record::subjects`].
const DATA_CLASS: &str = "internal";

/// Role given to every entity a draft names.
///
/// The draft calls them "entities this action touched" and puts no ordering or centrality on them,
/// so demoting some of them to `context` or `related` would invent a distinction the draft does not
/// carry. `primary` keeps every declared entity a first-class join key, which is what a draft
/// naming it was asking for.
const ENTITY_ROLE: &str = "primary";

/// Confidence given to every entity a draft names.
///
/// Below `1.0` means inferred from prose. An agent puts these in a structured field of its own
/// draft, so nothing here was extracted and nothing here is a guess — and a read filtering on
/// `min_confidence=1.0` is asking for exactly the references that were asserted rather than read
/// out of text.
const ENTITY_CONFIDENCE: f32 = 1.0;

/// The lists this client always sends empty. The element type is never constructed; each field
/// below says why its own list has nothing in it.
const EMPTY: &[&str] = &[];

/// A reference from a record to an entity, as the store spells it.
///
/// The draft carries `(kind, id)` tuples, which serialise as two-element arrays; the store wants an
/// object with a role and a confidence. This is that translation, and it is the reason a draft could
/// never be posted as-is.
#[derive(Debug, Serialize)]
struct Entity<'a> {
    /// Entity kind, checked against the deployment's `spec/entities.yaml`.
    kind: &'a str,
    /// Canonical identifier.
    id: &'a str,
    /// How the entity relates to the record.
    role: &'static str,
    /// Extraction confidence.
    confidence: f32,
}

/// A complete record, ready for the store.
///
/// Borrowed from the draft throughout: this is built, serialised and dropped inside one submission,
/// so copying the attributes and the prose would buy nothing.
#[derive(Debug, Serialize)]
// Every field name here is the store's, not ours: these are the wire keys, and renaming one to
// please a lint would rename it on the wire.
#[expect(
    clippy::struct_field_names,
    reason = "`record_id` is the store's field name"
)]
pub(crate) struct Record<'a> {
    /// Identity, and the store's idempotency key for the write.
    record_id: String,
    /// Schema version this record was written under.
    schema_ver: u32,
    /// The source's own time.
    at: String,
    /// The time the store orders and windows by.
    received_at: String,
    /// `false` because `received_at` came from our clock rather than from an upstream source.
    backfilled: bool,
    /// Who is claiming the action. From configuration, never from the draft.
    agent: &'a str,
    /// The interaction this record belongs to. Omitted when the caller named none, because an empty
    /// id is "nothing to link" rather than a link to nothing.
    #[serde(skip_serializing_if = "str::is_empty")]
    correlation_id: &'a str,
    /// What was done.
    action: &'a str,
    /// How it went, in the store's spelling.
    outcome: &'static str,
    /// Declared attributes, passed through exactly as the agent wrote them.
    attrs: &'a BTreeMap<String, serde_json::Value>,
    /// Entities this record joins on.
    entities: Vec<Entity<'a>>,
    /// Data subjects. Always empty: naming one needs a resolver this side does not have, and a
    /// guess would claim erasability the record cannot deliver. The cost is real and belongs in the
    /// open — a draft whose prose describes a person is stored as plaintext no key destruction
    /// reaches, so a deployment that needs erasable records needs a resolver here first.
    subjects: &'static [&'static str],
    /// Read scope.
    visibility: &'static str,
    /// Whether the body is erasable.
    data_class: &'static str,
    /// Policy applied before the write.
    redaction_policy: &'static str,
    /// Fields the policy masked. Always empty: nothing on this side masks anything, and naming a
    /// field here would tell a later reader it had been cleaned when it had not.
    fields_masked: &'static [&'static str],
    /// Free tags. Always empty: tags are the deployment's vocabulary, and a tag invented here would
    /// put the harness's words into it.
    tags: &'static [&'static str],
    /// Prose. Becomes the record body.
    summary: &'a str,
}

impl<'a> Record<'a> {
    /// Stamps a draft into a record: identity, timing and attribution added, nothing else changed.
    ///
    /// The identity is minted here, at translation, and that is what makes the store's idempotency
    /// work. `record_id` *is* the idempotency key, so the id has to be fixed before the bytes reach
    /// a transport: every redelivery a transport performs — the sidecar draining its spool, or a
    /// resend on the same connection — replays those bytes, sees the same id, and lands as one
    /// record rather than two. Minting inside the transport instead, per attempt, is precisely the
    /// mistake that turns one retry into two rows.
    ///
    /// The timestamps are fixed at the same moment and for the same reason: `received_at` is what
    /// the store orders by, so re-stamping it on a retry would move a record in time as a side
    /// effect of a redelivery.
    pub(crate) fn stamp(agent: &'a str, draft: &'a ActionDraft, correlation_id: &'a str) -> Self {
        // One instant, written twice. `at` is the source's own clock and `received_at` is the
        // store's; for a record produced here the source *is* here, so they cannot differ.
        let now = rfc3339_millis(SystemTime::now());
        Self {
            record_id: ulid::Ulid::new().to_string(),
            schema_ver: SCHEMA_VER,
            at: now.clone(),
            received_at: now,
            backfilled: false,
            agent,
            correlation_id,
            action: &draft.action,
            outcome: outcome(draft.outcome),
            attrs: &draft.attrs,
            entities: draft
                .entities
                .iter()
                .map(|(kind, id)| Entity {
                    kind,
                    id,
                    role: ENTITY_ROLE,
                    confidence: ENTITY_CONFIDENCE,
                })
                .collect(),
            subjects: EMPTY,
            visibility: VISIBILITY,
            data_class: DATA_CLASS,
            redaction_policy: REDACTION_POLICY,
            fields_masked: EMPTY,
            tags: EMPTY,
            summary: &draft.summary,
        }
    }
}

/// How the store spells an outcome.
///
/// The two enums do not agree, and quietly: the harness says `succeeded` and `failed` where the
/// store says `success` and `failure`. Mapped by hand rather than re-serialised, so a rename on
/// either side has to be resolved here instead of surfacing as a rejected write.
fn outcome(status: Status) -> &'static str {
    match status {
        Status::Succeeded => "success",
        Status::Failed => "failure",
        Status::Partial => "partial",
        Status::Declined => "declined",
    }
}

/// Formats an instant as an RFC 3339 UTC timestamp with milliseconds.
///
/// Written out rather than delegated to a date library: the store hand-parses this grammar, and the
/// only thing needed here is the one spelling it reads. Milliseconds are included because the store
/// orders on `received_at` and two records a millisecond apart are common.
fn rfc3339_millis(at: SystemTime) -> String {
    let ms = unix_millis(at);
    let (year, month, day) = civil_from_days(ms.div_euclid(MS_PER_DAY));
    let time = ms.rem_euclid(MS_PER_DAY);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        time / 3_600_000,
        time / 60_000 % 60,
        time / 1_000 % 60,
        time % 1_000
    )
}

/// Milliseconds since the Unix epoch, negative for an instant before it.
///
/// A clock set before 1970 is somebody's misconfiguration rather than this function's problem, but
/// it must not panic here: the store's own validation is where an implausible stamp gets refused,
/// and it can only refuse one it was sent.
fn unix_millis(at: SystemTime) -> i64 {
    match at.duration_since(UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_millis()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_millis()).unwrap_or(i64::MIN),
    }
}

/// The UTC calendar date a day number falls on, counting days from the Unix epoch.
///
/// Hinnant's civil-from-days: the era arithmetic gets the Gregorian leap rule right without a table,
/// which is the part a hand-rolled conversion usually gets wrong on 29 February or on a century
/// year.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    // Shift the epoch to 0000-03-01, which puts the leap day at the end of a 400-year era.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let march_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * march_month + 2) / 5 + 1;
    let month = if march_month < 10 {
        march_month + 3
    } else {
        march_month - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use harness_agent::{ActionDraft, Status};
    use serde_json::{Value, json};

    use super::{Record, outcome, rfc3339_millis};

    /// A draft naming one entity and one attribute.
    fn draft() -> ActionDraft {
        ActionDraft {
            action: "deploy".into(),
            outcome: Status::Succeeded,
            attrs: [("service".to_owned(), json!("api"))].into_iter().collect(),
            entities: vec![("deploy".to_owned(), "api/staging#1146".to_owned())],
            summary: "probe".into(),
        }
    }

    /// The stamped record, as JSON.
    fn stamped(draft: &ActionDraft, correlation_id: &str) -> Value {
        serde_json::to_value(Record::stamp("harness", draft, correlation_id)).expect("serialises")
    }

    /// An instant `ms` milliseconds after the epoch.
    fn at(ms: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(ms)
    }

    #[test]
    fn a_stamped_record_carries_every_field_the_store_requires() {
        // The defect this fixes was a body missing eleven of these. Listing them here means a field
        // dropped in a refactor fails a test rather than a live write.
        let record = stamped(&draft(), "env-lab-1");
        for field in [
            "record_id",
            "schema_ver",
            "at",
            "received_at",
            "backfilled",
            "agent",
            "correlation_id",
            "action",
            "outcome",
            "attrs",
            "entities",
            "subjects",
            "visibility",
            "data_class",
            "redaction_policy",
            "fields_masked",
            "tags",
            "summary",
        ] {
            assert!(record.get(field).is_some(), "missing `{field}`: {record}");
        }
        // The store refuses a field it does not declare, so a wrapper is as fatal as a gap.
        assert_eq!(record.get("record"), None, "the record is not nested");
    }

    #[test]
    fn the_defaults_are_the_ones_documented() {
        let record = stamped(&draft(), "env-lab-1");
        assert_eq!(record["schema_ver"], json!(1));
        assert_eq!(record["backfilled"], json!(false));
        assert_eq!(record["subjects"], json!([]));
        assert_eq!(record["visibility"], json!("owner"));
        assert_eq!(record["data_class"], json!("internal"));
        assert_eq!(record["redaction_policy"], json!("default-v1"));
        assert_eq!(record["fields_masked"], json!([]));
        assert_eq!(record["tags"], json!([]));
    }

    #[test]
    fn the_draft_reaches_the_store_unaltered() {
        let record = stamped(&draft(), "env-lab-1");
        assert_eq!(record["agent"], json!("harness"));
        assert_eq!(record["correlation_id"], json!("env-lab-1"));
        assert_eq!(record["action"], json!("deploy"));
        assert_eq!(record["attrs"], json!({"service": "api"}));
        assert_eq!(record["summary"], json!("probe"));
    }

    #[test]
    fn an_entity_tuple_becomes_an_asserted_reference() {
        let record = stamped(&draft(), "env-lab-1");
        assert_eq!(
            record["entities"],
            json!([{
                "kind": "deploy",
                "id": "api/staging#1146",
                "role": "primary",
                "confidence": 1.0,
            }]),
            "a `(kind, id)` tuple would serialise as a two-element array"
        );
    }

    #[test]
    fn an_attribute_named_correlation_id_keeps_its_own_meaning() {
        // Two different things that share a name. With the interaction stamped into `attrs`, one of
        // them was unrepresentable; now the field holds the interaction and the attribute holds
        // whatever the agent meant by it.
        let mut draft = draft();
        draft
            .attrs
            .insert("correlation_id".to_owned(), json!("corr-agent"));

        let record = stamped(&draft, "env-lab-1");

        assert_eq!(record["correlation_id"], json!("env-lab-1"));
        assert_eq!(record["attrs"]["correlation_id"], json!("corr-agent"));
    }

    #[test]
    fn no_interaction_leaves_the_field_off_the_wire() {
        assert_eq!(stamped(&draft(), "").get("correlation_id"), None);
    }

    #[test]
    fn the_record_id_is_a_ulid() {
        // The store parses this as Crockford base32 and refuses anything else, `I`, `L`, `O` and
        // `U` included.
        let record = stamped(&draft(), "env-lab-1");
        let id = record["record_id"].as_str().expect("a string");
        assert_eq!(id.len(), 26, "{id}");
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_digit() || (b.is_ascii_uppercase() && !b"ILOU".contains(&b))),
            "{id}"
        );
    }

    #[test]
    fn each_stamp_mints_its_own_identity() {
        // Two submissions of the same draft are two records. Reuse belongs to a retry of one
        // submission, which replays bytes already stamped rather than stamping again.
        let draft = draft();
        assert_ne!(
            stamped(&draft, "env-lab-1")["record_id"],
            stamped(&draft, "env-lab-1")["record_id"]
        );
    }

    #[test]
    fn both_timestamps_name_the_same_instant() {
        let record = stamped(&draft(), "env-lab-1");
        assert_eq!(record["at"], record["received_at"]);
    }

    #[test]
    fn every_status_maps_onto_the_stores_spelling() {
        // Two of the four differ, which is exactly why this is a table and not a re-serialisation.
        assert_eq!(outcome(Status::Succeeded), "success");
        assert_eq!(outcome(Status::Failed), "failure");
        assert_eq!(outcome(Status::Partial), "partial");
        assert_eq!(outcome(Status::Declined), "declined");
    }

    #[test]
    fn a_timestamp_is_rfc_3339_in_utc() {
        assert_eq!(rfc3339_millis(at(0)), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_millis(at(1_000)), "1970-01-01T00:00:01.000Z");
        assert_eq!(rfc3339_millis(at(86_399_999)), "1970-01-01T23:59:59.999Z");
        assert_eq!(rfc3339_millis(at(86_400_000)), "1970-01-02T00:00:00.000Z");
    }

    #[test]
    fn the_leap_rule_holds_where_a_hand_rolled_one_usually_does_not() {
        // 2000 is a leap year, 1900 was not, and 2024-02-29 exists. A conversion that gets any of
        // these wrong files records under the wrong day, which a windowed query then does not see.
        assert_eq!(
            rfc3339_millis(at(951_782_400_000)),
            "2000-02-29T00:00:00.000Z"
        );
        assert_eq!(
            rfc3339_millis(at(1_709_164_800_000)),
            "2024-02-29T00:00:00.000Z"
        );
        assert_eq!(
            rfc3339_millis(at(1_735_689_599_999)),
            "2024-12-31T23:59:59.999Z"
        );
        assert_eq!(
            rfc3339_millis(at(1_735_689_600_000)),
            "2025-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn a_clock_set_before_the_epoch_formats_rather_than_panics() {
        // Someone else's misconfiguration. The store is where an implausible stamp gets refused,
        // and it can only refuse one it was sent.
        let before = UNIX_EPOCH - Duration::from_millis(1);
        assert_eq!(rfc3339_millis(before), "1969-12-31T23:59:59.999Z");
    }
}
