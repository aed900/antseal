//! **F4 freeze gate** for the v1 wire-format registry — the normative
//! document `docs/format/registry-v1.md`, its machine mirror
//! `docs/format/registry-v1.json`, and the code that implements them.
//!
//! Renamed from `format_registry_draft.rs` at the Q14 `format-v1-freeze`
//! gate (D8 §12). The registry is now **frozen**: every number, name and
//! rule it records is format-permanent, and changing one is a
//! format-version event (MVP-SPEC.md line 123), not an edit.
//!
//! D8 §14 names the assertion set so it cannot be under-delivered.
//!
//! # A — mirror internal consistency
//!
//! The JSON parses and `registry_version == 1`; every map key, enum value,
//! tuple index and reserved-range bound is an unsigned integer (F4 accept:
//! "no negative or non-integer map keys anywhere in the registry"); no
//! duplicate key numbers within a map, nor duplicate values within an enum;
//! reserved ranges are well-formed, mutually disjoint, and collide with no
//! assigned key; every assigned key and reserved bound sits in the v1
//! single-byte band `0..=23` (registry §1 rule 4); the `maps[]` set is
//! exactly the fourteen registered names.
//!
//! # B — freeze state
//!
//! The document status is `frozen-v1`; every item's status **equals**
//! `frozen-v1` — equality, not membership in an allow-list, because an item
//! added with no status, with `proposed`, or with a novel spelling must all
//! fail identically; and none of the four pre-freeze strings occurs anywhere
//! in the mirror at any depth. That last one catches what an allow-list
//! structurally cannot: a `notes` string that still says "proposed", which
//! is how prose rots.
//!
//! # C — code ⟷ mirror
//!
//! The assertion both `manifest::registry` and `bundle::registry` claim in
//! their module docs: **every constant in those modules equals its registry
//! row**, in both directions. C1 map identity, C2 key numbers, C3 reserved
//! bands, C4 closed enums, C5 `sig_alg` (**both** code copies, C's and F's,
//! each against the mirror directly), C6 field **names**, C7 scalar lengths,
//! C8 tuple arities, C9 the nineteen D10 caps with their error codes, C10
//! the report's `AnchorState` against the wire's `AnchorStatus`.
//!
//! # D — document ⟷ mirror
//!
//! Registry §14 claims the JSON "mirrors this document 1:1". Until the
//! freeze nothing in the tree parsed the `.md` at all, so the claim was
//! unbacked — and the mirror had silently drifted from its own source.
//! This file now reads the document and compares its mechanical tables to
//! the mirror: §7's map tables (keys, **names**, reserved bands and named
//! slots), §7's per-field **type**, **presence**, `may be empty` **rule** and
//! **tier** tags (D111 R2–R5), §6's enum tables, §2's fixed-length table,
//! §11's cap table. The two surfaces' **prose** is compared to nothing, in
//! either direction, by design — D111 R1 records the measurement that refused
//! it. Brittleness to formatting is a feature after the freeze: the normative
//! document should not be reformatted silently.
//!
//! # E — recorded non-assertions
//!
//! Deliberate, not forgotten (registry §14): presence rules are expressed in
//! code by Rust types and cannot be reflected without a macro; validation
//! tiers have no code representation at all; §12's spec-coverage checklist
//! is prose; the receipt payload's internal layout is deliberately outside
//! the registry. One narrowing is recorded at its own assertion:
//! [`the_document_scalar_table_matches_the_mirror`] compares **lengths**,
//! because §2 groups by byte length while `scalars[]` names by role.
//!
//! This file also pins registry §7.6.1's **checked absences** on the table
//! side: no bundle map may grow a nonce, a signature container, a stored
//! `work_id`/`anchor_digest`/`seal_id`, a reveal-shape discriminant, a TSA
//! `source` string, or a receipt chain identifier.

use std::collections::{BTreeMap, BTreeSet};

use antseal_core::bundle::registry::{
    self as bundle_registry, AnchorStatus, BundleMapId, key as bundle_key,
};
use antseal_core::crypto::error::SigAlg;
use antseal_core::manifest::error::{
    AlgPosition, CondField, ContainerField, EnumId, FixedLenField, ManifestListKind,
};
use antseal_core::manifest::registry::{
    self as manifest_registry, DescriptorKind, FineTreeDomain, MapId, UnitKind,
};
use serde_json::Value;

const REGISTRY_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/format/registry-v1.json"
);

const DOC_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/format/registry-v1.md"
);

/// The **only** legal item status in a frozen v1 registry (D8 §12).
///
/// Not an allow-list: equality is strictly stronger, and after Q14 the
/// stronger property is what the document needs. The moment a v1.1 item is
/// drafted into a reserved slot this fails, forcing the v1.1 author to
/// extend the vocabulary consciously at their own gate rather than sliding
/// a proposal into a frozen document.
const FROZEN_ITEM_STATUS: &str = "frozen-v1";

/// The document-level marker, which is the same string.
const FROZEN_DOC_STATUS: &str = FROZEN_ITEM_STATUS;

/// Markers that were legal before the freeze and are illegal after it —
/// asserted absent from the whole mirror, at any depth, in any field.
const PRE_FREEZE_MARKERS: [&str; 4] = ["proposed", "pending-D9", "pending-D17", "draft-until-Q14"];

fn registry() -> Value {
    let text = std::fs::read_to_string(REGISTRY_PATH)
        .unwrap_or_else(|e| panic!("cannot read {REGISTRY_PATH}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("registry JSON does not parse: {e}"))
}

fn as_array<'a>(value: &'a Value, ctx: &str) -> &'a [Value] {
    value
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("{ctx}: expected a JSON array"))
}

fn get<'a>(obj: &'a Value, key: &str, ctx: &str) -> &'a Value {
    obj.get(key)
        .unwrap_or_else(|| panic!("{ctx}: missing field `{key}`"))
}

fn get_str<'a>(obj: &'a Value, key: &str, ctx: &str) -> &'a str {
    get(obj, key, ctx)
        .as_str()
        .unwrap_or_else(|| panic!("{ctx}: field `{key}` must be a string"))
}

/// The unsigned-integer assertion: JSON numbers that are negative or
/// fractional yield `None` from `as_u64` and fail here.
fn get_u64(obj: &Value, key: &str, ctx: &str) -> u64 {
    let value = get(obj, key, ctx);
    value
        .as_u64()
        .unwrap_or_else(|| panic!("{ctx}: field `{key}` must be an unsigned integer, got {value}"))
}

/// One keyed number space — a wire map (`fields[].key`) or a wire enum
/// (`values[].value`) — with its reserved `first..=last` ranges.
struct KeyedSpace {
    name: String,
    assigned: Vec<u64>,
    reserved: Vec<(u64, u64)>,
}

fn keyed_spaces(root: &Value) -> Vec<KeyedSpace> {
    let mut spaces = Vec::new();
    for (section, item_list, number_field) in
        [("maps", "fields", "key"), ("enums", "values", "value")]
    {
        for entry in as_array(get(root, section, "registry root"), section) {
            let name = format!("{section}.{}", get_str(entry, "name", section));
            let assigned: Vec<u64> = as_array(get(entry, item_list, &name), &name)
                .iter()
                .map(|item| get_u64(item, number_field, &name))
                .collect();
            let reserved: Vec<(u64, u64)> = as_array(get(entry, "reserved", &name), &name)
                .iter()
                .map(|range| {
                    (
                        get_u64(range, "first", &name),
                        get_u64(range, "last", &name),
                    )
                })
                .collect();
            spaces.push(KeyedSpace {
                name,
                assigned,
                reserved,
            });
        }
    }
    spaces
}

#[test]
fn registry_json_parses() {
    let root = registry();
    assert_eq!(
        get_u64(&root, "registry_version", "registry root"),
        1,
        "this gate covers registry v1"
    );
    assert_eq!(
        get_str(&root, "status", "registry root"),
        FROZEN_DOC_STATUS,
        "the registry froze at the Q14 `format-v1-freeze` gate (D8 §12); a \
         document that still calls itself a draft is lying about its own state"
    );
    // The six-plus keyed structures the F4 brief names must all be present.
    for expected in [
        "manifest_envelope",
        "manifest_body",
        "file_entry",
        "canon_descriptor",
        "unit_entry",
        "bundle",
        "storage_record",
        "ots_anchor",
        "tsa_anchor",
        "receipt_record",
        "covered_reveal",
        "noncovered_reveal",
        "touched_file",
        "full_reveal",
    ] {
        assert!(
            as_array(get(&root, "maps", "registry root"), "maps")
                .iter()
                .any(|m| m.get("name").and_then(Value::as_str) == Some(expected)),
            "registry is missing the `{expected}` map"
        );
    }
}

#[test]
fn all_keys_are_unsigned_integers_within_the_v1_band() {
    let root = registry();
    let band_max = get_u64(get(&root, "profile", "root"), "v1_key_band_max", "profile");
    for KeyedSpace {
        name,
        assigned,
        reserved,
    } in keyed_spaces(&root)
    {
        // `get_u64` inside `keyed_spaces` already enforced unsignedness;
        // map keys must additionally sit in the single-byte v1 band
        // (registry §1 rule 4). Enum value spaces define their own bounds
        // via their reserved ranges, checked below only for well-formedness.
        if name.starts_with("maps.") {
            for key in &assigned {
                assert!(
                    *key <= band_max,
                    "{name}: assigned key {key} outside the v1 band 0..={band_max}"
                );
            }
            for (first, last) in &reserved {
                assert!(
                    *last <= band_max,
                    "{name}: reserved range {first}..={last} outside the v1 band 0..={band_max}"
                );
            }
        }
    }
    // Tuple element indexes: unsigned and contiguous from 0 (positional).
    for tuple in as_array(get(&root, "tuples", "root"), "tuples") {
        let name = format!("tuples.{}", get_str(tuple, "name", "tuples"));
        let elements = as_array(get(tuple, "elements", &name), &name);
        for (position, element) in elements.iter().enumerate() {
            let index = get_u64(element, "index", &name);
            assert_eq!(
                index as usize, position,
                "{name}: tuple element indexes must be contiguous from 0"
            );
        }
    }
}

#[test]
fn no_duplicate_key_numbers_within_any_single_map() {
    for KeyedSpace { name, assigned, .. } in keyed_spaces(&registry()) {
        let mut sorted = assigned.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            assigned.len(),
            "{name}: duplicate key/value numbers in {assigned:?}"
        );
        assert!(!assigned.is_empty(), "{name}: no keys assigned at all");
    }
}

#[test]
fn reserved_ranges_do_not_collide_with_assigned_keys() {
    for KeyedSpace {
        name,
        assigned,
        reserved,
    } in keyed_spaces(&registry())
    {
        for (first, last) in &reserved {
            assert!(
                first <= last,
                "{name}: reserved range {first}..={last} is inverted"
            );
            for key in &assigned {
                assert!(
                    !(first <= key && key <= last),
                    "{name}: assigned key {key} collides with reserved range {first}..={last}"
                );
            }
        }
        // Reserved ranges within one space must also be mutually disjoint.
        for (i, a) in reserved.iter().enumerate() {
            for b in &reserved[i + 1..] {
                assert!(
                    a.1 < b.0 || b.1 < a.0,
                    "{name}: reserved ranges {a:?} and {b:?} overlap"
                );
            }
        }
    }
}

/// **B — every frozen item carries the frozen marker, by equality.**
#[test]
fn every_frozen_item_carries_the_frozen_marker() {
    fn walk(value: &Value, path: &str, violations: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if let Some(status) = map.get("status").and_then(Value::as_str)
                    && status != FROZEN_ITEM_STATUS
                {
                    violations.push(format!("{path}: status `{status}`"));
                }
                for (key, child) in map {
                    walk(child, &format!("{path}.{key}"), violations);
                }
            }
            Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    walk(child, &format!("{path}[{i}]"), violations);
                }
            }
            _ => {}
        }
    }

    let root = registry();
    let mut violations = Vec::new();
    let mut marked = 0usize;
    // The root-level `status` is the document marker, checked separately in
    // `registry_json_parses`; item statuses live under these five sections.
    for section in ["scalars", "enums", "tuples", "maps", "caps"] {
        walk(
            get(&root, section, "registry root"),
            section,
            &mut violations,
        );
    }
    // Count them too: a walk that found nothing to check would pass vacuously.
    fn count(value: &Value, marked: &mut usize) {
        match value {
            Value::Object(map) => {
                if map.get("status").and_then(Value::as_str).is_some() {
                    *marked += 1;
                }
                for child in map.values() {
                    count(child, marked);
                }
            }
            Value::Array(items) => items.iter().for_each(|c| count(c, marked)),
            _ => {}
        }
    }
    for section in ["scalars", "enums", "tuples", "maps", "caps"] {
        count(get(&root, section, "registry root"), &mut marked);
    }

    assert!(
        violations.is_empty(),
        "a frozen registry admits exactly one item status, `{FROZEN_ITEM_STATUS}`:\n{}",
        violations.join("\n")
    );
    // The arithmetic, so a future edit can tell a real change from a
    // miscount. D8 §12 counted **156** pre-freeze item markers (147
    // `proposed` + 9 `pending-D17`) plus the document marker = 157 `status`
    // fields. Three sit outside the five walked sections — the document
    // marker itself, `version_dispatch` and `profile.time_encoding` — and
    // one item marker left v1 with `tsa_anchor` key 4 (D8 §1). 157 − 3 − 1.
    assert_eq!(
        marked, 153,
        "a different count means an item gained or lost its status marker"
    );
    let raw = std::fs::read_to_string(REGISTRY_PATH).expect("mirror is readable");
    assert_eq!(
        raw.matches(&format!("\"status\": \"{FROZEN_ITEM_STATUS}\""))
            .count(),
        156,
        "every `status` field in the mirror, walked or not, must be frozen"
    );
}

/// **B — no pre-freeze marker survives anywhere in the mirror.**
///
/// A prohibition, not an allow-list entry. The four strings must not occur
/// at any depth, in any field — including key names and free prose, which is
/// the case an allow-list over `status` fields structurally cannot catch.
#[test]
fn no_pre_freeze_marker_survives_anywhere() {
    let raw = std::fs::read_to_string(REGISTRY_PATH)
        .unwrap_or_else(|e| panic!("cannot read {REGISTRY_PATH}: {e}"));
    for marker in PRE_FREEZE_MARKERS {
        assert!(
            !raw.contains(marker),
            "`{marker}` still occurs in the frozen mirror. It is illegal for a v1 \
             item: an item that still says so is either a question that escaped \
             the gate or a lie about the document's state, and both are worse \
             than a failing test. A v1.1 item needs its own vocabulary, extended \
             deliberately at its own gate."
        );
    }
    // The test-of-the-test: the strings really are searchable in this file's
    // own terms, so a typo in `PRE_FREEZE_MARKERS` cannot make it vacuous.
    assert!(raw.contains(FROZEN_ITEM_STATUS));
}

// ===========================================================================
// The 1:1 code ⟷ registry cross-check (F5/F8; registry §§7.15, 14)
// ===========================================================================

/// Look up one `maps[]` entry by its registry name.
fn map_entry<'a>(root: &'a Value, name: &str) -> &'a Value {
    as_array(get(root, "maps", "registry root"), "maps")
        .iter()
        .find(|m| m.get("name").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("registry has no map named `{name}`"))
}

/// Look up one `enums[]` entry by its registry name.
fn enum_entry<'a>(root: &'a Value, name: &str) -> &'a Value {
    as_array(get(root, "enums", "registry root"), "enums")
        .iter()
        .find(|e| e.get("name").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("registry has no enum named `{name}`"))
}

/// The assigned keys of one registry map, ascending.
fn registry_keys(root: &Value, name: &str) -> Vec<u64> {
    let entry = map_entry(root, name);
    let mut keys: Vec<u64> = as_array(get(entry, "fields", name), name)
        .iter()
        .map(|f| get_u64(f, "key", name))
        .collect();
    keys.sort_unstable();
    keys
}

/// The reserved band of one registry map as a single contiguous span, or
/// `None` when the map reserves nothing (the frozen manifest envelope).
///
/// A map may list several ranges — the two *named* reserved slots (bundle
/// key 10, receipt key 3) are split out from the anonymous remainder — so
/// this also asserts the ranges abut, which is what makes "the band" a
/// well-defined single interval on the code side.
fn registry_reserved_band(root: &Value, name: &str) -> Option<(u64, u64)> {
    let entry = map_entry(root, name);
    let mut ranges: Vec<(u64, u64)> = as_array(get(entry, "reserved", name), name)
        .iter()
        .map(|r| (get_u64(r, "first", name), get_u64(r, "last", name)))
        .collect();
    if ranges.is_empty() {
        return None;
    }
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        assert_eq!(
            pair[0].1 + 1,
            pair[1].0,
            "{name}: reserved ranges must abut so the band is one interval, got {pair:?}"
        );
    }
    Some((
        ranges.first().expect("non-empty").0,
        ranges.last().expect("non-empty").1,
    ))
}

/// The `(value, registry name)` pairs of one registry enum, in table order.
fn registry_enum_values<'a>(root: &'a Value, name: &str) -> Vec<(u64, &'a str)> {
    let entry = enum_entry(root, name);
    as_array(get(entry, "values", name), name)
        .iter()
        .map(|v| (get_u64(v, "value", name), get_str(v, "name", name)))
        .collect()
}

/// Every map key constant in `manifest::registry` and `bundle::registry`
/// equals its registry row, in both directions: same key set, no registry map
/// without a code counterpart and no code map without a row.
#[test]
fn code_map_keys_match_the_registry() {
    let root = registry();

    let mut covered: BTreeSet<String> = BTreeSet::new();
    for map in MapId::ALL {
        let name = map.registry_name();
        assert_eq!(
            map.assigned_keys(),
            registry_keys(&root, name).as_slice(),
            "maps.{name}: code key set differs from the registry"
        );
        covered.insert(name.to_owned());
    }
    for map in BundleMapId::ALL {
        let name = map.registry_name();
        assert_eq!(
            map.assigned_keys(),
            registry_keys(&root, name).as_slice(),
            "maps.{name}: code key set differs from the registry"
        );
        covered.insert(name.to_owned());
    }

    // The other direction: no registry map lacks a code counterpart.
    let registered: BTreeSet<String> = as_array(get(&root, "maps", "registry root"), "maps")
        .iter()
        .map(|m| get_str(m, "name", "maps").to_owned())
        .collect();
    assert_eq!(
        registered, covered,
        "every registry map needs a MapId/BundleMapId variant and vice versa"
    );
}

/// Reserved bands match, including the "abut and fill" shape registry §7.15
/// prescribes for the nine bundle maps and the envelope's deliberate
/// no-reserved-space exception (registry §1 rule 6).
#[test]
fn code_reserved_bands_match_the_registry() {
    let root = registry();
    let band_max = get_u64(get(&root, "profile", "root"), "v1_key_band_max", "profile");
    assert_eq!(
        band_max,
        manifest_registry::V1_KEY_BAND_MAX,
        "profile.v1_key_band_max must equal the code constant"
    );

    for map in MapId::ALL {
        let name = map.registry_name();
        assert_eq!(
            map.reserved_band(),
            registry_reserved_band(&root, name),
            "maps.{name}: reserved band differs from the registry"
        );
    }
    for map in BundleMapId::ALL {
        let name = map.registry_name();
        assert_eq!(
            Some(map.reserved_band()),
            registry_reserved_band(&root, name),
            "maps.{name}: reserved band differs from the registry"
        );
        // §7.15: no bundle map is shape-frozen — all nine reserve, and every
        // band runs to the band max.
        assert_eq!(
            map.reserved_band().1,
            band_max,
            "maps.{name}: band must fill"
        );
    }

    // The two *named* reserved slots sit at the numbers the registry names.
    for (map_name, slot_name, code_value) in [
        (
            "bundle",
            "range_reveals",
            bundle_key::bundle::RESERVED_RANGE_REVEALS,
        ),
        (
            "receipt_record",
            "chain_inputs",
            bundle_key::receipt::RESERVED_CHAIN_INPUTS,
        ),
    ] {
        let entry = map_entry(&root, map_name);
        let named: BTreeMap<&str, u64> = as_array(get(entry, "reserved", map_name), map_name)
            .iter()
            .filter_map(|r| Some((r.get("name")?.as_str()?, get_u64(r, "first", map_name))))
            .collect();
        assert_eq!(
            named.get(slot_name).copied(),
            Some(code_value),
            "maps.{map_name}: named reserved slot `{slot_name}` moved"
        );
    }
}

/// Every closed wire enum's values **and their registry spellings** match,
/// and every value in an enum's reserved band is rejected by the code.
#[test]
fn code_enums_match_the_registry() {
    let root = registry();

    assert_eq!(
        registry_enum_values(&root, DescriptorKind::REGISTRY_NAME),
        DescriptorKind::ALL
            .iter()
            .map(|k| (k.to_wire(), k.registry_value_name()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        registry_enum_values(&root, FineTreeDomain::REGISTRY_NAME),
        FineTreeDomain::ALL
            .iter()
            .map(|d| (d.to_wire(), d.registry_value_name()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        registry_enum_values(&root, UnitKind::REGISTRY_NAME),
        UnitKind::ALL
            .iter()
            .map(|k| (k.to_wire(), k.registry_value_name()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        registry_enum_values(&root, AnchorStatus::REGISTRY_NAME),
        AnchorStatus::ALL
            .iter()
            .map(|s| (s.to_wire(), s.registry_value_name()))
            .collect::<Vec<_>>()
    );

    // `sig_alg` has no closed Rust enum of its own (it reuses C's `SigAlg`),
    // so the mapping functions are what must agree with the table.
    let sig_alg = registry_enum_values(&root, "sig_alg");
    for (value, name) in &sig_alg {
        let alg = manifest_registry::sig_alg_from_wire(*value)
            .unwrap_or_else(|| panic!("sig_alg {value} ({name}) is registered but not in code"));
        assert_eq!(manifest_registry::sig_alg_to_wire(alg), *value);
    }
    for alg in SigAlg::ALL {
        let value = manifest_registry::sig_alg_to_wire(alg);
        assert!(
            sig_alg.iter().any(|(v, _)| *v == value),
            "code assigns sig_alg {value} to {alg} but the registry does not list it"
        );
    }

    // An unregistered value is a hard parse reject, never a silently ignored
    // one — so every reserved value must fail to parse in code.
    /// An enum's registry name paired with the code-side "does v1 accept
    /// this wire value?" predicate.
    type Acceptor = (&'static str, fn(u64) -> bool);

    let accepts: [Acceptor; 2] = [
        (AnchorStatus::REGISTRY_NAME, |v| {
            AnchorStatus::from_wire(v).is_some()
        }),
        ("sig_alg", |v| {
            manifest_registry::sig_alg_from_wire(v).is_some()
        }),
    ];
    for (name, accepted) in accepts {
        let entry = enum_entry(&root, name);
        for range in as_array(get(entry, "reserved", name), name) {
            let first = get_u64(range, "first", name);
            let last = get_u64(range, "last", name);
            for value in first..=last {
                assert!(
                    !accepted(value),
                    "enums.{name}: value {value} is reserved but code accepts it"
                );
            }
        }
    }
}

/// Every fixed scalar length in the registry has a code constant with the
/// same value, in both directions.
#[test]
fn code_scalar_lengths_match_the_registry() {
    let root = registry();
    let lengths: BTreeMap<&str, u64> = as_array(get(&root, "scalars", "registry root"), "scalars")
        .iter()
        .map(|s| {
            (
                get_str(s, "name", "scalars"),
                get_u64(s, "length", "scalars"),
            )
        })
        .collect();

    let code: BTreeMap<&str, u64> = [
        ("seal_id", manifest_registry::SEAL_ID_LEN),
        ("salt16", bundle_registry::SALT_LEN),
        ("nonce24", manifest_registry::NONCE_LEN),
        ("commit32", manifest_registry::COMMITMENT_LEN),
        ("seed32", bundle_registry::SEED_LEN),
        ("hash32", bundle_registry::NODE_HASH_LEN),
        ("key32", bundle_registry::KEY_LEN),
        ("address32", manifest_registry::ADDRESS_LEN),
        ("btc_header", bundle_registry::BLOCK_HEADER_LEN),
        ("ed25519_pubkey", manifest_registry::ED25519_PUBKEY_LEN),
        ("ed25519_sig", manifest_registry::ED25519_SIG_LEN),
        ("mldsa65_pubkey", manifest_registry::MLDSA65_PUBKEY_LEN),
        ("mldsa65_sig", manifest_registry::MLDSA65_SIG_LEN),
    ]
    .into_iter()
    .collect();

    assert_eq!(
        lengths, code,
        "scalars[] and the code length constants must agree 1:1"
    );
    // `hash32` covers boundary node hashes *and* EVM tx hashes; the code
    // keeps two named constants, so pin the second one against the same row.
    assert_eq!(bundle_registry::TX_HASH_LEN, lengths["hash32"]);
    assert_eq!(
        bundle_registry::STORAGE_NONCE_LEN,
        lengths["nonce24"],
        "the storage record's nonce is a plain nonce24"
    );
    assert_eq!(bundle_registry::STORAGE_ADDRESS_LEN, lengths["address32"]);
    // The ciphertext shape gate of registry §2 is derived, not a scalar row.
    assert_eq!(
        bundle_registry::MIN_CIPHERTEXT_LEN,
        bundle_registry::PADDING_BLOCK + bundle_registry::AEAD_TAG_LEN
    );
}

/// Positional tuple arities match: a `cover_entry`/`path_node` element count
/// is a shape rule the code enforces and the registry records.
#[test]
fn code_tuple_arities_match_the_registry() {
    use antseal_core::bundle::TupleId;

    let root = registry();
    let arities: BTreeMap<&str, u64> = as_array(get(&root, "tuples", "registry root"), "tuples")
        .iter()
        .map(|t| {
            let name = get_str(t, "name", "tuples");
            let count = as_array(get(t, "elements", name), name).len() as u64;
            (name, count)
        })
        .collect();

    assert_eq!(arities["cover_entry"], TupleId::CoverEntry.arity());
    assert_eq!(arities["path_node"], TupleId::PathNode.arity());
    // `byte_range` is the manifest half's tuple; F5 checks arity 2 inline.
    assert_eq!(arities["byte_range"], 2);
}

/// **Registry §7.6.1 — checked absences, on the table side.** Four fields are
/// absent from the bundle by design, and an absence nobody tests is an
/// absence that grows back. This fails the moment someone adds a *row* for
/// one of them, which is earlier than any code-side test could notice.
#[test]
fn no_bundle_map_grows_a_deliberately_absent_field() {
    let root = registry();

    // Banned in **every** bundle map.
    let banned_everywhere: &[(&str, &str)] = &[
        (
            "signature",
            "the bundle is unsigned: its authority is the embedded signed manifest",
        ),
        (
            "signatures",
            "there is no §7.1-style envelope at bundle level",
        ),
        (
            "sig_alg",
            "no signature container means no algorithm map either",
        ),
        ("work_id", "derived: SHA-256(manifest body bytes)"),
        ("anchor_digest", "derived: SHA-256(bundle key 1 bytes)"),
        (
            "seal_id",
            "a manifest body field; a stored copy could disagree with it",
        ),
        (
            "is_full_reveal",
            "D28 rider 1: reveal shape is derived, never declared",
        ),
        ("reveal_mode", "D28 rider 1"),
        ("reveal_shape", "D28 rider 1"),
    ];

    // Banned in the two **reveal** maps specifically. The storage record's
    // own `nonce` is the *manifest copy's* nonce and is legitimate; the ban
    // is on a per-unit reveal nonce (spec line 114: the manifest is the
    // single source of truth).
    let banned_in_reveals: &[(&str, &str)] = &[(
        "nonce",
        "nonces come from the manifest — the single source of truth (line 114)",
    )];

    // Banned on the TSA artifact specifically (D8 §1): the informational
    // `source` string left v1. It was bound by nothing — the bundle is
    // unsigned, so any relay can rewrite it — and consumed by nothing: the
    // report pipeline refuses in writing to copy bundle-recorded anchor
    // metadata, and a verdict's source identity comes from the verified
    // certificate chain. Key 4 is now plain reserved.
    let banned_on_tsa: &[(&str, &str)] = &[(
        "source",
        "D8 §1 removed the TSA source string from v1: unbindable (unsigned bundle), \
         unconsumed (verify::pipeline refuses it), and rendered beside a verdict",
    )];

    // Banned on the receipt (D8 §3b): a sealer-written chain identifier would
    // steer the verifier's RPC choice. The chain is pinned by the verifier.
    let banned_on_receipt: &[(&str, &str)] = &[
        (
            "chain_id",
            "the chain is pinned by the verifier (line 137), never named by the artifact",
        ),
        (
            "chain",
            "the chain is pinned by the verifier (line 137), never named by the artifact",
        ),
        (
            "network",
            "the chain is pinned by the verifier (line 137), never named by the artifact",
        ),
    ];

    let mut violations = Vec::new();
    for map in BundleMapId::ALL {
        let name = map.registry_name();
        let entry = map_entry(&root, name);
        let in_reveal = matches!(
            map,
            BundleMapId::CoveredReveal | BundleMapId::NonCoveredReveal
        );
        for field in as_array(get(entry, "fields", name), name) {
            let field_name = get_str(field, "name", name);
            let mut rules = banned_everywhere.to_vec();
            if in_reveal {
                rules.extend_from_slice(banned_in_reveals);
            }
            if map == BundleMapId::TsaAnchor {
                rules.extend_from_slice(banned_on_tsa);
            }
            if map == BundleMapId::ReceiptRecord {
                rules.extend_from_slice(banned_on_receipt);
            }
            if let Some((_, why)) = rules.iter().find(|(b, _)| *b == field_name) {
                violations.push(format!("maps.{name}.{field_name}: {why}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "registry §7.6.1 absences violated:\n  {}",
        violations.join("\n  ")
    );

    // The reveal sections' key spaces are fully accounted for, so there is
    // no unclaimed assigned slot a nonce could occupy without moving a key.
    assert_eq!(BundleMapId::CoveredReveal.assigned_keys(), [0, 1, 2, 3, 4]);
    assert_eq!(BundleMapId::NonCoveredReveal.assigned_keys(), [0, 1, 2, 3]);
}

/// **Registry §7.1 + §9 "Version dispatch order" (F10).** The registry's
/// `version_dispatch` block records four facts a permanent format rests on;
/// each is compared against the code that implements it.
///
/// The load-bearing one is the envelope freeze: the manifest body's
/// discriminant sits *inside* the body bstr, so the `{body, signatures}`
/// envelope must be parsed before the version is readable at all. It is
/// therefore the one map that can never carry a version-specific change —
/// which is exactly why it has no reserved band.
#[test]
fn code_version_dispatch_matches_the_registry() {
    let root = registry();
    let vd = get(&root, "version_dispatch", "registry root");

    // 1. The supported-version list is the same on both sides.
    let listed: Vec<u64> = as_array(
        get(vd, "supported_versions", "version_dispatch"),
        "versions",
    )
    .iter()
    .map(|v| {
        v.as_u64()
            .unwrap_or_else(|| panic!("supported_versions must be uints, got {v}"))
    })
    .collect();
    assert_eq!(
        listed,
        antseal_core::format::SUPPORTED_VERSIONS.to_vec(),
        "registry `version_dispatch.supported_versions` ≠ `format::SUPPORTED_VERSIONS`"
    );

    // 2. Both discriminants sit at key 0 of their own top-level map, and the
    //    registry's key number matches the code constant.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for d in as_array(
        get(vd, "discriminants", "version_dispatch"),
        "discriminants",
    ) {
        let artifact = get_str(d, "artifact", "discriminant");
        let key = get(d, "key", "discriminant")
            .as_u64()
            .expect("discriminant key must be a uint");
        assert_eq!(
            key,
            antseal_core::format::VERSION_KEY,
            "{artifact}: the discriminant must be key 0 — canonical maps ascend, \
             so only key 0 is readable as a constant-cost peek"
        );
        let code_key = match artifact {
            "bundle" => bundle_key::bundle::FORMAT_VERSION,
            "manifest_body" => antseal_core::manifest::registry::key::body::FORMAT_VERSION,
            other => panic!("unregistered discriminant artifact `{other}`"),
        };
        assert_eq!(key, code_key, "{artifact}: registry key ≠ code constant");
        // The stable code the registry names is the one the error emits.
        let registry_code = get_str(d, "unsupported_code", "discriminant");
        let emitted = match artifact {
            "bundle" => antseal_core::bundle::BundleError::UnsupportedFormatVersion {
                found: 2,
                supported: antseal_core::format::SUPPORTED_VERSIONS,
            }
            .code(),
            _ => antseal_core::manifest::ManifestError::UnsupportedFormatVersion {
                found: 2,
                supported: antseal_core::format::SUPPORTED_VERSIONS,
            }
            .code(),
        };
        assert_eq!(
            registry_code, emitted,
            "{artifact}: registry code ≠ emitted"
        );
        assert!(seen.insert(artifact), "duplicate discriminant `{artifact}`");
    }
    assert_eq!(
        seen,
        BTreeSet::from(["bundle", "manifest_body"]),
        "exactly two versioned top-level maps exist in v1"
    );

    // 3. The two codes are distinct — a v1 bundle carrying a v2 manifest must
    //    not render like a v2 bundle (D78: separate families, permanently).
    assert_ne!(
        antseal_core::bundle::BundleError::UnsupportedFormatVersion {
            found: 2,
            supported: antseal_core::format::SUPPORTED_VERSIONS,
        }
        .code(),
        antseal_core::manifest::ManifestError::UnsupportedFormatVersion {
            found: 2,
            supported: antseal_core::format::SUPPORTED_VERSIONS,
        }
        .code(),
    );

    // 4. The envelope freeze, on both sides. The registry states it in prose;
    //    the code states it as "no reserved band" — the observable form.
    assert!(
        get_str(vd, "envelope_frozen_across_versions", "version_dispatch").contains("body bstr"),
        "the registry must record WHY the envelope is frozen, not just that it is"
    );
    assert_eq!(
        MapId::Envelope.reserved_band(),
        None,
        "the envelope must reserve nothing: it is parsed before the version is \
         known, so no future field can ever be added to it"
    );
    assert_eq!(
        registry_reserved_band(&root, MapId::Envelope.registry_name()),
        None,
        "registry: the envelope must declare no reserved range"
    );
    // …and it carries no discriminant of its own, which would be redundant
    // with body key 0 and could disagree with it. Checked on the *table*
    // side, which fails the moment someone adds the row.
    let envelope = map_entry(&root, MapId::Envelope.registry_name());
    for field in as_array(get(envelope, "fields", "envelope"), "envelope") {
        assert_ne!(
            get_str(field, "name", "envelope field"),
            "format_version",
            "the envelope must not carry its own discriminant: it is parsed \
             BEFORE any version is known, and a second copy could disagree \
             with the body's"
        );
    }
}

// ===========================================================================
// The 1:1 cap ⟷ registry cross-check (F11; decision D10, registry §11)
// ===========================================================================

/// One `caps.entries[]` row.
struct CapRow<'a> {
    value: u64,
    code: &'a str,
}

/// The registry's cap table, keyed by constant name.
fn registry_caps(root: &Value) -> BTreeMap<&str, CapRow<'_>> {
    let caps = get(root, "caps", "registry root");
    as_array(get(caps, "entries", "caps"), "caps.entries")
        .iter()
        .map(|e| {
            let name = get_str(e, "name", "caps entry");
            (
                name,
                CapRow {
                    value: get_u64(e, "value", "caps entry"),
                    code: get_str(e, "code", "caps entry"),
                },
            )
        })
        .collect()
}

/// **F11 accept: "code == registry table".**
///
/// Every one of D10's nineteen frozen constants equals its registry row, and
/// the code each cap raises equals the row's `code`. The check runs in both
/// directions: no constant may be missing from the table, and no table row may
/// name a constant the code does not define.
///
/// The caps are format-permanent (they freeze at Q14 with the rest of v1: a
/// receiver that rejects a bundle a sealer produced is a compatibility break,
/// MVP-SPEC.md line 123), so a silent drift between the two would be
/// unrecoverable rather than merely untidy.
#[test]
fn code_caps_match_the_registry() {
    use antseal_core::bundle::error::{BundleListKind, OpaqueField};
    use antseal_core::codec::caps;
    use antseal_core::manifest::error::ManifestListKind;

    let root = registry();
    let table = registry_caps(&root);

    // (constant name, code value, the code that firing it raises)
    let mut from_code: Vec<(&str, u64, &'static str)> = vec![
        (
            "MAX_BUNDLE_BYTES",
            caps::MAX_BUNDLE_BYTES,
            antseal_core::bundle::BundleError::InputTooLarge {
                len: caps::MAX_BUNDLE_BYTES + 1,
                cap: caps::MAX_BUNDLE_BYTES,
            }
            .code(),
        ),
        (
            "MAX_MANIFEST_BYTES",
            caps::MAX_MANIFEST_BYTES,
            antseal_core::manifest::ManifestError::InputTooLarge {
                len: caps::MAX_MANIFEST_BYTES + 1,
                cap: caps::MAX_MANIFEST_BYTES,
            }
            .code(),
        ),
        (
            "MAX_CBOR_DEPTH",
            u64::from(caps::MAX_CBOR_DEPTH),
            antseal_core::codec::DecodeError::NestingTooDeep { position: 0 }.code(),
        ),
    ];

    // The two capped manifest lists.
    for list in ManifestListKind::ALL {
        let name = match list {
            ManifestListKind::Files => "MAX_FILE_COUNT",
            ManifestListKind::Units => "MAX_UNIT_COUNT",
        };
        from_code.push((
            name,
            list.cap(),
            antseal_core::manifest::ManifestError::ListTooLong {
                list,
                claimed: list.cap() + 1,
                cap: list.cap(),
            }
            .code(),
        ));
    }

    // The ten capped bundle lists.
    for list in BundleListKind::ALL {
        let name = match list {
            BundleListKind::OtsAnchors => "MAX_OTS_ANCHOR_COUNT",
            BundleListKind::TsaAnchors => "MAX_TSA_ANCHOR_COUNT",
            BundleListKind::Intermediates => "MAX_INTERMEDIATE_COUNT",
            BundleListKind::TxHashes => "MAX_TX_HASH_COUNT",
            BundleListKind::CoveredReveals => "MAX_COVERED_REVEAL_COUNT",
            BundleListKind::NonCoveredReveals => "MAX_NONCOVERED_REVEAL_COUNT",
            BundleListKind::Cover => "MAX_COVER_ENTRIES",
            BundleListKind::Paths => "MAX_PATH_NODES",
            BundleListKind::TouchedFiles => "MAX_TOUCHED_FILE_COUNT",
            BundleListKind::FullReveals => "MAX_FULL_REVEAL_COUNT",
        };
        from_code.push((
            name,
            list.cap(),
            antseal_core::bundle::BundleError::ListTooLong {
                list,
                claimed: list.cap() + 1,
                cap: list.cap(),
            }
            .code(),
        ));
    }

    // The four capped opaque artifacts.
    for field in OpaqueField::ALL {
        let name = match field {
            OpaqueField::Ots => "MAX_OTS_BYTES",
            OpaqueField::TsaToken => "MAX_TSA_TOKEN_BYTES",
            OpaqueField::Certificate => "MAX_CERT_BYTES",
            OpaqueField::ReceiptPayload => "MAX_RECEIPT_PAYLOAD_BYTES",
        };
        from_code.push((
            name,
            field.cap(),
            antseal_core::bundle::BundleError::ArtifactTooLarge {
                field,
                len: field.cap() + 1,
                cap: field.cap(),
            }
            .code(),
        ));
    }

    assert_eq!(
        from_code.len(),
        19,
        "D10 froze nineteen caps — a new one needs a registry row too"
    );

    for (name, value, code) in &from_code {
        let row = table
            .get(name)
            .unwrap_or_else(|| panic!("registry section 11 has no row for `{name}`"));
        assert_eq!(
            row.value, *value,
            "caps.{name}: value differs from the code"
        );
        assert_eq!(
            row.code, *code,
            "caps.{name}: error code differs from the code"
        );
    }

    // …and no registry row without a constant behind it.
    let from_code_names: BTreeSet<&str> = from_code.iter().map(|(n, _, _)| *n).collect();
    let from_registry: BTreeSet<&str> = table.keys().copied().collect();
    assert_eq!(
        from_registry, from_code_names,
        "registry section 11 and `codec::caps` disagree about which constants exist"
    );
}

/// The clamp rule is normative, so the registry must *state* it — otherwise a
/// third-party implementer reading only the table would cap counts and still
/// let a length header drive an unbounded allocation (D10 §4).
#[test]
fn registry_records_the_clamp_rule_and_the_depth_cap() {
    let root = registry();
    let caps = get(&root, "caps", "registry root");
    let clamp = get_str(caps, "clamp_rule", "caps");
    assert!(
        clamp.contains("min(claimed_length, remaining_input)"),
        "the clamp rule must state the formula verbatim: {clamp}"
    );
    assert!(
        clamp.contains("head canonicality"),
        "the clamp rule must state the frozen order at an array head: {clamp}"
    );

    // The depth cap appears in two places (§7.6.3's decode_layers and §11);
    // they must agree, and both must clear the v1 structural maximum of 6.
    let depth = get(
        get(&root, "decode_layers", "registry root"),
        "max_container_depth",
        "decode_layers",
    );
    let cap = get_u64(depth, "cap", "max_container_depth");
    assert_eq!(cap, u64::from(antseal_core::codec::caps::MAX_CBOR_DEPTH));
    assert!(cap >= get_u64(depth, "manifest_chain", "max_container_depth"));
    assert!(cap >= get_u64(depth, "bundle_chain", "max_container_depth"));
}

// ===========================================================================
// D86 — `ManifestError::map()` against the registry
// ===========================================================================

/// `(field name, key)` → the manifest map that declares it, read straight
/// from `maps[].fields`.
///
/// Keyed by the **pair**, not the name alone: `kind` is declared twice among
/// the manifest maps — `canon_descriptor` key 0 (`descriptor_kind`) and
/// `unit_entry` key 1 (`unit_kind`). The pair is unique across all five, and
/// this asserts that rather than assuming it, so a lookup below can never be
/// satisfied by two different maps.
fn manifest_field_owners(root: &Value) -> BTreeMap<(String, u64), MapId> {
    let mut owners: BTreeMap<(String, u64), MapId> = BTreeMap::new();
    for map in MapId::ALL {
        let name = map.registry_name();
        for field in as_array(get(map_entry(root, name), "fields", name), name) {
            let field_key = (
                get_str(field, "name", name).to_owned(),
                get_u64(field, "key", name),
            );
            assert!(
                owners.insert(field_key.clone(), map).is_none(),
                "maps.{name}: field {field_key:?} is declared by two manifest maps, so the \
                 (name, key) lookup would be ambiguous"
            );
        }
    }
    owners
}

/// The registry field a [`FixedLenField`] length check is about, as
/// `(name, key)` — **never** as a map: which map declares a field is the
/// registry's answer, and deriving it there rather than restating it is the
/// whole point of this section (D86 §4.3).
fn fixed_len_registry_field(field: FixedLenField) -> (&'static str, u64) {
    use manifest_registry::key;
    match field {
        FixedLenField::SealId => ("seal_id", key::body::SEAL_ID),
        FixedLenField::PathCommit => ("path_commit", key::file::PATH_COMMIT),
        FixedLenField::RawCommit => ("raw_commit", key::file::RAW_COMMIT),
        FixedLenField::CanonCommit => ("canon_commit", key::file::CANON_COMMIT),
        FixedLenField::FineRoot => ("fine_root", key::file::FINE_ROOT),
        FixedLenField::UnitCommit => ("unit_commit", key::unit::UNIT_COMMIT),
        FixedLenField::Nonce => ("nonce", key::unit::NONCE),
        FixedLenField::Address => ("address", key::unit::ADDRESS),
        // The two halves of one algorithm's material sit in different maps at
        // different layers: `pubkeys` is body key 5, `signatures` envelope
        // key 1.
        FixedLenField::Pubkey(_) => ("pubkeys", key::body::PUBKEYS),
        FixedLenField::Signature(_) => ("signatures", key::envelope::SIGNATURES),
    }
}

/// The registry field a conditional-presence rule governs. Both directions
/// (`UnexpectedField` / `MissingField`) name the same field.
fn cond_registry_field(field: CondField) -> (&'static str, u64) {
    use manifest_registry::key;
    match field {
        CondField::CanonCommit => ("canon_commit", key::file::CANON_COMMIT),
        CondField::FineRoot => ("fine_root", key::file::FINE_ROOT),
        CondField::FineTreeDomain => ("fine_tree_domain", key::descriptor::FINE_TREE_DOMAIN),
        CondField::UnicodeVersion => ("unicode_version", key::descriptor::UNICODE_VERSION),
        CondField::UnitCommit => ("unit_commit", key::unit::UNIT_COMMIT),
    }
}

/// The registry field a non-empty-container rule governs. `NormalUnits` is
/// `units`' own D77 rule (`maps.file_entry.fields[6].rule`) rather than a
/// field of its own — the registry records it exactly that way.
fn container_registry_field(field: ContainerField) -> (&'static str, u64) {
    use manifest_registry::key;
    match field {
        ContainerField::Files => ("files", key::body::FILES),
        ContainerField::Units | ContainerField::NormalUnits => ("units", key::file::UNITS),
        ContainerField::Pubkeys => ("pubkeys", key::body::PUBKEYS),
        ContainerField::Signatures => ("signatures", key::envelope::SIGNATURES),
    }
}

/// The registry field a capped list is.
fn list_registry_field(list: ManifestListKind) -> (&'static str, u64) {
    use manifest_registry::key;
    match list {
        ManifestListKind::Files => ("files", key::body::FILES),
        ManifestListKind::Units => ("units", key::file::UNITS),
    }
}

/// The registry field a closed enum is read from. `fine_tree_present` is a
/// **descriptor** field (key 1), never a file-entry one — a row D86 §4.3
/// bolds precisely because a hand-copy gets it wrong.
fn enum_registry_field(enumeration: EnumId) -> (&'static str, u64) {
    use manifest_registry::key;
    match enumeration {
        EnumId::DescriptorKind => ("kind", key::descriptor::KIND),
        EnumId::FineTreeDomain => ("fine_tree_domain", key::descriptor::FINE_TREE_DOMAIN),
        EnumId::FineTreeFlag => ("fine_tree_present", key::descriptor::FINE_TREE_PRESENT),
        EnumId::UnitKind => ("kind", key::unit::KIND),
    }
}

/// The registry field a `sig_alg` id appeared in.
fn alg_position_registry_field(position: AlgPosition) -> (&'static str, u64) {
    use manifest_registry::key;
    match position {
        AlgPosition::SigPolicy => ("sig_policy", key::body::SIG_POLICY),
        AlgPosition::Pubkeys => ("pubkeys", key::body::PUBKEYS),
        AlgPosition::Signatures => ("signatures", key::envelope::SIGNATURES),
    }
}

/// **D86 §4.3 — every field-bearing `ManifestError` discriminant's `map()`
/// equals the registry map that declares the field it rejects.**
///
/// The rows state only *which registry field* a rejection is about, as a
/// `(name, key)` pair; the owning map is looked up in `maps[].fields`. A
/// hand-copied mapping table therefore cannot be enshrined here — "signatures
/// lives in the body" is not expressible, because `("signatures", 1)`
/// resolves to `manifest_envelope` and nowhere else. That is what the five
/// non-obvious rows need: the two `signatures` ones, `pubkeys`,
/// `fine_tree_present`, and (in the companion test) `InputTooLarge`.
///
/// The per-family matches are exhaustive and wildcard-free, so a new
/// discriminant fails compilation here as well as in `map()` itself.
#[test]
fn code_error_maps_match_the_registry() {
    use antseal_core::manifest::ManifestError as E;

    let root = registry();
    let owners = manifest_field_owners(&root);

    // (error, registry field name, registry key). One entry per field-bearing
    // discriminant; the layer-wide arms are the companion test's.
    let mut rows: Vec<(E, &'static str, u64)> = Vec::new();

    for field in FixedLenField::ALL {
        let (name, key) = fixed_len_registry_field(field);
        rows.push((
            E::WrongLength {
                field,
                expected: 32,
                got: 7,
            },
            name,
            key,
        ));
    }
    for field in CondField::ALL {
        let (name, key) = cond_registry_field(field);
        rows.push((E::UnexpectedField { field }, name, key));
        rows.push((E::MissingField { field }, name, key));
    }
    for field in ContainerField::ALL {
        let (name, key) = container_registry_field(field);
        rows.push((E::EmptyContainer { field }, name, key));
    }
    for list in ManifestListKind::ALL {
        let (name, key) = list_registry_field(list);
        rows.push((
            E::ListTooLong {
                list,
                claimed: list.cap() + 1,
                cap: list.cap(),
            },
            name,
            key,
        ));
    }
    for enumeration in EnumId::ALL {
        let (name, key) = enum_registry_field(enumeration);
        rows.push((
            E::UnknownEnumValue {
                enumeration,
                value: 99,
            },
            name,
            key,
        ));
    }
    for position in AlgPosition::ALL {
        let (name, key) = alg_position_registry_field(position);
        rows.push((
            E::DuplicateAlg {
                position,
                alg_id: 0,
            },
            name,
            key,
        ));
        rows.push((
            E::UnregisteredAlg {
                position,
                alg_id: 9,
            },
            name,
            key,
        ));
    }
    {
        use manifest_registry::key;
        rows.extend([
            (E::WrongRangeArity { got: 3 }, "range", key::unit::RANGE),
            (
                E::DescriptorDomainMismatch {
                    kind: DescriptorKind::Binary,
                    implied: FineTreeDomain::Raw,
                    found: FineTreeDomain::Canonical,
                },
                "fine_tree_domain",
                key::descriptor::FINE_TREE_DOMAIN,
            ),
            (
                E::UnsupportedFormatVersion {
                    found: 2,
                    supported: antseal_core::format::SUPPORTED_VERSIONS,
                },
                "format_version",
                key::body::FORMAT_VERSION,
            ),
            (E::SigPolicyEmpty, "sig_policy", key::body::SIG_POLICY),
            (
                E::UnitIdMismatch {
                    expected: 1,
                    found: 2,
                },
                "unit_id",
                key::unit::UNIT_ID,
            ),
            // F40 / D23 clause 3: like D77's `NormalUnits`, a rule of the
            // `units` array as a whole (`maps.file_entry` key 6), not of any
            // one unit entry.
            (
                E::MultipleRawMirrors { count: 2 },
                "units",
                key::file::UNITS,
            ),
        ]);
    }

    for (err, name, key) in &rows {
        let want = owners
            .get(&((*name).to_owned(), *key))
            .unwrap_or_else(|| panic!("no manifest map declares a field ({name}, {key})"));
        assert_eq!(
            err.map(),
            *want,
            "{}: rejects registry field ({name}, {key}), which `maps.{}` declares",
            err.code(),
            want.registry_name()
        );
        // The layer is the map's own projection, never a second table.
        assert_eq!(err.layer(), want.layer(), "{}", err.code());
    }

    // The three key-space classes carry their map, so identity is the claim.
    for map in MapId::ALL {
        for err in [
            E::UnknownKey { map, key: 24 },
            E::ReservedKey { map, key: 8 },
            E::MissingKey { map, key: 0 },
        ] {
            assert_eq!(err.map(), map);
            assert_eq!(err.layer(), map.layer());
        }
    }
}

/// The three arms with no registry *field* behind them are pinned by the
/// registry blocks that do govern them: §7.6.3's `decode_layers` for the two
/// codec wrappers, and §11's cap table for the layer-2 input cap.
#[test]
fn code_error_maps_match_the_registry_for_the_layer_wide_arms() {
    use antseal_core::codec::DecodeError;
    use antseal_core::manifest::{Layer, ManifestError as E};

    let root = registry();

    // `decode_layers[].error_class` names the wrapper variant per layer.
    let layers = as_array(
        get(
            get(&root, "decode_layers", "registry root"),
            "layers",
            "decode_layers",
        ),
        "decode_layers.layers",
    );
    let class_of = |n: u64| -> &str {
        layers
            .iter()
            .find(|l| get_u64(l, "layer", "decode_layers.layers") == n)
            .map(|l| get_str(l, "error_class", "decode_layers.layers"))
            .unwrap_or_else(|| panic!("registry has no decode layer {n}"))
    };
    assert_eq!(class_of(2), "ManifestError::Envelope");
    assert_eq!(class_of(3), "ManifestError::Body");

    let inner = DecodeError::NonShortestInt { position: 7 };
    let envelope = E::Envelope {
        source: inner.clone(),
    };
    let body = E::Body { source: inner };
    assert_eq!(envelope.map(), MapId::Envelope);
    assert_eq!(envelope.layer(), Layer::Envelope);
    assert_eq!(body.map(), MapId::Body);
    assert_eq!(body.layer(), Layer::Body);

    // `MAX_MANIFEST_BYTES` bounds the **layer-2 input** (§11, D10 §1), which
    // is why an over-cap manifest is attributed to the envelope even though
    // no envelope field is at fault.
    let applies_to = as_array(
        get(get(&root, "caps", "registry root"), "entries", "caps"),
        "caps.entries",
    )
    .iter()
    .find(|e| get_str(e, "name", "caps entry") == "MAX_MANIFEST_BYTES")
    .map(|e| get_str(e, "applies_to", "caps entry"))
    .expect("registry section 11 lists MAX_MANIFEST_BYTES");
    assert!(
        applies_to.contains("layer-2"),
        "the manifest cap must apply to the layer-2 input, got {applies_to:?}"
    );

    let too_large = E::InputTooLarge {
        len: antseal_core::codec::caps::MAX_MANIFEST_BYTES + 1,
        cap: antseal_core::codec::caps::MAX_MANIFEST_BYTES,
    };
    assert_eq!(too_large.map(), MapId::Envelope);
    assert_eq!(too_large.layer(), Layer::Envelope);
}

// ===========================================================================
// C5 / C6 / C10 — the three code ⟷ mirror gaps D8 §14 named
// ===========================================================================

/// **C5 — `sig_alg`, BOTH code copies, each against the mirror directly.**
///
/// There are two mappings at HEAD: C's (`crypto::sig_policy`) and F's
/// (`manifest::registry`, the one the codec actually uses). D8 §7 ruled the
/// duplication *stays* — this table is the single normative source of the
/// numbers, and how many `match` arms the crate has is a code-organisation
/// matter the registry does not own. What had to close is the pin: before
/// the freeze only F's copy was driven against the mirror, and C's was tied
/// to it indirectly by a sibling test bounded at id 20. Two hops, one of
/// them bounded, for a format-permanent numbering. Now both copies are
/// asserted against the JSON directly, over the full registered set and the
/// full reserved band.
#[test]
fn code_sig_alg_mappings_match_the_registry_on_both_copies() {
    use antseal_core::crypto::sig_policy;

    let root = registry();
    let table = registry_enum_values(&root, "sig_alg");
    assert!(!table.is_empty(), "the sig_alg enum must not be empty");

    for (value, name) in &table {
        // F's copy — the one the manifest decoder and encoder call.
        let via_f = manifest_registry::sig_alg_from_wire(*value)
            .unwrap_or_else(|| panic!("sig_alg {value} ({name}) is registered but F rejects it"));
        assert_eq!(manifest_registry::sig_alg_to_wire(via_f), *value);
        // C's copy — pinned to the same row, not to F's answer.
        let via_c = sig_policy::sig_alg_from_id(*value)
            .unwrap_or_else(|| panic!("sig_alg {value} ({name}) is registered but C rejects it"));
        assert_eq!(sig_policy::sig_alg_to_id(via_c), *value);
        assert_eq!(
            via_f, via_c,
            "sig_alg {value} ({name}) decodes to two different algorithms"
        );
    }

    // Both directions: no code-assigned id missing from the table.
    for alg in SigAlg::ALL {
        for (which, id) in [
            (
                "manifest::registry",
                manifest_registry::sig_alg_to_wire(alg),
            ),
            ("crypto::sig_policy", sig_policy::sig_alg_to_id(alg)),
        ] {
            assert!(
                table.iter().any(|(v, _)| *v == id),
                "{which} assigns sig_alg {id} to {alg} but the registry does not list it"
            );
        }
    }

    // The whole reserved band rejects in both copies. An unregistered value
    // is a hard parse reject, never a silently ignored one — and the band is
    // read from the mirror, so it cannot be bounded at a hand-typed number.
    let entry = enum_entry(&root, "sig_alg");
    let mut band_values = 0usize;
    for range in as_array(get(entry, "reserved", "sig_alg"), "sig_alg") {
        let first = get_u64(range, "first", "sig_alg");
        let last = get_u64(range, "last", "sig_alg");
        for value in first..=last {
            band_values += 1;
            assert!(
                manifest_registry::sig_alg_from_wire(value).is_none(),
                "sig_alg {value} is reserved but manifest::registry accepts it"
            );
            assert!(
                sig_policy::sig_alg_from_id(value).is_none(),
                "sig_alg {value} is reserved but crypto::sig_policy accepts it"
            );
        }
    }
    assert!(band_values > 0, "the reserved band must not be empty");

    // The 16-value universe is load-bearing for D10 as well as for §6.2:
    // §11's recorded non-cap on sig_policy/pubkeys/signatures is justified
    // BY it, so widening the band would require minting three caps.
    let universe = table.len() + band_values;
    assert_eq!(
        universe, 16,
        "the sig_alg universe is frozen at 16 values — D10's recorded non-cap \
         on sig_policy/pubkeys/signatures depends on it (registry §6.2, §11)"
    );
    assert_eq!(
        sig_policy::FIRST_RESERVED_ID,
        table.len() as u64,
        "the first reserved id must abut the registered set"
    );
}

/// **C6 — field NAMES, not just numbers (task F33).**
///
/// C2 compares key *numbers* only, so a field could be renamed in the
/// registry with no test failure — and the registry document is the
/// normative text a third-party verifier implements from. Worse, registry
/// §7.6.1's checked absences are a **name**-based ban list
/// (`no_bundle_map_grows_a_deliberately_absent_field`), so a rename is
/// exactly the mutation that evades them: call a resurrected TSA `source`
/// field `provenance` and every numeric check still passes.
///
/// Both directions, per map, as ordered `(key, name)` pairs.
#[test]
fn code_field_names_match_the_registry() {
    let root = registry();

    let mut checked = 0usize;
    let mut check = |name: &str, pairs: Vec<(u64, &'static str)>| {
        let entry = map_entry(&root, name);
        let from_registry: Vec<(u64, String)> = as_array(get(entry, "fields", name), name)
            .iter()
            .map(|f| (get_u64(f, "key", name), get_str(f, "name", name).to_owned()))
            .collect();
        let from_code: Vec<(u64, String)> =
            pairs.into_iter().map(|(k, n)| (k, n.to_owned())).collect();
        assert_eq!(
            from_code, from_registry,
            "maps.{name}: the code's (key, name) pairs differ from the registry's"
        );
        checked += from_registry.len();
    };

    for map in MapId::ALL {
        let keys = map.assigned_keys();
        let names = map.field_names();
        assert_eq!(
            keys.len(),
            names.len(),
            "maps.{}: assigned_keys() and field_names() must stay parallel",
            map.registry_name()
        );
        check(
            map.registry_name(),
            keys.iter().copied().zip(names.iter().copied()).collect(),
        );
    }
    for map in BundleMapId::ALL {
        let keys = map.assigned_keys();
        let names = map.field_names();
        assert_eq!(
            keys.len(),
            names.len(),
            "maps.{}: assigned_keys() and field_names() must stay parallel",
            map.registry_name()
        );
        check(
            map.registry_name(),
            keys.iter().copied().zip(names.iter().copied()).collect(),
        );
    }
    // 28 manifest-side (2 + 8 + 7 + 4 + 7) + 40 bundle-side
    // (10 + 3 + 5 + 4 + 3 + 5 + 4 + 3 + 3). The `tsa_anchor` term is 4, not
    // 5: D8 §1 removed key 4's `source` from v1.
    assert_eq!(
        checked, 68,
        "the fourteen v1 maps assign 68 keys between them; a different count \
         means a field was added or removed, which is a format-version event"
    );

    // The per-key accessor agrees with the parallel lists, and answers `None`
    // outside the assigned set — including on `tsa_anchor` key 4, which D8 §1
    // removed from v1.
    for map in BundleMapId::ALL {
        for (key, name) in map.assigned_keys().iter().zip(map.field_names()) {
            assert_eq!(map.field_name(*key), Some(*name));
        }
        let (first, last) = map.reserved_band();
        for key in first..=last {
            assert_eq!(
                map.field_name(key),
                None,
                "maps.{}: reserved key {key} must have no field name",
                map.registry_name()
            );
        }
    }
    assert_eq!(
        BundleMapId::TsaAnchor.field_name(4),
        None,
        "tsa_anchor key 4 left v1 with D8 §1 — it is reserved, not a named field"
    );
}

/// **C10 — the report's `AnchorState` against the wire's `AnchorStatus`.**
///
/// Two independent seven-variant enums with byte-identical kebab-case
/// spellings, and nothing bound them. The independence is deliberate — the
/// report is a *separate, non-wire* format (D27/D29) and a verifier derives
/// its own state rather than copying the sealer's — but report v1 freezes at
/// Q14 alongside the wire (D84 §7), so an unpinned pair would let one
/// taxonomy ship under two names.
#[test]
fn report_anchor_state_matches_the_wire_anchor_status() {
    use antseal_core::verify::report::AnchorState;

    let root = registry();
    let wire: Vec<&str> = registry_enum_values(&root, AnchorStatus::REGISTRY_NAME)
        .into_iter()
        .map(|(_, name)| name)
        .collect();
    let report: Vec<&str> = AnchorState::ALL.iter().map(|s| s.wire_name()).collect();
    assert_eq!(
        report, wire,
        "the report's AnchorState spellings, in order, must equal the wire \
         enum's registry_value_name list"
    );

    // …and the wire enum's own code copy still matches the mirror in order,
    // so the chain report -> mirror -> wire code closes.
    let from_code: Vec<&str> = AnchorStatus::ALL
        .iter()
        .map(|s| s.registry_value_name())
        .collect();
    assert_eq!(from_code, wire);
    assert_eq!(wire.len(), 7, "the spec's taxonomy has seven states");
}

// ===========================================================================
// D — document ⟷ mirror (registry §14's "mirrors this document 1:1")
// ===========================================================================
//
// Nothing in the tree parsed `registry-v1.md` before the freeze, which is
// why §14's claim was unbacked and why the mirror had drifted from its own
// source (D8 §17 items 6, 7, 9). These assertions read the document and
// compare its **mechanical tables** — the ones that are data rather than
// prose — to the mirror. Four of them — `type`, `presence`, the
// `may be empty` rule and the tier tags (D111 R2–R5) — pin per-field columns
// that reached no assertion before, and the comment block introducing them
// records why the two surfaces' **prose**, by contrast, is compared to
// nothing in either direction and must stay that way.

/// The normative document, read once per assertion.
fn document() -> String {
    std::fs::read_to_string(DOC_PATH).unwrap_or_else(|e| panic!("cannot read {DOC_PATH}: {e}"))
}

/// The cells of one Markdown table row, trimmed. `None` for a non-row line.
fn table_row(line: &str) -> Option<Vec<&str>> {
    let trimmed = line.trim();
    if !trimmed.starts_with('|') || !trimmed.ends_with('|') {
        return None;
    }
    Some(
        trimmed
            .trim_start_matches('|')
            .trim_end_matches('|')
            .split('|')
            .map(str::trim)
            .collect(),
    )
}

/// Strip the backticks a registry table puts around every identifier.
fn unticked(cell: &str) -> &str {
    cell.trim_matches('`')
}

/// The rows of the first table under `heading_prefix` whose header line is
/// `header`, as cell vectors.
fn table_under<'a>(doc: &'a str, heading_prefix: &str, header: &str) -> Vec<Vec<&'a str>> {
    let mut lines = doc.lines().skip_while(|l| !l.starts_with(heading_prefix));
    assert!(
        lines.next().is_some(),
        "the document has no heading starting `{heading_prefix}`"
    );
    let mut rows = Vec::new();
    let mut in_table = false;
    for line in lines {
        if line.starts_with("## ") || line.starts_with("### ") {
            break;
        }
        if !in_table {
            if line.trim() == header {
                in_table = true;
            }
            continue;
        }
        match table_row(line) {
            // The `| --- | … |` separator.
            Some(cells) if cells.iter().all(|c| c.chars().all(|ch| ch == '-')) => {}
            Some(cells) => rows.push(cells),
            None => break,
        }
    }
    assert!(
        !rows.is_empty(),
        "no `{header}` table found under `{heading_prefix}`"
    );
    rows
}

/// Parse a band cell like `8–23` (en dash) or `4-23` into its bounds.
fn band_bounds(cell: &str) -> Option<(u64, u64)> {
    let (first, last) = cell
        .split_once('\u{2013}')
        .or_else(|| cell.split_once('-'))?;
    Some((first.trim().parse().ok()?, last.trim().parse().ok()?))
}

/// **D — §7's map tables: keys, NAMES, named reserved slots and bands.**
///
/// The section number each map lives in is read from the mirror's own
/// `doc_section` pointer, so the mirror says where its source is rather than
/// the test hard-coding a fifteenth copy of the mapping.
#[test]
fn the_document_map_tables_match_the_mirror() {
    const HEADER: &str = "| key | field | type | presence | len/shape |";
    let doc = document();
    let root = registry();

    let mut sections_checked = 0usize;
    for entry in as_array(get(&root, "maps", "registry root"), "maps") {
        let name = get_str(entry, "name", "maps");
        let section = get_str(entry, "doc_section", name);
        let rows = table_under(&doc, &format!("### {section} "), HEADER);

        let mut doc_fields: Vec<(u64, String)> = Vec::new();
        let mut doc_named: Vec<(u64, String)> = Vec::new();
        let mut doc_bands: Vec<(u64, u64)> = Vec::new();
        for cells in &rows {
            assert_eq!(
                cells.len(),
                5,
                "maps.{name}: §{section}'s rows have five columns after the \
                 freeze — the status column was deleted (D8 §15)"
            );
            let (key_cell, name_cell, presence) = (cells[0], cells[1], cells[3]);
            if let Ok(key) = key_cell.parse::<u64>() {
                if presence.contains("reserved") {
                    doc_named.push((key, unticked(name_cell).to_owned()));
                } else {
                    doc_fields.push((key, unticked(name_cell).to_owned()));
                }
            } else if let Some(bounds) = band_bounds(key_cell) {
                doc_bands.push(bounds);
            } else {
                panic!("maps.{name}: §{section} row has an unparseable key cell `{key_cell}`");
            }
        }

        let mirror_fields: Vec<(u64, String)> = as_array(get(entry, "fields", name), name)
            .iter()
            .map(|f| (get_u64(f, "key", name), get_str(f, "name", name).to_owned()))
            .collect();
        assert_eq!(
            doc_fields, mirror_fields,
            "maps.{name}: §{section}'s (key, field) rows differ from the mirror"
        );

        let mut mirror_named: Vec<(u64, String)> = Vec::new();
        let mut mirror_bands: Vec<(u64, u64)> = Vec::new();
        for range in as_array(get(entry, "reserved", name), name) {
            let first = get_u64(range, "first", name);
            let last = get_u64(range, "last", name);
            match range.get("name").and_then(Value::as_str) {
                Some(slot) => {
                    assert_eq!(
                        first, last,
                        "maps.{name}: a named reserved slot is one key, not a range"
                    );
                    mirror_named.push((first, slot.to_owned()));
                }
                None => mirror_bands.push((first, last)),
            }
        }
        assert_eq!(
            doc_named, mirror_named,
            "maps.{name}: §{section}'s named reserved slots differ from the mirror"
        );
        assert_eq!(
            doc_bands, mirror_bands,
            "maps.{name}: §{section}'s reserved band row differs from the mirror"
        );
        sections_checked += 1;
    }
    assert_eq!(
        sections_checked, 14,
        "all fourteen registered maps must have a §7.x table"
    );
}

/// One documented §7.x field beside the mirror object that claims to mirror
/// it, as produced by [`map_rows_against_the_mirror`].
///
/// `section` rides along so a failure can cite the frozen registry **by
/// section** — `registry §7.6 key 3` — which is this project's citation
/// discipline for the two frozen wire documents: a line number into a frozen
/// file rots at the next edit, and `scripts/check-traceability.py` rejects
/// one.
struct MapRow<'a> {
    map: &'a str,
    section: &'a str,
    key: u64,
    cells: Vec<&'a str>,
    field: &'a Value,
}

/// Every (map, key) pair of §7.x, as the document's row beside the mirror's
/// field.
///
/// Panics naming the pair if a documented key has no mirror field or the
/// reverse. A silent skip is the one failure mode the assertions below cannot
/// tolerate, because each of them certifies a **count**: a parse that quietly
/// found nothing would pass every comparison it made and certify nothing.
///
/// Reserved *band* rows (keyed by a range) and *named* reserved slots (keyed
/// by a number, but flagged in the presence cell) are not fields and are
/// stepped over; both are already pinned in both directions by
/// [`the_document_map_tables_match_the_mirror`]. The section each map lives
/// in is read from the mirror's own `doc_section` pointer, exactly as that
/// test does, so no fifteenth copy of the map⟷section mapping is introduced.
fn map_rows_against_the_mirror<'a>(doc: &'a str, root: &'a Value) -> Vec<MapRow<'a>> {
    const HEADER: &str = "| key | field | type | presence | len/shape |";

    let mut rows = Vec::new();
    for entry in as_array(get(root, "maps", "registry root"), "maps") {
        let map = get_str(entry, "name", "maps");
        let section = get_str(entry, "doc_section", map);

        let mut documented: BTreeMap<u64, Vec<&str>> = BTreeMap::new();
        for cells in table_under(doc, &format!("### {section} "), HEADER) {
            assert_eq!(
                cells.len(),
                5,
                "maps.{map}: registry §{section}'s rows have five columns after \
                 the freeze (D8 §15)"
            );
            let Ok(key) = cells[0].parse::<u64>() else {
                continue; // a reserved band row, keyed by a range
            };
            if cells[3].contains("reserved") {
                continue; // a named reserved slot, not a field
            }
            assert!(
                documented.insert(key, cells).is_none(),
                "maps.{map}: registry §{section} documents key {key} twice"
            );
        }

        for field in as_array(get(entry, "fields", map), map) {
            let key = get_u64(field, "key", map);
            let cells = documented.remove(&key).unwrap_or_else(|| {
                panic!(
                    "maps.{map}: the mirror carries a field at registry §{section} \
                     key {key} and the document has no row for it"
                )
            });
            rows.push(MapRow {
                map,
                section,
                key,
                cells,
                field,
            });
        }

        assert!(
            documented.is_empty(),
            "maps.{map}: registry §{section} documents keys {:?} that the mirror \
             carries no field for",
            documented.keys().collect::<Vec<_>>()
        );
    }
    rows
}

/// The normalisation of a `presence` cell, shared by the presence and
/// `may be empty` assertions so that the two cannot drift apart: emphasis and
/// backticks removed, trimmed, lowercased.
///
/// Stripping `*` covers `**` in the same pass. The function is **total** —
/// every cell yields a string — and it is the *caller* that decides an
/// unrecognised result is a failure rather than a skip.
fn normalised_presence(cell: &str) -> String {
    cell.replace(['*', '`'], "").trim().to_lowercase()
}

/// The tier letters tagged in a `len/shape` cell: the set of `[P]`, `[X]` and
/// `[R]` tokens it contains, which is exactly what `\[([PXR])\]` collects.
///
/// Hand-rolled because this crate carries no regex dependency and the pattern
/// is three literal three-byte tokens. **Bracketed and case-sensitive**: a
/// bare `P` and a lowercase `[p]` are prose, not tier tags, so rewriting the
/// words around a tag can neither manufacture one nor destroy one.
fn tier_tags(cell: &str) -> BTreeSet<&'static str> {
    [("[P]", "P"), ("[X]", "X"), ("[R]", "R")]
        .into_iter()
        .filter(|(token, _)| cell.contains(token))
        .map(|(_, letter)| letter)
        .collect()
}

// ---------------------------------------------------------------------------
// D — why the two surfaces' PROSE is compared to nothing, and what is
//     compared instead (D111; Q131's Accept clause 2)
// ---------------------------------------------------------------------------
//
// `registry-v1.md`'s `len/shape` cell (`cells[4]`) and `registry-v1.json`'s
// `notes` field state overlapping facts in independent words, and **nothing
// in this project compares them, in either direction, by design**.
//
// `622f5fe` §1 ruled the naive form out and the ruling stands:
//
//     "§2 groups fields by byte length and names them in prose while
//      `scalars[]` names them by role with synthetic keys (`salt16`,
//      `commit32`, `hash32`), so the two are not row-comparable and a
//      substring match on the prose would pin editorial wording rather
//      than format facts."
//
// D111 measured whether a CLOSED VOCABULARY escapes that ruling. It does
// not — it renames it. Over the 68 (map, key) pairs, symmetric and
// emphasis-stripped:
//
//   * `UNANCHORED` occurs in BOTH surfaces' prose at registry §7.6 key 3
//     and nowhere else in either, so a term-presence rule is satisfied at
//     all 68 keys by construction — INCLUDING at the one key whose two
//     copies actually diverge. The check is green on its own motivating
//     case.
//   * the tier letters `[P]`/`[X]`/`[R]` are md-only at 25 of the (key,
//     letter) pairs, because the mirror does not put tiers in prose: it
//     has a `tier` field. A symmetric check reddens 25 times for zero
//     defects.
//   * `may be empty` appears in the mirror's `rule` field at 8 keys and in
//     the `.md`'s PRESENCE cell at the same 8 — but in `cells[4]` at only
//     2, so hunting the phrase in the prose cell misses three quarters of
//     the sites where both surfaces actually state it.
//   * `reserved` splits 1/1 on editorial cross-references, while the
//     reserved FACT is already pinned both ways by
//     `the_document_map_tables_match_the_mirror`.
//
// Root cause: the two cells are not the same field. The `.md` cell merges
// byte length, shape pointer, tier tags, conditions and gloss; the mirror
// splits those across `length`, `type`, `rule`, `tier` and `notes`. 66 of
// 68 pairs differ literally, and at 5 scalar keys the `.md` cell is a bare
// `32`/`16` against an EMPTY `notes`. Not comparable.
//
// WHAT COVERS THE GAP INSTEAD — this is the operative half of the refusal:
//
//   1. The four assertions below pin the mirror's `type`, `presence`,
//      `rule` and `tier` against the document's own columns. D108 §3.1 C1
//      names all four as format surface, and before D111 NOTHING in
//      `crates/` read `tier` or `rule` at all.
//   2. `format_freeze.rs`'s `every_erratum_quotes_its_frozen_sentence_verbatim`
//      (D108 R4) pins the full text of any prose sentence known to be
//      over-read — BOTH copies of registry §7.6 key 3's sentence are
//      entries there today, byte-for-byte, one per surface.
//   3. `FROZEN.sha256` covers every remaining prose byte. D108 §3.2: the
//      prose is the ONLY content the digest alone covers, which is an
//      argument for the digest and not against it.
//
// Do not add a prose comparison here. If a future divergence matters, it
// is an erratum entry (2) or a registry-version event, never a substring
// match.

/// **D — §7's `type` column against the mirror's `type` field.**
///
/// Closed at five spellings — `bstr`, `uint`, `tstr`, `array`, `map` — the
/// CBOR major types a decoder branches on. The registry is **frozen**, so the
/// set of types across all 68 keys is format-permanent and a sixth spelling
/// is a format-version event this must catch.
///
/// Compared **case-sensitively and byte-for-byte, with no emphasis
/// stripping**: the type column is data and carries no emphasis today, so a
/// `**bstr**` appearing in either surface is itself the drift.
#[test]
fn the_document_type_column_matches_the_mirror() {
    let doc = document();
    let root = registry();

    let mut pairs_compared = 0usize;
    let mut observed: BTreeMap<&str, usize> = BTreeMap::new();
    for row in map_rows_against_the_mirror(&doc, &root) {
        let documented = unticked(row.cells[2]).trim();
        let mirrored = get_str(row.field, "type", row.map);
        assert_eq!(
            documented, mirrored,
            "maps.{}: registry §{} key {}'s type column says `{documented}` and \
             the mirror says `{mirrored}`",
            row.map, row.section, row.key
        );
        *observed.entry(mirrored).or_default() += 1;
        pairs_compared += 1;
    }

    // Anti-vacuity. A parse that silently found nothing would make every
    // comparison above succeed by never running.
    assert_eq!(
        pairs_compared, 68,
        "the fourteen §7.x tables carry 68 documented fields between them; a run \
         that compares fewer has stopped parsing, not started passing"
    );
    assert_eq!(
        observed,
        BTreeMap::from([
            ("array", 14),
            ("bstr", 25),
            ("map", 5),
            ("tstr", 4),
            ("uint", 20),
        ]),
        "the frozen registry's type vocabulary is closed at these five spellings \
         with these multiplicities"
    );
}

/// **D — §7's `presence` column against the mirror's `presence` field.**
///
/// Closed at two values: `required` — a decoder rejects a manifest or bundle
/// missing it, 58 keys — and `optional`, where absence is legal, 10 keys. The
/// mirror takes no third value across all 68 keys and the registry is frozen.
///
/// The `.md` writes far more than the bare word (`**opt — biconditional,
/// [R]: …**`), so the document side is normalised by [`normalised_presence`]
/// and matched on its leading `req`/`opt`. The normalisation is **total or
/// the test fails**: a cell that reduces to neither is a hard panic naming
/// the pair and the raw cell, never a silent skip. The mirror side is
/// compared case-sensitively against the two literals.
#[test]
fn the_document_presence_column_matches_the_mirror() {
    let doc = document();
    let root = registry();

    let mut required_seen = 0usize;
    let mut optional_seen = 0usize;
    for row in map_rows_against_the_mirror(&doc, &root) {
        let normalised = normalised_presence(row.cells[3]);
        let documented = if normalised.starts_with("req") {
            required_seen += 1;
            "required"
        } else if normalised.starts_with("opt") {
            optional_seen += 1;
            "optional"
        } else {
            panic!(
                "maps.{}: registry §{} key {}'s presence cell `{}` normalises to \
                 `{normalised}`, which begins with neither `req` nor `opt` — this \
                 normalisation is total or this test fails, and it never skips",
                row.map, row.section, row.key, row.cells[3]
            )
        };
        let mirrored = get_str(row.field, "presence", row.map);
        assert_eq!(
            documented, mirrored,
            "maps.{}: registry §{} key {} is `{documented}` in the document and \
             `{mirrored}` in the mirror",
            row.map, row.section, row.key
        );
    }

    // Anti-vacuity, as two independent floors rather than one total: a
    // normalisation bug that collapsed every cell into a single branch would
    // still satisfy a sum of 68.
    assert_eq!(
        required_seen, 58,
        "the frozen registry requires 58 of its 68 documented fields"
    );
    assert_eq!(
        optional_seen, 10,
        "the frozen registry makes 10 of its 68 documented fields optional"
    );
    assert_eq!(
        required_seen + optional_seen,
        68,
        "every documented field lands in exactly one of the two branches"
    );
}

/// **D — the `may be empty` rule, as a set, in both directions.**
///
/// Load-bearing because it is the difference between *"a bundle with no
/// anchors is UNANCHORED"* and *"a bundle with no anchors is a parse error"*:
/// registry §7.6 keys 3/4 and 6–9 turn on it. It is the one term of Q131's
/// proposed six that survives measurement, and the vocabulary closes at one
/// because it is the only `rule` value that recurs as a bare closed phrase —
/// every other is a per-key condition or a prose rationale.
///
/// Asserted as **set equality**, so a drop on either surface reddens and the
/// failure names both one-sided differences.
#[test]
fn the_document_may_be_empty_rule_matches_the_mirror() {
    const RULE: &str = "may be empty";
    let doc = document();
    let root = registry();

    let mut from_document: BTreeSet<String> = BTreeSet::new();
    let mut from_mirror: BTreeSet<String> = BTreeSet::new();
    for row in map_rows_against_the_mirror(&doc, &root) {
        let pair = format!(
            "maps.{} key {} (registry §{})",
            row.map, row.key, row.section
        );
        if normalised_presence(row.cells[3]).contains(RULE) {
            from_document.insert(pair.clone());
        }
        if row
            .field
            .get("rule")
            .and_then(Value::as_str)
            .is_some_and(|rule| rule.trim().to_lowercase() == RULE)
        {
            from_mirror.insert(pair);
        }
    }

    let document_only: Vec<&String> = from_document.difference(&from_mirror).collect();
    let mirror_only: Vec<&String> = from_mirror.difference(&from_document).collect();
    assert!(
        document_only.is_empty() && mirror_only.is_empty(),
        "the `{RULE}` rule must be stated on both surfaces or on neither — \
         document-only: {document_only:?}; mirror-only: {mirror_only:?}"
    );

    // Anti-vacuity: two empty sets are equal, and would certify nothing.
    assert_eq!(
        from_document.len(),
        8,
        "the frozen registry states `{RULE}` at eight keys"
    );
}

/// **D — §7's inline tier tags against the mirror's `tier` field.**
///
/// Closed at three letters, matched **only inside square brackets**: `[P]`
/// decidable from the one entry being decoded, `[X]` decidable from the whole
/// container, `[R]` post-decode (D78). `validation_tiers.tiers[]` declares
/// exactly these three and is frozen.
///
/// **Recorded narrowing** (D8 §14's E-family discipline): the relation is
/// **containment, not equality**, and deliberately one-directional. The `.md`
/// tags *per clause* and only where a tier is load-bearing or surprising,
/// while the mirror's `tier` is one value *per field*, so equality is false
/// at 27 of 68 for three benign reasons — 21 keys the document simply leaves
/// untagged, cells that carry three tags for three conditions, and one mirror
/// field that puts its tier letter in its `rule` string. What is true, and
/// what this asserts, is that where the document tags any tier and the mirror
/// declares one, the mirror's is among the document's.
///
/// This reads the `len/shape` cell, and it is the only assertion that does —
/// but it reads **only** the three bracket tokens, never the surrounding
/// words. Rewrite every word of that cell and this does not move.
#[test]
fn the_document_tier_tags_are_consistent_with_the_mirror() {
    let doc = document();
    let root = registry();

    let mut both_present = 0usize;
    let mut skipped = 0usize;
    for row in map_rows_against_the_mirror(&doc, &root) {
        let tagged = tier_tags(row.cells[4]);
        match (
            tagged.is_empty(),
            row.field.get("tier").and_then(Value::as_str),
        ) {
            (false, Some(mirrored)) => {
                both_present += 1;
                assert!(
                    tagged.contains(mirrored),
                    "maps.{}: registry §{} key {} tags {:?} in its len/shape cell \
                     and the mirror declares tier `{mirrored}`, which is not among \
                     them",
                    row.map,
                    row.section,
                    row.key,
                    tagged
                );
            }
            // Either surface staying silent is legal; §7.3 key 6 is the one
            // pair where the document tags and the mirror does not.
            _ => skipped += 1,
        }
    }

    // Anti-vacuity, and this assertion needs it most because it is the only
    // guarded one: a regex that stops matching, a mirror that nulls its
    // tiers, or a document whose tags are reformatted all leave every
    // surviving comparison passing while the guard quietly swallows the pair.
    assert_eq!(
        both_present, 19,
        "19 of the 68 keys are tagged in the document AND typed in the mirror; a \
         shift means one side stopped being read, not that the two agree"
    );
    assert_eq!(
        both_present + skipped,
        68,
        "every documented field is either compared or counted as skipped"
    );
}

/// **D — §6's enum tables against `enums[]`.**
///
/// §6.1 and §6.2 are one row per value; §6.3 packs three small enums into
/// one table as `0 = \x60name\x60, 1 = \x60name\x60` cells. Both shapes are read.
#[test]
fn the_document_enum_tables_match_the_mirror() {
    let doc = document();
    let root = registry();

    // §6.1 `anchor_status` — `| value | state | headline-eligible |`.
    let rows = table_under(&doc, "### 6.1 ", "| value | state | headline-eligible |");
    let from_doc: Vec<(u64, String)> = rows
        .iter()
        .map(|c| {
            (
                c[0].parse().expect("§6.1 value cell is a uint"),
                unticked(c[1]).to_owned(),
            )
        })
        .collect();
    let from_mirror: Vec<(u64, String)> = registry_enum_values(&root, "anchor_status")
        .into_iter()
        .map(|(v, n)| (v, n.to_owned()))
        .collect();
    assert_eq!(
        from_doc, from_mirror,
        "§6.1 differs from enums.anchor_status"
    );

    // §6.2 `sig_alg` — `| value | algorithm | pubkey | signature | notes |`,
    // with the reserved band as its own row.
    let rows = table_under(
        &doc,
        "### 6.2 ",
        "| value | algorithm | pubkey | signature | notes |",
    );
    let mut from_doc: Vec<(u64, String)> = Vec::new();
    let mut doc_band: Option<(u64, u64)> = None;
    for cells in &rows {
        if let Ok(value) = cells[0].parse::<u64>() {
            from_doc.push((value, unticked(cells[1]).to_owned()));
        } else {
            doc_band = band_bounds(cells[0]);
        }
    }
    let from_mirror: Vec<(u64, String)> = registry_enum_values(&root, "sig_alg")
        .into_iter()
        .map(|(v, n)| (v, n.to_owned()))
        .collect();
    assert_eq!(from_doc, from_mirror, "§6.2 differs from enums.sig_alg");
    let mirror_band = as_array(
        get(enum_entry(&root, "sig_alg"), "reserved", "sig_alg"),
        "r",
    )
    .iter()
    .map(|r| {
        (
            get_u64(r, "first", "sig_alg"),
            get_u64(r, "last", "sig_alg"),
        )
    })
    .next();
    assert_eq!(
        doc_band, mirror_band,
        "§6.2's reserved row differs from the mirror's band"
    );

    // §6.3 — three enums, one row each, values inline.
    let rows = table_under(&doc, "### 6.3 ", "| enum | values |");
    let mut seen = BTreeSet::new();
    for cells in &rows {
        let enum_name = unticked(cells[0].split_whitespace().next().expect("enum name"));
        let from_doc: Vec<(u64, String)> = cells[1]
            .split(", ")
            .filter_map(|pair| {
                let (value, name) = pair.split_once(" = ")?;
                // Trailing prose after the last value is separated by a
                // space, so take only the backticked identifier.
                let name = name.split(' ').next()?;
                Some((value.trim().parse().ok()?, unticked(name).to_owned()))
            })
            .collect();
        let from_mirror: Vec<(u64, String)> = registry_enum_values(&root, enum_name)
            .into_iter()
            .map(|(v, n)| (v, n.to_owned()))
            .collect();
        assert_eq!(
            from_doc, from_mirror,
            "§6.3's `{enum_name}` row differs from the mirror"
        );
        seen.insert(enum_name.to_owned());
    }
    assert_eq!(
        seen,
        BTreeSet::from([
            "descriptor_kind".to_owned(),
            "fine_tree_domain".to_owned(),
            "unit_kind".to_owned(),
        ]),
        "§6.3 must carry exactly the three small closed enums"
    );

    // Both directions: no mirror enum without a document table.
    let mirrored: BTreeSet<String> = as_array(get(&root, "enums", "registry root"), "enums")
        .iter()
        .map(|e| get_str(e, "name", "enums").to_owned())
        .collect();
    let documented: BTreeSet<String> = seen
        .into_iter()
        .chain(["anchor_status".to_owned(), "sig_alg".to_owned()])
        .collect();
    assert_eq!(mirrored, documented);
}

/// **D — §2's fixed-length table against `scalars[]`, by length.**
///
/// **Recorded narrowing** (D8 §14's E-family discipline, applied to an
/// assertion rather than to an omission): §2 groups fields *by byte length*
/// and names them in prose, while `scalars[]` names them *by role* with
/// synthetic keys (`salt16`, `commit32`, `hash32`). The two are not
/// row-comparable, and a substring match on the prose would pin editorial
/// wording rather than format facts — it fails on "every GGM cover seed" vs
/// `seed32`'s "GGM cover seeds" while catching nothing real. What *is* a
/// format fact, and what this asserts, is the **set of lengths**: both
/// directions, so deleting a length row from either side goes red.
#[test]
fn the_document_scalar_table_matches_the_mirror() {
    let doc = document();
    let root = registry();

    let rows = table_under(&doc, "## 2. ", "| bytes | fields | source |");
    let from_doc: BTreeSet<u64> = rows
        .iter()
        .map(|c| c[0].parse().expect("§2 byte cell is a uint"))
        .collect();
    let from_mirror: BTreeSet<u64> = as_array(get(&root, "scalars", "registry root"), "scalars")
        .iter()
        .map(|s| get_u64(s, "length", "scalars"))
        .collect();
    assert_eq!(
        from_doc, from_mirror,
        "§2's byte lengths and scalars[].length must be the same set"
    );
    assert_eq!(rows.len(), from_doc.len(), "§2 lists each length once");
}

/// **D — §11's cap table against `caps.entries[]`, by name, value and code.**
#[test]
fn the_document_cap_table_matches_the_mirror() {
    let doc = document();
    let root = registry();

    let rows = table_under(
        &doc,
        "## 11. ",
        "| constant | value | applies to | error code |",
    );
    let from_doc: BTreeMap<String, (u64, String)> = rows
        .iter()
        .map(|c| {
            (
                unticked(c[0]).to_owned(),
                (
                    c[1].parse().expect("§11 value cell is a uint"),
                    unticked(c[3]).to_owned(),
                ),
            )
        })
        .collect();
    let from_mirror: BTreeMap<String, (u64, String)> = registry_caps(&root)
        .into_iter()
        .map(|(name, row)| (name.to_owned(), (row.value, row.code.to_owned())))
        .collect();
    assert_eq!(
        from_doc, from_mirror,
        "§11's cap table and caps.entries[] must agree on name, value and code"
    );
    assert_eq!(from_doc.len(), 19, "D10 froze nineteen caps");
}
