//! F4 draft gate: internal consistency of the machine-readable wire-format
//! registry mirror (`docs/format/registry-v1.json`; normative text in
//! `docs/format/registry-v1.md`).
//!
//! Scope at DRAFT stage — the registry freezes only at the Q14
//! `format-v1-freeze` gate:
//!
//! - the JSON parses;
//! - every map key, enum value, tuple index, and reserved-range bound is an
//!   unsigned integer (F4 accept: "no negative or non-integer map keys
//!   anywhere in the registry");
//! - no duplicate key numbers within any single map (nor duplicate values
//!   within any single enum; tuple element indexes are contiguous);
//! - reserved ranges are well-formed, mutually disjoint, and collide with
//!   no assigned key in the same map/enum;
//! - assigned map keys and reserved ranges respect the v1 single-byte key
//!   band (`0..=23`, registry §1 rule 4);
//! - every draft item carries a registered status marker
//!   (`proposed` / `pending-D9` / `pending-D17`).
//!
//! # The 1:1 code ⟷ registry cross-check (F5/F8, registry §§7.15, 14)
//!
//! The second half of this file is the assertion both
//! `manifest::registry` and `bundle::registry` claim in their module docs:
//! **every constant in those modules equals its registry row**. Map keys,
//! reserved bands, closed-enum values and their registry spellings, fixed
//! scalar lengths, tuple arities, and the v1 key-band bound are each read
//! from the JSON mirror and compared against the code. Changing a number on
//! either side without changing the other fails here — which is the point:
//! after Q14 either change is a format-version event (MVP-SPEC.md line 123).
//!
//! It also pins registry §7.6.1's **checked absences** on the table side: no
//! bundle map may grow a nonce, a signature container, a stored
//! `work_id`/`anchor_digest`/`seal_id`, or a reveal-shape discriminant.

use std::collections::{BTreeMap, BTreeSet};

use antseal_core::bundle::registry::{
    self as bundle_registry, AnchorStatus, BundleMapId, key as bundle_key,
};
use antseal_core::crypto::error::SigAlg;
use antseal_core::manifest::registry::{
    self as manifest_registry, DescriptorKind, FineTreeDomain, MapId, UnitKind,
};
use serde_json::Value;

const REGISTRY_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/format/registry-v1.json"
);

/// Status vocabulary the F4 task brief registers for draft items.
const ALLOWED_ITEM_STATUSES: [&str; 3] = ["proposed", "pending-D9", "pending-D17"];

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
        "draft-until-Q14",
        "F4 is a draft deliverable; the freeze happens at Q14 (flip deliberately)"
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

#[test]
fn every_draft_item_carries_a_registered_status_marker() {
    fn walk(value: &Value, path: &str, violations: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if let Some(status) = map.get("status").and_then(Value::as_str)
                    && !ALLOWED_ITEM_STATUSES.contains(&status)
                {
                    violations.push(format!("{path}: unregistered status `{status}`"));
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
    // The root-level `status` is the document lifecycle marker
    // (`draft-until-Q14`), checked separately in `registry_json_parses`;
    // item statuses live under these four sections.
    for section in ["scalars", "enums", "tuples", "maps"] {
        walk(
            get(&root, section, "registry root"),
            section,
            &mut violations,
        );
    }
    assert!(
        violations.is_empty(),
        "status markers outside the F4 vocabulary {ALLOWED_ITEM_STATUSES:?}:\n{}",
        violations.join("\n")
    );
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
