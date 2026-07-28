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
    // item statuses live under these five sections (`caps` joined at F11).
    for section in ["scalars", "enums", "tuples", "maps", "caps"] {
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
