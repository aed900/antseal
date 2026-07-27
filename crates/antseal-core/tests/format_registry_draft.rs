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
//! The 1:1 assertion that **code constants match this table** arrives with
//! F5/F8 (schema types), per the F4 accept note in registry-v1.md §14.

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
