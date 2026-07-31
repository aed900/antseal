//! F5 — manifest body schema: the reject matrix (one distinct error per
//! mutation, MVP-SPEC.md line 168) and the accept matrix.
//!
//! Every reject case is built with the **independent** hand CBOR writer
//! in `manifest_wire`, not with the F2 encoder, because most of these
//! shapes are exactly the ones F2 makes unrepresentable. That is the
//! point of the F5 accept criterion "all validation runs inside the
//! strict-decode path": the wire can express them, so the decoder has to
//! refuse them.

mod manifest_wire;

use antseal_core::crypto::disclosure::UnitBinding;
use antseal_core::crypto::error::SigAlg;
use antseal_core::manifest::registry::key;
use antseal_core::manifest::{
    AlgPosition, ByteRange, CanonMode, CondField, ContainerField, ContentAddress, DescriptorKind,
    EnumId, FileEntry, FineTree, FixedLenField, ManifestBodyV1, ManifestError, MapId, Nonce24,
    UnitEntry, UnitKind, fixtures,
};
use manifest_wire as w;

/// A manifest body as raw `(map key, encoded value)` entries — the shape the
/// hand-rolled writer produces so tests can build bodies the schema types
/// could never construct.
type RawBody = Vec<(u64, Vec<u8>)>;

/// A named shipped-fixture constructor.
type FixtureBuilder = (&'static str, fn() -> ManifestBodyV1);

/// Decode a body from a list of raw map entries.
fn decode(entries: &[(u64, Vec<u8>)]) -> Result<ManifestBodyV1, ManifestError> {
    ManifestBodyV1::decode(&w::map(entries))
}

/// Decode and require a specific error.
fn reject(entries: &[(u64, Vec<u8>)], expected: &ManifestError) {
    match decode(entries) {
        Ok(_) => panic!("expected {expected:?}, but the body decoded"),
        Err(actual) => assert_eq!(&actual, expected, "wrong rejection class"),
    }
}

/// Replace the single file of the default body.
fn body_with_file(file: Vec<(u64, Vec<u8>)>) -> Vec<(u64, Vec<u8>)> {
    w::body(vec![file])
}

// ---------------------------------------------------------------------------
// the baseline decodes (so every reject case below isolates one mutation)
// ---------------------------------------------------------------------------

#[test]
fn baseline_body_decodes() {
    let body = decode(&w::default_body()).expect("baseline must decode");
    assert_eq!(body.format_version(), 1);
    assert_eq!(body.files().len(), 1);
    assert_eq!(body.units_total(), 2);
}

// ---------------------------------------------------------------------------
// sig_policy (MVP-SPEC.md line 97) — three distinct rejections
// ---------------------------------------------------------------------------

#[test]
fn reject_empty_sig_policy() {
    let mut body = w::default_body();
    w::set(&mut body, key::body::SIG_POLICY, w::array(&[]));
    reject(&body, &ManifestError::SigPolicyEmpty);
}

#[test]
fn reject_duplicated_sig_policy_entry() {
    let mut body = w::default_body();
    w::set(
        &mut body,
        key::body::SIG_POLICY,
        w::array(&[w::uint(0), w::uint(1), w::uint(0)]),
    );
    reject(
        &body,
        &ManifestError::DuplicateAlg {
            position: AlgPosition::SigPolicy,
            alg_id: 0,
        },
    );
}

#[test]
fn reject_unregistered_algorithm_id_in_sig_policy() {
    // Registry §6.2: ids 2..=15 are reserved, unregistered in v1.
    let mut body = w::default_body();
    w::set(
        &mut body,
        key::body::SIG_POLICY,
        w::array(&[w::uint(0), w::uint(2)]),
    );
    reject(
        &body,
        &ManifestError::UnregisteredAlg {
            position: AlgPosition::SigPolicy,
            alg_id: 2,
        },
    );
}

#[test]
fn reject_unregistered_algorithm_id_in_pubkeys_distinctly() {
    let mut body = w::default_body();
    let mut pubkeys = w::hybrid_pubkeys();
    pubkeys.push((7, w::bstr(&[0u8; 32])));
    w::set(&mut body, key::body::PUBKEYS, w::map(&pubkeys));
    reject(
        &body,
        &ManifestError::UnregisteredAlg {
            position: AlgPosition::Pubkeys,
            alg_id: 7,
        },
    );
}

// ---------------------------------------------------------------------------
// unit_commit iff not fine-tree-covered (line 94) — both directions
// ---------------------------------------------------------------------------

#[test]
fn reject_unit_commit_present_on_a_covered_unit() {
    // A fine-tree file's normal unit is bound solely by fine_root; a
    // second commitment over the same bytes would let a sealer open byte
    // i two ways under one anchored work_id.
    let mut unit = w::covered_unit(0, 0, 1024);
    w::set(&mut unit, key::unit::UNIT_COMMIT, w::commit(0x99));
    let file = w::file_entry(1, true, 1024, vec![unit, w::noncovered_unit(1, 1, 0, 1030)]);
    reject(
        &body_with_file(file),
        &ManifestError::UnexpectedField {
            field: CondField::UnitCommit,
        },
    );
}

#[test]
fn reject_unit_commit_absent_on_a_non_covered_unit() {
    // The raw mirror lives in the raw byte domain the canonical fine tree
    // does not cover, so dropping its unit_commit leaves it unbound.
    let mut mirror = w::noncovered_unit(1, 1, 0, 1030);
    w::remove(&mut mirror, key::unit::UNIT_COMMIT);
    let file = w::file_entry(1, true, 1024, vec![w::covered_unit(0, 0, 1024), mirror]);
    reject(
        &body_with_file(file),
        &ManifestError::MissingField {
            field: CondField::UnitCommit,
        },
    );
}

#[test]
fn reject_unit_commit_absent_on_a_no_fine_tree_unit() {
    let mut unit = w::noncovered_unit(0, 0, 0, 700);
    w::remove(&mut unit, key::unit::UNIT_COMMIT);
    let file = w::file_entry(1, false, 700, vec![unit]);
    reject(
        &body_with_file(file),
        &ManifestError::MissingField {
            field: CondField::UnitCommit,
        },
    );
}

// ---------------------------------------------------------------------------
// canon_commit iff text; fine_root iff fine tree
// ---------------------------------------------------------------------------

#[test]
fn reject_canon_commit_on_a_binary_file() {
    let mut file = w::binary_file();
    w::set(&mut file, key::file::CANON_COMMIT, w::commit(0x03));
    reject(
        &body_with_file(file),
        &ManifestError::UnexpectedField {
            field: CondField::CanonCommit,
        },
    );
}

#[test]
fn reject_canon_commit_missing_on_a_text_file() {
    let mut file = w::text_file_with_mirror();
    w::remove(&mut file, key::file::CANON_COMMIT);
    reject(
        &body_with_file(file),
        &ManifestError::MissingField {
            field: CondField::CanonCommit,
        },
    );
}

#[test]
fn reject_fine_root_on_a_no_fine_tree_file() {
    let mut file = w::no_fine_tree_file();
    w::set(&mut file, key::file::FINE_ROOT, w::commit(0x04));
    reject(
        &body_with_file(file),
        &ManifestError::UnexpectedField {
            field: CondField::FineRoot,
        },
    );
}

#[test]
fn reject_fine_root_missing_on_a_fine_tree_file() {
    let mut file = w::binary_file();
    w::remove(&mut file, key::file::FINE_ROOT);
    reject(
        &body_with_file(file),
        &ManifestError::MissingField {
            field: CondField::FineRoot,
        },
    );
}

// ---------------------------------------------------------------------------
// descriptor conditional fields and the kind <-> domain alignment
// ---------------------------------------------------------------------------

#[test]
fn reject_unicode_version_on_a_binary_file() {
    let mut descriptor = w::descriptor(0, true);
    descriptor.push((
        key::descriptor::UNICODE_VERSION,
        w::tstr(w::UNICODE_VERSION),
    ));
    let mut file = w::binary_file();
    w::set(&mut file, key::file::DESCRIPTOR, w::map(&descriptor));
    reject(
        &body_with_file(file),
        &ManifestError::UnexpectedField {
            field: CondField::UnicodeVersion,
        },
    );
}

#[test]
fn reject_unicode_version_missing_on_a_text_file() {
    let mut descriptor = w::descriptor(1, true);
    descriptor.retain(|(k, _)| *k != key::descriptor::UNICODE_VERSION);
    let mut file = w::text_file_with_mirror();
    w::set(&mut file, key::file::DESCRIPTOR, w::map(&descriptor));
    reject(
        &body_with_file(file),
        &ManifestError::MissingField {
            field: CondField::UnicodeVersion,
        },
    );
}

#[test]
fn reject_fine_tree_domain_without_a_fine_tree() {
    let mut descriptor = w::descriptor(0, false);
    descriptor.push((key::descriptor::FINE_TREE_DOMAIN, w::uint(0)));
    let mut file = w::empty_file();
    w::set(&mut file, key::file::DESCRIPTOR, w::map(&descriptor));
    reject(
        &body_with_file(file),
        &ManifestError::UnexpectedField {
            field: CondField::FineTreeDomain,
        },
    );
}

#[test]
fn reject_fine_tree_domain_missing_with_a_fine_tree() {
    let mut descriptor = w::descriptor(0, true);
    descriptor.retain(|(k, _)| *k != key::descriptor::FINE_TREE_DOMAIN);
    let mut file = w::binary_file();
    w::set(&mut file, key::file::DESCRIPTOR, w::map(&descriptor));
    reject(
        &body_with_file(file),
        &ManifestError::MissingField {
            field: CondField::FineTreeDomain,
        },
    );
}

#[test]
fn reject_descriptor_domain_contradicting_its_kind() {
    // A binary file's fine tree covers raw bytes (MVP-SPEC.md line 84);
    // claiming the canonical domain is a contradiction, not a variant.
    let mut descriptor = w::descriptor(0, true);
    w::set(
        &mut descriptor,
        key::descriptor::FINE_TREE_DOMAIN,
        w::uint(1),
    );
    let mut file = w::binary_file();
    w::set(&mut file, key::file::DESCRIPTOR, w::map(&descriptor));
    reject(
        &body_with_file(file),
        &ManifestError::DescriptorDomainMismatch {
            kind: DescriptorKind::Binary,
            implied: antseal_core::manifest::FineTreeDomain::Raw,
            found: antseal_core::manifest::FineTreeDomain::Canonical,
        },
    );
}

// ---------------------------------------------------------------------------
// exact byte lengths (registry §2) — one distinct error per field class
// ---------------------------------------------------------------------------

#[test]
fn reject_wrong_length_seal_id() {
    let mut body = w::default_body();
    w::set(&mut body, key::body::SEAL_ID, w::bstr(&[0u8; 15]));
    reject(
        &body,
        &ManifestError::WrongLength {
            field: FixedLenField::SealId,
            expected: 16,
            got: 15,
        },
    );
}

#[test]
fn reject_wrong_length_nonce() {
    let mut unit = w::covered_unit(0, 0, 1024);
    w::set(&mut unit, key::unit::NONCE, w::bstr(&[0u8; 12]));
    let file = w::file_entry(1, true, 1024, vec![unit, w::noncovered_unit(1, 1, 0, 1030)]);
    reject(
        &body_with_file(file),
        &ManifestError::WrongLength {
            field: FixedLenField::Nonce,
            expected: 24,
            got: 12,
        },
    );
}

#[test]
fn reject_wrong_length_commitments_each_distinctly() {
    // path_commit / raw_commit / canon_commit on the file entry.
    let cases: &[(u64, FixedLenField)] = &[
        (key::file::PATH_COMMIT, FixedLenField::PathCommit),
        (key::file::RAW_COMMIT, FixedLenField::RawCommit),
        (key::file::CANON_COMMIT, FixedLenField::CanonCommit),
    ];
    for (k, field) in cases {
        let mut file = w::text_file_with_mirror();
        w::set(&mut file, *k, w::bstr(&[0u8; 31]));
        reject(
            &body_with_file(file),
            &ManifestError::WrongLength {
                field: *field,
                expected: 32,
                got: 31,
            },
        );
    }

    // unit_commit on the mirror unit.
    let mut mirror = w::noncovered_unit(1, 1, 0, 1030);
    w::set(&mut mirror, key::unit::UNIT_COMMIT, w::bstr(&[0u8; 33]));
    let file = w::file_entry(1, true, 1024, vec![w::covered_unit(0, 0, 1024), mirror]);
    reject(
        &body_with_file(file),
        &ManifestError::WrongLength {
            field: FixedLenField::UnitCommit,
            expected: 32,
            got: 33,
        },
    );
}

#[test]
fn reject_wrong_length_fine_root() {
    let mut file = w::binary_file();
    w::set(&mut file, key::file::FINE_ROOT, w::bstr(&[0u8; 16]));
    reject(
        &body_with_file(file),
        &ManifestError::WrongLength {
            field: FixedLenField::FineRoot,
            expected: 32,
            got: 16,
        },
    );
}

#[test]
fn reject_wrong_length_address() {
    // Decision D11 fixes the Autonomi address at 32 B.
    let mut unit = w::covered_unit(0, 0, 4096);
    w::set(&mut unit, key::unit::ADDRESS, w::bstr(&[0u8; 20]));
    let file = w::file_entry(0, true, 4096, vec![unit]);
    reject(
        &body_with_file(file),
        &ManifestError::WrongLength {
            field: FixedLenField::Address,
            expected: 32,
            got: 20,
        },
    );
}

#[test]
fn reject_wrong_length_pubkey_per_algorithm() {
    let mut body = w::default_body();
    w::set(
        &mut body,
        key::body::PUBKEYS,
        w::map(&[(0, w::bstr(&[0u8; 31])), (1, w::bstr(&[0u8; 1952]))]),
    );
    reject(
        &body,
        &ManifestError::WrongLength {
            field: FixedLenField::Pubkey(SigAlg::Ed25519),
            expected: 32,
            got: 31,
        },
    );

    let mut body = w::default_body();
    w::set(
        &mut body,
        key::body::PUBKEYS,
        w::map(&[(0, w::bstr(&[0u8; 32])), (1, w::bstr(&[0u8; 1951]))]),
    );
    reject(
        &body,
        &ManifestError::WrongLength {
            field: FixedLenField::Pubkey(SigAlg::MlDsa65),
            expected: 1952,
            got: 1951,
        },
    );
}

// ---------------------------------------------------------------------------
// closed enums
// ---------------------------------------------------------------------------

#[test]
fn reject_unknown_unit_kind() {
    let mut unit = w::covered_unit(0, 0, 4096);
    w::set(&mut unit, key::unit::KIND, w::uint(2));
    let file = w::file_entry(0, true, 4096, vec![unit]);
    reject(
        &body_with_file(file),
        &ManifestError::UnknownEnumValue {
            enumeration: EnumId::UnitKind,
            value: 2,
        },
    );
}

#[test]
fn reject_unknown_descriptor_kind() {
    let mut descriptor = w::descriptor(0, true);
    w::set(&mut descriptor, key::descriptor::KIND, w::uint(9));
    let mut file = w::binary_file();
    w::set(&mut file, key::file::DESCRIPTOR, w::map(&descriptor));
    reject(
        &body_with_file(file),
        &ManifestError::UnknownEnumValue {
            enumeration: EnumId::DescriptorKind,
            value: 9,
        },
    );
}

#[test]
fn reject_unknown_fine_tree_domain_value() {
    let mut descriptor = w::descriptor(0, true);
    w::set(
        &mut descriptor,
        key::descriptor::FINE_TREE_DOMAIN,
        w::uint(5),
    );
    let mut file = w::binary_file();
    w::set(&mut file, key::file::DESCRIPTOR, w::map(&descriptor));
    reject(
        &body_with_file(file),
        &ManifestError::UnknownEnumValue {
            enumeration: EnumId::FineTreeDomain,
            value: 5,
        },
    );
}

#[test]
fn reject_non_binary_fine_tree_flag() {
    // Registry §1 rule 1: the flag is uint 0/1, never "non-zero is true".
    let mut descriptor = w::descriptor(0, true);
    w::set(
        &mut descriptor,
        key::descriptor::FINE_TREE_PRESENT,
        w::uint(2),
    );
    let mut file = w::binary_file();
    w::set(&mut file, key::file::DESCRIPTOR, w::map(&descriptor));
    reject(
        &body_with_file(file),
        &ManifestError::UnknownEnumValue {
            enumeration: EnumId::FineTreeFlag,
            value: 2,
        },
    );
}

// ---------------------------------------------------------------------------
// key space: reserved vs unknown vs missing (registry §1 rule 4)
// ---------------------------------------------------------------------------

#[test]
fn reject_reserved_and_unknown_keys_distinctly_in_every_map() {
    // Body.
    let mut body = w::default_body();
    w::set(&mut body, 8, w::uint(0));
    reject(
        &body,
        &ManifestError::ReservedKey {
            map: MapId::Body,
            key: 8,
        },
    );
    let mut body = w::default_body();
    w::set(&mut body, 24, w::uint(0));
    reject(
        &body,
        &ManifestError::UnknownKey {
            map: MapId::Body,
            key: 24,
        },
    );

    // File entry.
    let mut file = w::binary_file();
    w::set(&mut file, 7, w::uint(0));
    reject(
        &body_with_file(file),
        &ManifestError::ReservedKey {
            map: MapId::FileEntry,
            key: 7,
        },
    );

    // Descriptor.
    let mut descriptor = w::descriptor(0, true);
    descriptor.push((4, w::uint(0)));
    let mut file = w::binary_file();
    w::set(&mut file, key::file::DESCRIPTOR, w::map(&descriptor));
    reject(
        &body_with_file(file),
        &ManifestError::ReservedKey {
            map: MapId::Descriptor,
            key: 4,
        },
    );

    // Unit entry.
    let mut unit = w::covered_unit(0, 0, 4096);
    w::set(&mut unit, 23, w::uint(0));
    let file = w::file_entry(0, true, 4096, vec![unit]);
    reject(
        &body_with_file(file),
        &ManifestError::ReservedKey {
            map: MapId::UnitEntry,
            key: 23,
        },
    );
    let mut unit = w::covered_unit(0, 0, 4096);
    w::set(&mut unit, 99, w::uint(0));
    let file = w::file_entry(0, true, 4096, vec![unit]);
    reject(
        &body_with_file(file),
        &ManifestError::UnknownKey {
            map: MapId::UnitEntry,
            key: 99,
        },
    );
}

#[test]
fn reject_missing_required_keys_naming_the_hole() {
    for k in [
        key::body::FORMAT_VERSION,
        key::body::APP_VERSION,
        key::body::SEAL_ID,
        key::body::TITLE,
        key::body::CLAIMED_TIME,
        key::body::PUBKEYS,
        key::body::SIG_POLICY,
        key::body::FILES,
    ] {
        let mut body = w::default_body();
        w::remove(&mut body, k);
        reject(
            &body,
            &ManifestError::MissingKey {
                map: MapId::Body,
                key: k,
            },
        );
    }

    for k in [
        key::unit::UNIT_ID,
        key::unit::KIND,
        key::unit::RANGE,
        key::unit::TRUE_LENGTH,
        key::unit::NONCE,
        key::unit::ADDRESS,
    ] {
        let mut unit = w::covered_unit(0, 0, 4096);
        w::remove(&mut unit, k);
        let file = w::file_entry(0, true, 4096, vec![unit]);
        reject(
            &body_with_file(file),
            &ManifestError::MissingKey {
                map: MapId::UnitEntry,
                key: k,
            },
        );
    }
}

// ---------------------------------------------------------------------------
// structure
// ---------------------------------------------------------------------------

#[test]
fn reject_empty_containers() {
    let mut body = w::default_body();
    w::set(&mut body, key::body::FILES, w::array(&[]));
    reject(
        &body,
        &ManifestError::EmptyContainer {
            field: ContainerField::Files,
        },
    );

    let mut file = w::binary_file();
    w::set(&mut file, key::file::UNITS, w::array(&[]));
    reject(
        &body_with_file(file),
        &ManifestError::EmptyContainer {
            field: ContainerField::Units,
        },
    );

    let mut body = w::default_body();
    w::set(&mut body, key::body::PUBKEYS, w::map(&[]));
    reject(
        &body,
        &ManifestError::EmptyContainer {
            field: ContainerField::Pubkeys,
        },
    );
}

/// **D77: a file whose entire unit table is raw mirrors is rejected.**
///
/// The shape TODO.md and D28 named — a size-0 file with *zero* units — was
/// already closed by `manifest-empty-units` above. The one that survived every
/// layer is the **mirror-only** file: `units` is non-empty, so F5 accepted it;
/// R3's `check_tiling` filters to `kind = Normal` and `tile(&[], 0) == Ok`, so
/// it accepted it too; and D28's `full(F)` is then false for *every* bundle
/// forever, which permanently un-opens two signed, anchored commitments
/// (`canon_commit`, `raw_commit`) — verbatim the condition D28 exists to
/// prevent.
///
/// No honest sealer can emit it: a mirror exists **iff** raw ≠ canonical, and
/// G5 emits the Normal `[0,0)` unit alongside the mirror even in the
/// degenerate BOM-only case. So the strict rule costs the honest sealer
/// nothing, and strict → permissive stays a legal future relaxation while the
/// reverse is not.
#[test]
fn reject_a_file_whose_only_unit_is_a_raw_mirror() {
    // A `--no-fine-tree` file whose single unit is `kind = 1` (raw mirror).
    // Every other rule is satisfied: the unit table is non-empty, and the
    // mirror carries the `unit_commit` a non-covered unit needs.
    let file = w::file_entry(1, false, 0, vec![w::noncovered_unit(0, 1, 0, 12)]);
    reject(
        &body_with_file(file),
        &ManifestError::EmptyContainer {
            field: ContainerField::NormalUnits,
        },
    );
}

/// **D77's frozen check order, in both directions.** The new rule sits after
/// `units.is_empty()` and before the coverage loop, and both edges are
/// observable:
///
/// - a genuinely unit-less file must still report `manifest-empty-units`, not
///   the new code — two codes for one input would break "one code per outcome
///   a mutation can be pinned to" (error-code contract §1);
/// - a mirror-only file whose file *has* a fine tree must report the shape
///   error, not whichever per-unit `unit_commit` error the coverage loop would
///   otherwise reach first.
#[test]
fn the_normal_unit_rule_is_ordered_between_emptiness_and_coverage() {
    // Edge 1: no units at all keeps the older, more specific code.
    let mut empty = w::binary_file();
    w::set(&mut empty, key::file::UNITS, w::array(&[]));
    reject(
        &body_with_file(empty),
        &ManifestError::EmptyContainer {
            field: ContainerField::Units,
        },
    );

    // Edge 2: a fine-tree file whose only unit is a mirror carrying a
    // `unit_commit` — the configuration in which a *Normal* unit would have
    // been rejected by the coverage loop. The shape error still wins.
    let file = w::file_entry(1, true, 0, vec![w::noncovered_unit(0, 1, 0, 12)]);
    reject(
        &body_with_file(file),
        &ManifestError::EmptyContainer {
            field: ContainerField::NormalUnits,
        },
    );
}

#[test]
fn reject_byte_range_that_is_not_a_two_element_array() {
    for (items, got) in [
        (vec![w::uint(0)], 1u64),
        (vec![w::uint(0), w::uint(1), w::uint(2)], 3),
        (vec![], 0),
    ] {
        let mut unit = w::covered_unit(0, 0, 4096);
        w::set(&mut unit, key::unit::RANGE, w::array(&items));
        let file = w::file_entry(0, true, 4096, vec![unit]);
        reject(
            &body_with_file(file),
            &ManifestError::WrongRangeArity { got },
        );
    }
}

#[test]
fn reject_unit_id_that_is_not_its_manifest_order_ordinal() {
    // Ids are work-global and define every per-unit derivation, so a
    // silent reordering must be unrepresentable (registry §7.5 key 0).
    let file_a = w::file_entry(0, true, 10, vec![w::covered_unit(0, 0, 10)]);
    let file_b = w::file_entry(0, true, 10, vec![w::covered_unit(5, 0, 10)]);
    reject(
        &w::body(vec![file_a, file_b]),
        &ManifestError::UnitIdMismatch {
            expected: 1,
            found: 5,
        },
    );
}

#[test]
fn reject_unsupported_format_version() {
    let mut body = w::default_body();
    w::set(&mut body, key::body::FORMAT_VERSION, w::uint(2));
    reject(
        &body,
        &ManifestError::UnsupportedFormatVersion {
            found: 2,
            supported: antseal_core::format::SUPPORTED_VERSIONS,
        },
    );
}

// ---------------------------------------------------------------------------
// the reject matrix is a *matrix*: every case above has its own code
// ---------------------------------------------------------------------------

#[test]
fn every_reject_case_carries_a_distinct_error_code() {
    use std::collections::BTreeMap;

    // (case name, mutated body) pairs whose codes must be pairwise
    // distinct — the line-168 "every mutation fails with a distinct
    // error" requirement, executed.
    let mut cases: Vec<(&str, RawBody)> = Vec::new();

    let mut b = w::default_body();
    w::set(&mut b, key::body::SIG_POLICY, w::array(&[]));
    cases.push(("empty sig_policy", b));

    let mut b = w::default_body();
    w::set(
        &mut b,
        key::body::SIG_POLICY,
        w::array(&[w::uint(0), w::uint(0)]),
    );
    cases.push(("duplicate sig_policy entry", b));

    let mut b = w::default_body();
    w::set(&mut b, key::body::SIG_POLICY, w::array(&[w::uint(3)]));
    cases.push(("unregistered sig_policy alg", b));

    let mut unit = w::covered_unit(0, 0, 1024);
    w::set(&mut unit, key::unit::UNIT_COMMIT, w::commit(0x99));
    cases.push((
        "unit_commit on a covered unit",
        body_with_file(w::file_entry(
            1,
            true,
            1024,
            vec![unit, w::noncovered_unit(1, 1, 0, 1030)],
        )),
    ));

    let mut mirror = w::noncovered_unit(1, 1, 0, 1030);
    w::remove(&mut mirror, key::unit::UNIT_COMMIT);
    cases.push((
        "unit_commit absent on a mirror",
        body_with_file(w::file_entry(
            1,
            true,
            1024,
            vec![w::covered_unit(0, 0, 1024), mirror],
        )),
    ));

    let mut file = w::binary_file();
    w::set(&mut file, key::file::CANON_COMMIT, w::commit(0x03));
    cases.push(("canon_commit on a binary file", body_with_file(file)));

    let mut file = w::no_fine_tree_file();
    w::set(&mut file, key::file::FINE_ROOT, w::commit(0x04));
    cases.push(("fine_root on a --no-fine-tree file", body_with_file(file)));

    let mut b = w::default_body();
    w::set(&mut b, key::body::SEAL_ID, w::bstr(&[0u8; 15]));
    cases.push(("wrong-length seal_id", b));

    let mut unit = w::covered_unit(0, 0, 4096);
    w::set(&mut unit, key::unit::NONCE, w::bstr(&[0u8; 23]));
    cases.push((
        "wrong-length nonce",
        body_with_file(w::file_entry(0, true, 4096, vec![unit])),
    ));

    let mut file = w::binary_file();
    w::set(&mut file, key::file::PATH_COMMIT, w::bstr(&[0u8; 31]));
    cases.push(("wrong-length path_commit", body_with_file(file)));

    let mut file = w::binary_file();
    w::set(&mut file, key::file::FINE_ROOT, w::bstr(&[0u8; 31]));
    cases.push(("wrong-length fine_root", body_with_file(file)));

    let mut unit = w::covered_unit(0, 0, 4096);
    w::set(&mut unit, key::unit::ADDRESS, w::bstr(&[0u8; 31]));
    cases.push((
        "wrong-length address",
        body_with_file(w::file_entry(0, true, 4096, vec![unit])),
    ));

    let mut unit = w::covered_unit(0, 0, 4096);
    w::set(&mut unit, key::unit::KIND, w::uint(2));
    cases.push((
        "unknown unit kind",
        body_with_file(w::file_entry(0, true, 4096, vec![unit])),
    ));

    let mut b = w::default_body();
    w::set(&mut b, 8, w::uint(0));
    cases.push(("reserved body key", b));

    let mut b = w::default_body();
    w::set(&mut b, 24, w::uint(0));
    cases.push(("unknown body key", b));

    let mut b = w::default_body();
    w::remove(&mut b, key::body::TITLE);
    cases.push(("missing required key", b));

    let mut b = w::default_body();
    w::set(&mut b, key::body::FILES, w::array(&[]));
    cases.push(("empty files", b));

    let mut unit = w::covered_unit(0, 0, 4096);
    w::set(&mut unit, key::unit::RANGE, w::array(&[w::uint(0)]));
    cases.push((
        "one-element byte range",
        body_with_file(w::file_entry(0, true, 4096, vec![unit])),
    ));

    cases.push((
        "unit_id out of manifest order",
        w::body(vec![
            w::file_entry(0, true, 10, vec![w::covered_unit(0, 0, 10)]),
            w::file_entry(0, true, 10, vec![w::covered_unit(7, 0, 10)]),
        ]),
    ));

    cases.push((
        "two raw mirrors in one file",
        body_with_file(w::file_entry(
            1,
            true,
            1024,
            vec![
                w::covered_unit(0, 0, 1024),
                w::noncovered_unit(1, 1, 0, 1030),
                w::noncovered_unit(2, 1, 512, 600),
            ],
        )),
    ));

    let mut b = w::default_body();
    w::set(&mut b, key::body::FORMAT_VERSION, w::uint(2));
    cases.push(("unsupported format_version", b));

    let mut seen: BTreeMap<&'static str, &str> = BTreeMap::new();
    for (name, entries) in &cases {
        let err = decode(entries).expect_err(name);
        let code = err.code();
        assert!(
            code.starts_with("manifest-"),
            "{name}: schema rejections use the manifest- prefix, got {code}"
        );
        if let Some(previous) = seen.insert(code, name) {
            panic!("{name} and {previous} share the code {code}");
        }
    }
    assert_eq!(seen.len(), cases.len(), "every case must be distinct");
}

// ---------------------------------------------------------------------------
// accept matrix (F5 accept: each of these decodes)
// ---------------------------------------------------------------------------

#[test]
fn accept_text_file_with_a_raw_mirror() {
    let body = decode(&w::body(vec![w::text_file_with_mirror()])).expect("must decode");
    let file = &body.files()[0];
    assert_eq!(file.canon().kind(), DescriptorKind::Text);
    assert!(file.fine_tree().is_present());
    let mirror = file.raw_mirror().expect("mirror present");
    assert_eq!(mirror.kind(), UnitKind::RawMirror);
    assert!(mirror.unit_commit().is_some());
    assert!(file.units()[0].unit_commit().is_none());
}

#[test]
fn accept_binary_single_unit_file() {
    let body = decode(&w::body(vec![w::binary_file()])).expect("must decode");
    let file = &body.files()[0];
    assert_eq!(file.canon(), &CanonMode::Binary);
    assert_eq!(file.units().len(), 1);
    assert!(file.raw_mirror().is_none());
}

#[test]
fn accept_no_fine_tree_file() {
    let body = decode(&w::body(vec![w::no_fine_tree_file()])).expect("must decode");
    let file = &body.files()[0];
    assert_eq!(file.fine_tree(), FineTree::Absent);
    assert!(file.descriptor().fine_tree_domain().is_none());
    assert!(file.units()[0].unit_commit().is_some());
}

#[test]
fn accept_empty_file() {
    let body = decode(&w::body(vec![w::empty_file()])).expect("must decode");
    let file = &body.files()[0];
    assert_eq!(file.size(), 0);
    let unit = &file.units()[0];
    assert_eq!(unit.true_length(), 0);
    assert_eq!(unit.range(), ByteRange::new(0, 0));
    assert_eq!(file.fine_tree(), FineTree::Absent);
}

#[test]
fn accept_multi_file_split_shaped_body() {
    let body = decode(&w::body(vec![
        w::text_file_with_mirror(),
        w::binary_file(),
        w::no_fine_tree_file(),
    ]));
    // Unit ids must be work-global, so the hand-built files (each
    // numbering from 0) are rejected until renumbered — exactly the
    // property the ordinal check exists for.
    assert_eq!(
        body,
        Err(ManifestError::UnitIdMismatch {
            expected: 2,
            found: 0
        })
    );

    // Renumbered work-globally, the same three files decode.
    let text = w::file_entry(
        1,
        true,
        1024,
        vec![
            w::covered_unit(0, 0, 1024),
            w::noncovered_unit(1, 1, 0, 1030),
        ],
    );
    let binary = w::file_entry(0, true, 4096, vec![w::covered_unit(2, 0, 4096)]);
    let plain = w::file_entry(1, false, 700, vec![w::noncovered_unit(3, 0, 0, 700)]);
    let body = decode(&w::body(vec![text, binary, plain])).expect("must decode");
    assert_eq!(body.files().len(), 3);
    assert_eq!(body.units_total(), 4);
}

#[test]
fn accept_ed25519_only_sig_policy_fallback() {
    // MVP-SPEC.md line 97: if ML-DSA had failed the WASM probe the
    // fallback ships sig_policy = [ed25519] with the format unchanged.
    let mut body = w::default_body();
    w::set(&mut body, key::body::SIG_POLICY, w::array(&[w::uint(0)]));
    w::set(
        &mut body,
        key::body::PUBKEYS,
        w::map(&[(0, w::bstr(&[0xE1; 32]))]),
    );
    let decoded = decode(&body).expect("fallback shape must decode");
    assert_eq!(decoded.sig_policy(), [SigAlg::Ed25519]);
    assert_eq!(decoded.pubkeys().len(), 1);
}

#[test]
fn accept_preserves_sig_policy_order() {
    // The policy is an ordered list (spec line 97); the wire order is the
    // sealer's and must survive decode unchanged.
    let mut body = w::default_body();
    w::set(
        &mut body,
        key::body::SIG_POLICY,
        w::array(&[w::uint(1), w::uint(0)]),
    );
    let decoded = decode(&body).expect("must decode");
    assert_eq!(decoded.sig_policy(), [SigAlg::MlDsa65, SigAlg::Ed25519]);
}

// ---------------------------------------------------------------------------
// the same gate guards in-memory construction (F5 accept: a
// schema-invalid body cannot be *constructed*, not merely not decoded)
// ---------------------------------------------------------------------------

#[test]
fn in_memory_construction_runs_the_same_validation() {
    // Empty sig_policy.
    assert_eq!(
        ManifestBodyV1::new(
            "app".to_owned(),
            fixtures::seal_id(),
            String::new(),
            0,
            fixtures::hybrid_pubkeys(),
            vec![],
            vec![fixtures::binary_file(0)],
        )
        .map(|_| ()),
        Err(ManifestError::SigPolicyEmpty)
    );

    // Duplicate policy entry.
    assert_eq!(
        ManifestBodyV1::new(
            "app".to_owned(),
            fixtures::seal_id(),
            String::new(),
            0,
            fixtures::hybrid_pubkeys(),
            vec![SigAlg::Ed25519, SigAlg::Ed25519],
            vec![fixtures::binary_file(0)],
        )
        .map(|_| ()),
        Err(ManifestError::DuplicateAlg {
            position: AlgPosition::SigPolicy,
            alg_id: 0
        })
    );

    // No files.
    assert_eq!(
        ManifestBodyV1::new(
            "app".to_owned(),
            fixtures::seal_id(),
            String::new(),
            0,
            fixtures::hybrid_pubkeys(),
            vec![SigAlg::Ed25519],
            vec![],
        )
        .map(|_| ()),
        Err(ManifestError::EmptyContainer {
            field: ContainerField::Files
        })
    );

    // Unit ids that are not manifest-order ordinals.
    assert_eq!(
        ManifestBodyV1::new(
            "app".to_owned(),
            fixtures::seal_id(),
            String::new(),
            0,
            fixtures::hybrid_pubkeys(),
            vec![SigAlg::Ed25519],
            vec![fixtures::binary_file(3)],
        )
        .map(|_| ()),
        Err(ManifestError::UnitIdMismatch {
            expected: 0,
            found: 3
        })
    );

    // A covered unit carrying a unit_commit.
    let bogus = UnitEntry::new(
        0,
        UnitKind::Normal,
        ByteRange::new(0, 16),
        16,
        UnitBinding::NonCovered {
            unit_commit: [0x99; 32],
        },
        Nonce24::from_bytes([0; 24]),
        ContentAddress::from_bytes([0; 32]),
    );
    assert_eq!(
        FileEntry::new(
            [0; 32],
            [0; 32],
            CanonMode::Binary,
            16,
            FineTree::Present { root: [1; 32] },
            vec![bogus],
        )
        .map(|_| ()),
        Err(ManifestError::UnexpectedField {
            field: CondField::UnitCommit
        })
    );

    // An empty unit table.
    assert_eq!(
        FileEntry::new(
            [0; 32],
            [0; 32],
            CanonMode::Binary,
            0,
            FineTree::Absent,
            vec![],
        )
        .map(|_| ()),
        Err(ManifestError::EmptyContainer {
            field: ContainerField::Units
        })
    );

    // D77: a non-empty unit table with no `kind = normal` unit. Constructible
    // ≡ decodable — `FileEntry::decode` routes through `new`, so closing the
    // shape here closes it for every decoded manifest as well, which is why
    // D77 chose F5 over R3.
    let mirror_only = UnitEntry::new(
        0,
        UnitKind::RawMirror,
        ByteRange::new(0, 12),
        12,
        UnitBinding::NonCovered {
            unit_commit: [0x77; 32],
        },
        Nonce24::from_bytes([0; 24]),
        ContentAddress::from_bytes([0; 32]),
    );
    assert_eq!(
        FileEntry::new(
            [0; 32],
            [0; 32],
            CanonMode::Binary,
            0,
            FineTree::Absent,
            vec![mirror_only],
        )
        .map(|_| ()),
        Err(ManifestError::EmptyContainer {
            field: ContainerField::NormalUnits
        })
    );

    // D23 clause 3 / F40: a non-empty unit table with a Normal unit but TWO
    // raw mirrors. Constructible ≡ decodable — `FileEntry::decode` routes
    // through `new` (body.rs), so closing the shape here closes it for every
    // decoded manifest as well; `reject_a_file_with_two_raw_mirrors` is the
    // decode-path twin of this arm. Both mirrors carry the `unit_commit` a
    // non-covered unit must, so the coverage rules alone would accept this —
    // which is precisely why the count rule has to exist.
    let mirror = |id: u64, seed: u8| {
        UnitEntry::new(
            id,
            UnitKind::RawMirror,
            ByteRange::new(0, 20),
            20,
            UnitBinding::NonCovered {
                unit_commit: [seed; 32],
            },
            Nonce24::from_bytes([seed; 24]),
            ContentAddress::from_bytes([seed; 32]),
        )
    };
    let normal = UnitEntry::new(
        0,
        UnitKind::Normal,
        ByteRange::new(0, 16),
        16,
        UnitBinding::FineTreeCovered,
        Nonce24::from_bytes([0; 24]),
        ContentAddress::from_bytes([0; 32]),
    );
    assert_eq!(
        FileEntry::new(
            [0; 32],
            [0; 32],
            CanonMode::Text {
                canon_commit: [3; 32],
                unicode_version: "unicode-17.0.0".to_owned(),
            },
            16,
            FineTree::Present { root: [1; 32] },
            vec![normal, mirror(1, 0x41), mirror(2, 0x42)],
        )
        .map(|_| ()),
        Err(ManifestError::MultipleRawMirrors { count: 2 })
    );
}

/// **D23 clause 3 (F40): a file with two raw mirrors is rejected.**
///
/// This is the exact shape the 2026-07-31 adversarial review demonstrated
/// clean-verifying (findings 1–3): units `{0: Normal (covered), 1: RawMirror,
/// 2: RawMirror}`, every other rule satisfied — ordinals sequential, D77's
/// Normal present, and *both* mirrors carrying the `unit_commit` a
/// non-covered unit must carry, so the coverage loop has nothing to object
/// to. Before F40 this decoded clean, and only mirror 1 was bound by rows
/// 9–10; mirror 2 rode along signed and anchored, bound by nothing but its
/// own sealer-chosen commitment — a second, contradictory "original"
/// (MVP-SPEC.md line 121). The red-direction run is recorded in F40's
/// report: both this decode path and the direct-construction path accepted
/// the shape on the pre-fix tree.
#[test]
fn reject_a_file_with_two_raw_mirrors() {
    let file = w::file_entry(
        1,
        true,
        1024,
        vec![
            w::covered_unit(0, 0, 1024),
            w::noncovered_unit(1, 1, 0, 1030),
            w::noncovered_unit(2, 1, 512, 600),
        ],
    );
    reject(
        &body_with_file(file),
        &ManifestError::MultipleRawMirrors { count: 2 },
    );

    // The count is the real count, not a boolean: three mirrors say three.
    let file = w::file_entry(
        1,
        true,
        1024,
        vec![
            w::covered_unit(0, 0, 1024),
            w::noncovered_unit(1, 1, 0, 1030),
            w::noncovered_unit(2, 1, 512, 600),
            w::noncovered_unit(3, 1, 512, 601),
        ],
    );
    reject(
        &body_with_file(file),
        &ManifestError::MultipleRawMirrors { count: 3 },
    );
}

/// **F40's frozen check order, in both directions** (the D77 pattern one
/// rule down):
///
/// - an input violating D77 *and* the mirror-count rule at once — a
///   mirror-only table with two mirrors — keeps reporting
///   `manifest-empty-normal-units`: inputs F5 already rejected keep their
///   code, and the new rule claims only previously-accepted inputs plus the
///   coverage loop's mis-attributions below;
/// - a two-mirror file whose *second* mirror is also malformed (missing its
///   `unit_commit`) reports the shape error, not the per-unit
///   `manifest-missing-unit-commit` the coverage loop would have tripped —
///   the same shape-beats-binding order D77 recorded, because which
///   per-unit error fires first is an iteration accident while the table
///   fault is the stable fact.
#[test]
fn the_mirror_count_rule_is_ordered_after_d77_and_before_coverage() {
    // Edge 1: both shape rules violated — D77's (frozen first) wins.
    let file = w::file_entry(
        1,
        false,
        0,
        vec![
            w::noncovered_unit(0, 1, 0, 12),
            w::noncovered_unit(1, 1, 0, 34),
        ],
    );
    reject(
        &body_with_file(file),
        &ManifestError::EmptyContainer {
            field: ContainerField::NormalUnits,
        },
    );

    // Edge 2: two mirrors AND a binding fault on the second — the shape
    // error wins over the coverage loop.
    let mut second = w::noncovered_unit(2, 1, 512, 600);
    w::remove(&mut second, key::unit::UNIT_COMMIT);
    let file = w::file_entry(
        1,
        true,
        1024,
        vec![
            w::covered_unit(0, 0, 1024),
            w::noncovered_unit(1, 1, 0, 1030),
            second,
        ],
    );
    reject(
        &body_with_file(file),
        &ManifestError::MultipleRawMirrors { count: 2 },
    );
}

/// Every fixture the crate ships round-trips through encode → decode,
/// so the committed fixtures and the schema can never drift apart.
#[test]
fn every_shipped_fixture_round_trips() {
    let builders: [FixtureBuilder; 6] = [
        ("text_with_mirror", fixtures::text_with_mirror_body),
        ("binary_single_unit", fixtures::binary_single_unit_body),
        ("no_fine_tree", fixtures::no_fine_tree_body),
        ("empty_file", fixtures::empty_file_body),
        ("multi_file_split", fixtures::multi_file_split_body),
        ("ed25519_only", fixtures::ed25519_only_body),
    ];
    for (name, build) in builders {
        let bytes = antseal_core::manifest::encode_body(build()).expect(name);
        let decoded = ManifestBodyV1::decode(&bytes).expect(name);
        assert_eq!(decoded, build(), "{name}: decode(encode(x)) != x");
        // ...and re-encoding the *rebuilt* body reproduces the bytes.
        let again = antseal_core::manifest::encode_body(build()).expect(name);
        assert_eq!(again, bytes, "{name}: encoding is not deterministic");
    }
}
