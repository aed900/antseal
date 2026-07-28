//! Hash domain-tag registry — the **single** module defining the seven domain
//! tags of MVP-SPEC.md line 79, and the one helper every tagged SHA-256
//! preimage in the codebase must route through.
//!
//! Per the spec ("Definitions & encoding", line 79), the tag is the **first
//! byte** of every *commitment / tree / salt-derivation* SHA-256 preimage the
//! spec defines. No other module may hard-code a tag byte; call sites name
//! the `TAG_*` consts and build preimages with [`tagged_sha256`] so the tag
//! is always, structurally, the first preimage byte. A grep-enforced test in
//! this module keeps that invariant honest.
//!
//! # `work_id` / `anchor_digest` are domain-separated by construction
//!
//! `work_id = SHA-256(body)` and `anchor_digest = SHA-256(full manifest
//! bytes)` (MVP-SPEC.md line 75) do **not** take a domain tag: they hash raw
//! deterministic-CBOR bytes and are domain-separated from every tagged
//! preimage by construction, because their first hashed byte is a top-level
//! CBOR header that cannot collide with `0x00`–`0x06` (MVP-SPEC.md line 79).
//! Concretely: the manifest and the `body` are deterministic-CBOR maps /
//! embedded byte strings, so the leading byte is a major-type-5 map header
//! (`0xA0..`) or a major-type-2 byte-string header (`0x40..`); the bytes
//! `0x00`–`0x06` as a *leading* byte would encode the top-level unsigned
//! integers 0–6, which the manifest/bundle schema never is. F asserts this
//! disjointness against [`MAX_DOMAIN_TAG`] on every encoded manifest/body
//! golden vector.
//!
//! Salts, by contrast, are separated by their HKDF *labels*, not by tags
//! (spec line 79 parenthetical); see [`crate::crypto::hkdf`].

use sha2::{Digest, Sha256};

/// `0x00` — fine-tree **leaf** preimage,
/// `leaf_i = SHA-256(0x00 ‖ salt_i ‖ LE64(i) ‖ byte_i)` (MVP-SPEC.md lines
/// 79, 96). Consumed by G's fine-tree construction.
pub const TAG_FINE_TREE_LEAF: u8 = 0x00;

/// `0x01` — fine-tree interior **node** preimage: two-child SHA-256 Merkle
/// with `0x01` node prefix, RFC-6962-style unbalanced promotion (MVP-SPEC.md
/// lines 78, 79, 96). Consumed by G's fine-tree construction.
pub const TAG_FINE_TREE_NODE: u8 = 0x01;

/// `0x02` — `unit_commit = SHA-256(0x02 ‖ unit_salt ‖ unit_bytes)`
/// (MVP-SPEC.md lines 79, 94). Present iff the unit is NOT fine-tree-covered
/// (`--no-fine-tree` whole-file units and raw-mirror units only).
pub const TAG_UNIT_COMMIT: u8 = 0x02;

/// `0x03` — `raw_commit = SHA-256(0x03 ‖ file_salt ‖ raw_bytes)`
/// (MVP-SPEC.md lines 79, 95).
pub const TAG_RAW_COMMIT: u8 = 0x03;

/// `0x04` — `canon_commit = SHA-256(0x04 ‖ file_salt ‖ canonical_bytes)`
/// (text files only; MVP-SPEC.md lines 79, 95).
pub const TAG_CANON_COMMIT: u8 = 0x04;

/// `0x05` — `path_commit = SHA-256(0x05 ‖ path_salt ‖ path_utf8)`
/// (MVP-SPEC.md lines 79, 95).
pub const TAG_PATH_COMMIT: u8 = 0x05;

/// `0x06` — GGM salt-tree **child** derivation,
/// `s_{v‖b} = SHA-256(0x06 ‖ s_v ‖ b)` for child bit `b ∈ {0x00, 0x01}`
/// (MVP-SPEC.md lines 79, 96). Note the trailing child-index byte `b` is
/// preimage *data*, not a domain tag — only the first preimage byte carries
/// domain meaning.
pub const TAG_GGM_SALT_CHILD: u8 = 0x06;

/// The largest registered domain tag. Exported for F's disjointness
/// assertion: the first byte of every encoded manifest/`body` (a top-level
/// deterministic-CBOR map/bstr header) must be `> MAX_DOMAIN_TAG`, which is
/// what makes `work_id`/`anchor_digest` domain-separated by construction
/// (MVP-SPEC.md line 79; module docs above).
pub const MAX_DOMAIN_TAG: u8 = 0x06;

/// Compute `SHA-256(tag ‖ parts[0] ‖ parts[1] ‖ …)`.
///
/// The single routing point for every domain-tagged SHA-256 preimage
/// (MVP-SPEC.md line 79): commitments (C6), fine-tree leaves/nodes and GGM
/// salt-child derivation (G). Passing the parts as slices guarantees the tag
/// is the first preimage byte and lets callers hash without concatenating
/// into an owned buffer.
///
/// `tag` must be one of this module's `TAG_*` consts — call sites pass the
/// named const, never a literal (grep-enforced by
/// `no_other_module_hardcodes_domain_tag_bytes`).
///
/// ```
/// use antseal_core::crypto::domain::{TAG_UNIT_COMMIT, tagged_sha256};
///
/// // unit_commit = SHA-256(0x02 ‖ unit_salt ‖ unit_bytes)  (spec line 94)
/// let unit_salt = [0u8; 16];
/// let parts: [&[u8]; 2] = [&unit_salt, b"unit bytes"];
/// let digest = tagged_sha256(TAG_UNIT_COMMIT, &parts);
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn tagged_sha256(tag: u8, parts: &[&[u8]]) -> [u8; 32] {
    debug_assert!(
        tag <= MAX_DOMAIN_TAG,
        "unregistered domain tag: every tagged preimage must use a TAG_* const from crypto::domain"
    );
    let mut hasher = Sha256::new();
    hasher.update([tag]);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    // The source-scanning discipline test below reads the crate's own
    // `src/` tree at run time. That is the one genuinely native-only test in
    // this crate: `wasm32-unknown-unknown` has no filesystem, so it is
    // excluded from the `wasm32-core-tests` lane (P14,
    // docs/wasm-toolchain.md). It stays a first-class native test.
    #[cfg(not(target_arch = "wasm32"))]
    use std::fs;
    #[cfg(not(target_arch = "wasm32"))]
    use std::path::{Path, PathBuf};

    /// The seven tags, exactly as registered by MVP-SPEC.md line 79.
    const ALL_TAGS: [(u8, &str); 7] = [
        (TAG_FINE_TREE_LEAF, "fine-tree leaf"),
        (TAG_FINE_TREE_NODE, "fine-tree node"),
        (TAG_UNIT_COMMIT, "unit_commit"),
        (TAG_RAW_COMMIT, "raw_commit"),
        (TAG_CANON_COMMIT, "canon_commit"),
        (TAG_PATH_COMMIT, "path_commit"),
        (TAG_GGM_SALT_CHILD, "GGM salt-tree child"),
    ];

    /// Values are exactly `0x00`–`0x06` in spec order (MVP-SPEC.md line 79),
    /// each defined once, and `MAX_DOMAIN_TAG` is the largest.
    #[test]
    fn tag_values_match_spec_line_79() {
        for (expected, (tag, _name)) in ALL_TAGS.iter().enumerate() {
            assert_eq!(u8::try_from(expected).ok(), Some(*tag));
        }
        assert_eq!(MAX_DOMAIN_TAG, 0x06);
        assert_eq!(
            usize::from(MAX_DOMAIN_TAG) + 1,
            ALL_TAGS.len(),
            "registry and MAX_DOMAIN_TAG must move together"
        );
    }

    /// C1 accept: `tagged_sha256` equals SHA-256 over the manually
    /// concatenated preimage `tag ‖ concat(parts)`, computed independently,
    /// for every tag and for several part splits of the same content
    /// (streaming must equal concatenation).
    #[test]
    fn tagged_sha256_matches_independent_sha256() {
        let salt = [0xA5u8; 16];
        let content = b"the quick brown fox jumps over the lazy dog";
        for (tag, name) in ALL_TAGS {
            // Independent computation: one flat buffer, one-shot SHA-256.
            let mut preimage = vec![tag];
            preimage.extend_from_slice(&salt);
            preimage.extend_from_slice(content);
            let expected: [u8; 32] = Sha256::digest(&preimage).into();

            // Same content presented as different part splits.
            let split_at = content.len() / 2;
            let as_two_parts: [&[u8]; 2] = [&salt, content];
            let as_three_parts: [&[u8]; 3] = [&salt, &content[..split_at], &content[split_at..]];
            assert_eq!(tagged_sha256(tag, &as_two_parts), expected, "{name}");
            assert_eq!(tagged_sha256(tag, &as_three_parts), expected, "{name}");
        }
    }

    /// Zero parts hashes exactly the lone tag byte; the empty part
    /// contributes nothing.
    #[test]
    fn tagged_sha256_empty_parts() {
        let expected: [u8; 32] = Sha256::digest([TAG_UNIT_COMMIT]).into();
        assert_eq!(tagged_sha256(TAG_UNIT_COMMIT, &[]), expected);
        assert_eq!(tagged_sha256(TAG_UNIT_COMMIT, &[b""]), expected);
    }

    /// Distinct tags over identical parts give distinct digests (domain
    /// separation actually separates).
    #[test]
    fn distinct_tags_separate_domains() {
        let parts: [&[u8]; 1] = [b"same bytes under every tag"];
        let digests: Vec<[u8; 32]> = ALL_TAGS
            .iter()
            .map(|(tag, _)| tagged_sha256(*tag, &parts))
            .collect();
        for i in 0..digests.len() {
            for j in (i + 1)..digests.len() {
                assert_ne!(digests[i], digests[j], "tags 0x{i:02x} vs 0x{j:02x}");
            }
        }
    }

    /// C1 accept: no module other than this one hard-codes a domain-tag byte
    /// (grep-enforced test).
    ///
    /// Scans the *library region* (everything before the first
    /// `#[cfg(test)]`) of every `.rs` file under `src/` except this file,
    /// rejecting:
    ///
    /// 1. `tagged_sha256(0…` — a literal tag at a call site anywhere in the
    ///    crate (call sites must name a `TAG_*` const);
    /// 2. `: u8 = 0x00` … `: u8 = 0x06` — a tag-valued `u8` const defined
    ///    outside this registry. Convention enforced crate-wide: hex-form
    ///    `u8` consts in the range `0x00`–`0x06` are reserved to this module;
    ///    write unrelated small `u8` consts in decimal.
    /// 3. `Sha256::new` / `Sha256::digest` inside `src/crypto/` — within the
    ///    crypto tree, every direct hash construction routes through
    ///    [`tagged_sha256`] (naming `Sha256` as a type parameter, e.g.
    ///    `Hkdf<Sha256>`, remains fine). `work_id`/`anchor_digest` hash raw
    ///    CBOR *outside* `src/crypto/` and are exempt by construction (module
    ///    docs; MVP-SPEC.md lines 75, 79).
    ///
    /// Relies on `cargo fmt --check` (CI) normalizing token spacing.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn no_other_module_hardcodes_domain_tag_bytes() {
        let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let this_file = src_root.join("crypto").join("domain.rs");
        let crypto_dir = src_root.join("crypto");

        let mut files = Vec::new();
        collect_rust_files(&src_root, &mut files);
        assert!(
            files.contains(&this_file),
            "scanner failed to see its own registry file — walker broken?"
        );

        let tag_const_patterns: Vec<String> = (0u8..=MAX_DOMAIN_TAG)
            .map(|b| format!(": u8 = 0x{b:02x}"))
            .collect();
        let mut violations = Vec::new();

        for file in &files {
            if *file == this_file {
                continue;
            }
            let content = fs::read_to_string(file)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
            // Library region only: independent SHA-256 computations inside
            // test modules are legitimate (and required by golden tests).
            let library_region = content.split("#[cfg(test)]").next().unwrap_or("");

            if library_region.contains("tagged_sha256(0") {
                violations.push(format!(
                    "{}: literal domain tag at a tagged_sha256 call site (use a TAG_* const)",
                    file.display()
                ));
            }
            for pattern in &tag_const_patterns {
                if library_region.contains(pattern.as_str()) {
                    violations.push(format!(
                        "{}: tag-valued u8 const `{pattern}` defined outside crypto::domain",
                        file.display()
                    ));
                }
            }
            if file.starts_with(&crypto_dir) {
                for pattern in ["Sha256::new", "Sha256::digest"] {
                    if library_region.contains(pattern) {
                        violations.push(format!(
                            "{}: direct `{pattern}` in src/crypto/ — route the preimage through crypto::domain::tagged_sha256",
                            file.display()
                        ));
                    }
                }
            }
        }

        assert!(
            violations.is_empty(),
            "domain-tag discipline violations (MVP-SPEC.md line 79; tasks/C.md C1):\n{}",
            violations.join("\n")
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries =
            fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("cannot read dir entry under {}: {e}", dir.display()))
                .path();
            if path.is_dir() {
                collect_rust_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
}
