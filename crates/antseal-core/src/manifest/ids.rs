//! `work_id` and `anchor_digest` (F7): the two SHA-256 identities of a
//! sealed work (MVP-SPEC.md line 75).
//!
//! - **`work_id` = SHA-256(body bytes)** — the identity of the *work*.
//!   It covers the manifest body and nothing else, so it is stable across
//!   re-signing and is what a human quotes.
//! - **`anchor_digest` = SHA-256(full manifest bytes, signatures
//!   included)** — what the timestamps are taken over. Anchoring the
//!   signature-bearing bytes is what binds the signatures into the
//!   timestamp; anchoring the body alone would leave the signatures
//!   un-timestamped and re-signable after the fact.
//!
//! Two functions, two newtypes, no conversion between them: mixing them
//! up is a type error, not a subtle verification bug.
//!
//! # Why neither carries a domain tag
//!
//! Every *commitment / tree / salt-derivation* pre-image in this format
//! starts with a byte from the single hash-domain-tag registry — `0x00`
//! fine-tree leaf, `0x01` node, `0x02` `unit_commit`, `0x03` `raw_commit`,
//! `0x04` `canon_commit`, `0x05` `path_commit`, `0x06` GGM salt child
//! (spec line 79; [`crate::crypto::domain`]). These two functions hash
//! **raw deterministic-CBOR bytes** and are domain-separated by
//! construction *of their two pre-image languages*, not by a property of
//! canonical items in general: a body is the v1 body **map** (head `0xa8`
//! today; any additive v1.x key keeps it a map head) and an envelope is
//! the envelope **map** (head `0xa2`), and every canonical CBOR map head
//! is `>= 0xa0` — far above the `0x00..=0x06` tag range. The general
//! claim would be false, and this doc once asserted it (F41): the v1
//! profile admits top-level `uint` items, and the canonical encoding of
//! the integer `0` is the single byte `0x00`, which **is**
//! `TAG_FINE_TREE_LEAF`. No bare integer is a body or an envelope — both
//! schemas require a map — which is the whole argument;
//! `pre_images_are_maps_whose_heads_clear_the_tag_range` below executes
//! it, counterexample included, and the F16 vector checker asserts it on
//! every committed golden vector. Prefixing a tag would therefore add no
//! separation, and would break the property that `work_id` is the hash of
//! *exactly the bytes that were signed*.
//!
//! Domain separation between the two *functions* comes from their
//! pre-images being different languages: a body is a map with key 0 =
//! `format_version`, an envelope is a map with key 0 = a byte string. A
//! body can never be a valid envelope (its key 0 is a `uint`, not a
//! `bstr`), so no byte string is legitimately hashed under both names.
//!
//! # Binding strength (frozen at M0)
//!
//! Both are standard-model SHA-256 collision-resistance, ~128-bit —
//! the permanent sealer-equivocation bound (spec line 100). There is no
//! hash agility; a wider hash would be a format-version event.
//!
//! # Naming ban
//!
//! The spec bans the bare phrase "manifest hash" (line 75): the two
//! digests are never interchangeable and a single fuzzy name invites
//! anchoring the wrong one. `no_source_file_uses_a_banned_identifier` in
//! `tests/identifier_bans.rs` greps the tracked sources (`manifest_hash`
//! is on its ban list) to keep it that way. (F41: this note used to name
//! a test and file that never existed.)

use core::fmt;

use sha2::{Digest, Sha256};

/// Render 32 bytes as lowercase hex.
fn write_hex(bytes: &[u8; 32], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

/// Declare one 32-byte digest newtype with lowercase-hex `Display` and a
/// `Debug` that names the type (so a log line can never be mistaken for
/// the other digest).
macro_rules! digest_newtype {
    ($(#[$doc:meta])* $name:ident, $label:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Length in bytes.
            pub const LEN: u64 = 32;

            /// Wrap already-computed digest bytes (decode/report paths).
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Consume into the raw digest bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }

            /// Lowercase hex, allocated. CLI/report presentation
            /// (truncation, grouping) is U's and R's, never this layer's.
            #[must_use]
            pub fn to_hex(&self) -> String {
                self.to_string()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_hex(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($label, "("))?;
                write_hex(&self.0, f)?;
                f.write_str(")")
            }
        }
    };
}

digest_newtype!(
    /// `work_id` = SHA-256(manifest body bytes) — the work's identity
    /// (MVP-SPEC.md line 75).
    ///
    /// Deliberately not convertible to or from [`AnchorDigest`]: the two
    /// are computed over different pre-images and anchoring the wrong one
    /// would silently leave the signatures un-timestamped.
    WorkId,
    "WorkId"
);

digest_newtype!(
    /// `anchor_digest` = SHA-256(full manifest bytes, signatures
    /// included) — the value the OTS/TSA anchors are taken over
    /// (MVP-SPEC.md line 75).
    AnchorDigest,
    "AnchorDigest"
);

/// Compute `work_id` over the **exact** body bytes as received or as just
/// encoded — never over a re-encoding (spec line 74).
///
/// Verify side: [`super::Manifest::body_bytes`]. Seal side:
/// [`super::body::encode_body`]'s output.
#[must_use]
pub fn work_id(body_bytes: &[u8]) -> WorkId {
    WorkId::from_bytes(Sha256::digest(body_bytes).into())
}

/// Compute `anchor_digest` over the full **plaintext** manifest envelope
/// bytes, signatures included (spec lines 75, 98: bytes anchored ≠ bytes
/// stored — the network copy is `k_m`-encrypted).
///
/// Verify side: [`super::Manifest::encoded_bytes`], or the bundle's
/// embedded manifest bytes. Seal side:
/// [`super::encode_envelope`]'s output.
#[must_use]
pub fn anchor_digest(manifest_bytes: &[u8]) -> AnchorDigest {
    AnchorDigest::from_bytes(Sha256::digest(manifest_bytes).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both are plain SHA-256 of their input — no prefix, no tag, no
    /// length framing (the property the domain-tag note relies on).
    #[test]
    fn digests_are_bare_sha256_of_their_input() {
        let input: &[u8] = b"antseal";
        let expected: [u8; 32] = Sha256::digest(input).into();
        assert_eq!(work_id(input).as_bytes(), &expected);
        assert_eq!(anchor_digest(input).as_bytes(), &expected);
    }

    /// The empty-input digest, pinned against the published SHA-256 test
    /// vector — an independent check that no framing sneaks in.
    #[test]
    fn empty_input_matches_the_published_sha256_vector() {
        const E3B0: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(work_id(&[]).to_string(), E3B0);
        assert_eq!(anchor_digest(&[]).to_string(), E3B0);
    }

    /// `Display` is lowercase hex, 64 characters, and `to_hex` agrees.
    #[test]
    fn display_is_lowercase_hex() {
        let id = WorkId::from_bytes([0xAB; 32]);
        let rendered = id.to_string();
        assert_eq!(rendered.len(), 64);
        assert_eq!(rendered, "ab".repeat(32));
        assert_eq!(id.to_hex(), rendered);
        assert!(
            rendered
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
    }

    /// `Debug` names which digest it is, so the two can never be
    /// confused in a log line or an assertion failure.
    #[test]
    fn debug_names_the_digest_kind() {
        assert!(format!("{:?}", WorkId::from_bytes([0; 32])).starts_with("WorkId("));
        assert!(format!("{:?}", AnchorDigest::from_bytes([0; 32])).starts_with("AnchorDigest("));
    }

    /// The domain-tag non-collision argument, executed **with its
    /// counterexample** (F41). The separation holds because both
    /// pre-images are CBOR *maps*; it does **not** hold for canonical
    /// items in general, and this test's predecessor asserted that false
    /// universal over three cherry-picked non-`uint` items.
    #[test]
    fn pre_images_are_maps_whose_heads_clear_the_tag_range() {
        use crate::codec::check_canonical;
        use crate::crypto::domain::{
            MAX_DOMAIN_TAG, TAG_CANON_COMMIT, TAG_FINE_TREE_LEAF, TAG_FINE_TREE_NODE,
            TAG_GGM_SALT_CHILD, TAG_PATH_COMMIT, TAG_RAW_COMMIT, TAG_UNIT_COMMIT,
        };
        use crate::manifest::fixtures;

        for tag in [
            TAG_FINE_TREE_LEAF,
            TAG_FINE_TREE_NODE,
            TAG_UNIT_COMMIT,
            TAG_RAW_COMMIT,
            TAG_CANON_COMMIT,
            TAG_PATH_COMMIT,
            TAG_GGM_SALT_CHILD,
        ] {
            assert!(tag <= MAX_DOMAIN_TAG, "the registry occupies 0x00..=0x06");
            // A byte in 0x00..=0x06 read as a CBOR head is major type 0
            // (unsigned integer) with an immediate argument — a bare
            // integer, which is not a manifest and not an envelope.
            assert_eq!(tag >> 5, 0, "tag bytes are major-type-0 heads");
        }

        // The planted counterexample: the canonical encoding of the
        // integer 0 is the single byte 0x00, an admitted canonical item
        // that *is* TAG_FINE_TREE_LEAF. So "no canonical v1 item can
        // start with a domain-tag byte" is false, and the argument below
        // must not — and does not — rest on it.
        assert_eq!(TAG_FINE_TREE_LEAF, 0x00);
        check_canonical(&[TAG_FINE_TREE_LEAF])
            .expect("uint 0 is a canonical item, first byte in the tag range");

        // What is true: the pre-images of `work_id` (body bytes) and
        // `anchor_digest` (envelope bytes) are canonical CBOR maps, and
        // every canonical map head byte is >= 0xa0 > MAX_DOMAIN_TAG.
        // Checked on real sealed fixtures, not on hand-picked minima.
        const { assert!(0xa0 > MAX_DOMAIN_TAG) };
        let sealed = fixtures::text_with_mirror_manifest();
        for (name, bytes) in [
            (
                "envelope (anchor_digest pre-image)",
                sealed.envelope.as_slice(),
            ),
            ("body (work_id pre-image)", sealed.body.as_slice()),
        ] {
            let head = *bytes.first().expect("fixture is non-empty");
            assert_eq!(head >> 5, 5, "{name} must start with a map head");
            assert!(
                head > MAX_DOMAIN_TAG,
                "{name} head 0x{head:02x} must clear the tag range"
            );
        }
        // Today's exact shapes: {0: body, 1: signatures} and the 8-key v1
        // body. An additive v1.x key would move these to 0xa3/0xa9 — still
        // map heads — so the two asserts above are the load-bearing ones.
        assert_eq!(sealed.envelope[0], 0xa2);
        assert_eq!(sealed.body[0], 0xa8);
    }
}
