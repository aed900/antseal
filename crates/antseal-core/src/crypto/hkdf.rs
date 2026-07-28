//! HKDF-SHA256 derivation from the master secret `W` with the **frozen label
//! registry** and the **injective info encoding** (MVP-SPEC.md lines 76–77,
//! 89, 91, 94–98; tasks/C.md C2).
//!
//! Normative construction (spec line 77):
//!
//! ```text
//! HKDF-SHA256(W, label, id):  salt = empty,  IKM = W,
//!                             info = u8(len(label)) ‖ label ‖ LE64(id)
//! ```
//!
//! The length prefix makes the `(label, id) → info` map injective **by
//! construction** — not by the accident that the current labels happen to be
//! prefix-free — so any future label can be added safely. Injectivity is the
//! security-critical property: distinct info ⇒ independent PRF outputs ⇒
//! keys and salts of different roles never collide. Calls with no natural id
//! use the reserved sentinel [`SENTINEL_ID`].
//!
//! # Frozen label registry
//!
//! | label            | output | id domain  | consumer                          |
//! |------------------|--------|------------|-----------------------------------|
//! | `"unit-key"`     | 32 B   | `unit_id`  | unit AEAD key `k_u` (C9; line 91) |
//! | `"unit-salt"`    | 16 B   | `unit_id`  | `unit_commit` salt (C6; line 94)  |
//! | `"path-salt"`    | 16 B   | `file_id`  | `path_commit` salt (C6; line 95)  |
//! | `"file-salt"`    | 16 B   | `file_id`  | `raw_commit`/`canon_commit` salt (C6; line 95) |
//! | `"fine-seed"`    | 32 B   | `file_id`  | GGM salt-tree root `s_root` (G; line 96) |
//! | `"sig-ed25519"`  | 32 B   | sentinel   | Ed25519 signing seed (C12; line 97) |
//! | `"sig-mldsa65"`  | 32 B   | sentinel   | ML-DSA-65 seed ξ (C13; line 97)   |
//! | `"manifest-key"` | 32 B   | sentinel   | manifest AEAD key `k_m` (C10; line 98) |
//!
//! The registry is **frozen**: adding a label is a format event. The M0
//! golden test (spec line 153) asserts all registered infos are pairwise
//! distinct; `testdata/vectors/hkdf/` pins the derivation outputs.
//!
//! # Only typed derivation — no free-form labels
//!
//! The public derivation API is exactly the `derive_*` functions below, one
//! per registry entry, so passing the wrong id kind ([`UnitId`] vs
//! [`FileId`]) or expecting the wrong output length
//! ([`Salt16`] vs [`Key32`]/[`Seed32`]) is unrepresentable. No public API
//! accepts a label string; the registry is the only path.
//!
//! # Input and disclosure shapes (C5/C7)
//!
//! `W` is taken as the borrowed [`MasterSecretRef`]; the owning, zeroizing
//! [`crate::crypto::secrets::MasterSecret`] borrows into it via
//! `secret_ref()` (C5). [`derive_file_salt`] returns the **opaque**
//! [`FileSalt`] — no byte accessor — because `file_salt` bytes may be
//! disclosed only through
//! [`crate::crypto::disclosure::FullFileRevealDisclosure`] (C7; spec
//! line 95). Intermediate OKM buffers are wiped before return (C21).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use super::material::{FileSalt, Key32, MasterSecretRef, Salt16, Seed32};

/// Reserved sentinel id `0xFFFFFFFFFFFFFFFF` for derivations with no natural
/// id (spec line 77): the `"sig-ed25519"`, `"sig-mldsa65"` and
/// `"manifest-key"` registry entries. Encodes as eight `0xFF` bytes under
/// [`le64`].
pub const SENTINEL_ID: u64 = u64::MAX;

/// Encode an id as the spec's LE64 (spec line 76: every label concatenation
/// is `ASCII-label ‖ LE64(id)`). The shared helper for every LE64 in the
/// codebase — HKDF infos here, AEAD AAD `seal_id ‖ LE64(unit_id)` (C9),
/// fine-tree leaf preimages `LE64(i)` (G).
#[must_use]
pub const fn le64(id: u64) -> [u8; 8] {
    id.to_le_bytes()
}

/// Work-global unit ordinal in manifest order (spec line 76). Deliberately
/// work-global, not file-scoped: file-scoped numbering would silently derive
/// identical keys/salts across files. F's manifest schema adopts this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnitId(pub u64);

/// Index into the manifest file table (spec line 76). F's manifest schema
/// adopts this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub u64);

/// Which id domain a registry label takes (registry table in module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdDomain {
    /// The label is derived per unit, keyed by [`UnitId`].
    UnitId,
    /// The label is derived per file, keyed by [`FileId`].
    FileId,
    /// The label has no natural id and uses [`SENTINEL_ID`].
    Sentinel,
}

/// The frozen HKDF label registry (module docs). Public for introspection —
/// golden tests and F's schema checks enumerate it — but **not** a
/// derivation entry point: derivation goes only through the typed
/// `derive_*` functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Label {
    /// `"unit-key"` — 32 B unit AEAD key `k_u` (spec line 91).
    UnitKey,
    /// `"unit-salt"` — 16 B `unit_commit` salt (spec line 94).
    UnitSalt,
    /// `"path-salt"` — 16 B `path_commit` salt (spec line 95).
    PathSalt,
    /// `"file-salt"` — 16 B `raw_commit`/`canon_commit` salt (spec line 95).
    FileSalt,
    /// `"fine-seed"` — 32 B GGM salt-tree root `s_root` (spec line 96).
    FineSeed,
    /// `"sig-ed25519"` — 32 B Ed25519 signing seed (spec line 97).
    SigEd25519,
    /// `"sig-mldsa65"` — 32 B ML-DSA-65 seed ξ (spec line 97).
    SigMlDsa65,
    /// `"manifest-key"` — 32 B manifest AEAD key `k_m` (spec line 98).
    ManifestKey,
}

impl Label {
    /// Every registered label, in registry order.
    pub const ALL: [Self; 8] = [
        Self::UnitKey,
        Self::UnitSalt,
        Self::PathSalt,
        Self::FileSalt,
        Self::FineSeed,
        Self::SigEd25519,
        Self::SigMlDsa65,
        Self::ManifestKey,
    ];

    /// The frozen ASCII label string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnitKey => "unit-key",
            Self::UnitSalt => "unit-salt",
            Self::PathSalt => "path-salt",
            Self::FileSalt => "file-salt",
            Self::FineSeed => "fine-seed",
            Self::SigEd25519 => "sig-ed25519",
            Self::SigMlDsa65 => "sig-mldsa65",
            Self::ManifestKey => "manifest-key",
        }
    }

    /// Registered output length in bytes (16 or 32; enforced on the
    /// derivation API by the [`Salt16`]/[`Key32`]/[`Seed32`] return types).
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::UnitSalt | Self::PathSalt | Self::FileSalt => Salt16::LEN,
            Self::UnitKey
            | Self::FineSeed
            | Self::SigEd25519
            | Self::SigMlDsa65
            | Self::ManifestKey => Key32::LEN,
        }
    }

    /// Which id domain this label takes.
    #[must_use]
    pub const fn id_domain(self) -> IdDomain {
        match self {
            Self::UnitKey | Self::UnitSalt => IdDomain::UnitId,
            Self::PathSalt | Self::FileSalt | Self::FineSeed => IdDomain::FileId,
            Self::SigEd25519 | Self::SigMlDsa65 | Self::ManifestKey => IdDomain::Sentinel,
        }
    }

    /// The encoded info bytes `u8(len(label)) ‖ label ‖ LE64(id)` for this
    /// label (spec line 77). Introspection for golden tests and F; not a
    /// derivation entry point.
    #[must_use]
    pub fn info_bytes(self, id: u64) -> Vec<u8> {
        encode_info(self.as_str().as_bytes(), id)
    }
}

/// Encode `info = u8(len(label)) ‖ label ‖ LE64(id)` (spec line 77).
///
/// Crate-private: the only public path to an info is a registered [`Label`]
/// (no free-form label API). The generic form exists so the structural-
/// injectivity property test can exercise arbitrary labels up to 255 bytes.
///
/// Contract: `label.len() <= 255` (all registry labels are ≤ 12 bytes; the
/// length prefix is a single byte by construction).
pub(crate) fn encode_info(label: &[u8], id: u64) -> Vec<u8> {
    let len = u8::try_from(label.len()).expect("HKDF label must be at most 255 bytes");
    let mut info = Vec::with_capacity(1 + label.len() + 8);
    info.push(len);
    info.extend_from_slice(label);
    info.extend_from_slice(&le64(id));
    info
}

/// HKDF-SHA256 with the spec's parameters: salt = empty, IKM = `W`,
/// info per [`encode_info`] (spec line 77), expanded into `okm`.
///
/// RFC 5869 note: an absent salt is defined as `HashLen` zero bytes; for
/// HMAC-SHA256 an empty salt key is zero-padded to the block size, so
/// "empty" and "HashLen zeros" coincide — asserted against an
/// independently-computed raw HMAC reference in this module's tests.
fn hkdf_expand(w: MasterSecretRef<'_>, label: Label, id: u64, okm: &mut [u8]) {
    debug_assert_eq!(
        okm.len(),
        label.output_len(),
        "registry output length mismatch"
    );
    let info = label.info_bytes(id);
    let hk = Hkdf::<Sha256>::new(Some(&[]), w.as_bytes());
    // Registry output lengths are 16 or 32 bytes — far below the RFC 5869
    // ceiling of 255 * HashLen — so expansion cannot fail.
    hk.expand(&info, okm)
        .expect("registry output length is within the RFC 5869 bound");
}

fn derive_key32(w: MasterSecretRef<'_>, label: Label, id: u64) -> Key32 {
    let mut okm = [0u8; Key32::LEN];
    hkdf_expand(w, label, id, &mut okm);
    let out = Key32::from_bytes(okm);
    okm.zeroize();
    out
}

fn derive_seed32(w: MasterSecretRef<'_>, label: Label, id: u64) -> Seed32 {
    let mut okm = [0u8; Seed32::LEN];
    hkdf_expand(w, label, id, &mut okm);
    let out = Seed32::from_bytes(okm);
    okm.zeroize();
    out
}

fn derive_salt16(w: MasterSecretRef<'_>, label: Label, id: u64) -> Salt16 {
    let mut okm = [0u8; Salt16::LEN];
    hkdf_expand(w, label, id, &mut okm);
    let out = Salt16::from_bytes(okm);
    okm.zeroize();
    out
}

/// `k_u = HKDF(W, "unit-key", unit_id)` — the 32-byte XChaCha20-Poly1305
/// key for one unit (spec line 91; consumed by C9).
#[must_use]
pub fn derive_unit_key(w: MasterSecretRef<'_>, unit_id: UnitId) -> Key32 {
    derive_key32(w, Label::UnitKey, unit_id.0)
}

/// `unit_salt = HKDF(W, "unit-salt", unit_id)` — the 16-byte salt of
/// `unit_commit` (spec line 94; consumed by C6).
#[must_use]
pub fn derive_unit_salt(w: MasterSecretRef<'_>, unit_id: UnitId) -> Salt16 {
    derive_salt16(w, Label::UnitSalt, unit_id.0)
}

/// `path_salt = HKDF(W, "path-salt", file_id)` — the 16-byte salt of
/// `path_commit`, independent of [`derive_file_salt`] so disclosing a path
/// never compromises content commitments (spec line 95; consumed by C6).
#[must_use]
pub fn derive_path_salt(w: MasterSecretRef<'_>, file_id: FileId) -> Salt16 {
    derive_salt16(w, Label::PathSalt, file_id.0)
}

/// `file_salt = HKDF(W, "file-salt", file_id)` — the 16-byte salt of
/// `raw_commit`/`canon_commit`, disclosed only on a full-file reveal (spec
/// line 95; consumed by C6). Returns the **opaque** [`FileSalt`]: the C7
/// disclosure rule is enforced by the type — its bytes are publicly
/// reachable only through
/// [`crate::crypto::disclosure::FullFileRevealDisclosure`], never from this
/// derivation API.
#[must_use]
pub fn derive_file_salt(w: MasterSecretRef<'_>, file_id: FileId) -> FileSalt {
    FileSalt::from_derived(derive_salt16(w, Label::FileSalt, file_id.0))
}

/// `s_root = HKDF(W, "fine-seed", file_id)` — the 32-byte GGM salt-tree
/// root (spec line 96; consumed by G).
#[must_use]
pub fn derive_fine_seed(w: MasterSecretRef<'_>, file_id: FileId) -> Seed32 {
    derive_seed32(w, Label::FineSeed, file_id.0)
}

/// Ed25519 signing seed = `HKDF(W, "sig-ed25519", sentinel)` (spec line 97;
/// consumed by C12).
#[must_use]
pub fn derive_sig_ed25519_seed(w: MasterSecretRef<'_>) -> Seed32 {
    derive_seed32(w, Label::SigEd25519, SENTINEL_ID)
}

/// ML-DSA-65 seed ξ = `HKDF(W, "sig-mldsa65", sentinel)` (spec line 97;
/// FIPS 204 keygen expands the 32-byte seed; consumed by C13).
#[must_use]
pub fn derive_sig_mldsa65_seed(w: MasterSecretRef<'_>) -> Seed32 {
    derive_seed32(w, Label::SigMlDsa65, SENTINEL_ID)
}

/// `k_m = HKDF(W, "manifest-key")` — the 32-byte manifest AEAD key, sentinel
/// id (spec line 98; consumed by C10).
#[must_use]
pub fn derive_manifest_key(w: MasterSecretRef<'_>) -> Key32 {
    derive_key32(w, Label::ManifestKey, SENTINEL_ID)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    // Property tests need the proptest-bearing `test-util` tier, which the
    // wasm32 `--lib` test build deliberately does not enable (P14,
    // docs/wasm-toolchain.md). Everything else in this module runs on both.
    #[cfg(feature = "test-util")]
    use proptest::prelude::*;
    #[cfg(feature = "test-util")]
    use proptest::test_runner::RngSeed;

    /// Fixed, public, NON-SECRET test master secret (bytes 0x00..0x1F) —
    /// the same fixture `testdata/vectors/hkdf/` derives from. Never a real
    /// secret (project rule 6).
    const TEST_W: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];

    fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }

    /// Independently-computed RFC 5869 HKDF-SHA256 (raw HMAC extract +
    /// expand), the reference the crate-backed derivation must match.
    fn reference_hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
        // Extract: PRK = HMAC-SHA256(salt, IKM).
        let prk = hmac_sha256(salt, ikm);
        // Expand: T(n) = HMAC-SHA256(PRK, T(n-1) ‖ info ‖ n), n from 1.
        let mut okm = Vec::new();
        let mut block: Vec<u8> = Vec::new();
        let mut counter = 1u8;
        while okm.len() < out_len {
            let mut message = block.clone();
            message.extend_from_slice(info);
            message.push(counter);
            block = hmac_sha256(&prk, &message);
            okm.extend_from_slice(&block);
            counter += 1;
        }
        okm.truncate(out_len);
        okm
    }

    /// Derive through the public typed API, dispatching per label. Sentinel
    /// labels require `id == SENTINEL_ID`.
    fn derive_via_typed_api(w: MasterSecretRef<'_>, label: Label, id: u64) -> Vec<u8> {
        match label {
            Label::UnitKey => derive_unit_key(w, UnitId(id)).into_bytes().to_vec(),
            Label::UnitSalt => derive_unit_salt(w, UnitId(id)).into_bytes().to_vec(),
            Label::PathSalt => derive_path_salt(w, FileId(id)).into_bytes().to_vec(),
            // In-module test: crate-private preimage access. Public byte
            // access to a derived file_salt exists only via
            // `disclosure::FullFileRevealDisclosure` (C7).
            Label::FileSalt => derive_file_salt(w, FileId(id))
                .as_salt()
                .as_bytes()
                .to_vec(),
            Label::FineSeed => derive_fine_seed(w, FileId(id)).into_bytes().to_vec(),
            Label::SigEd25519 => {
                assert_eq!(id, SENTINEL_ID);
                derive_sig_ed25519_seed(w).into_bytes().to_vec()
            }
            Label::SigMlDsa65 => {
                assert_eq!(id, SENTINEL_ID);
                derive_sig_mldsa65_seed(w).into_bytes().to_vec()
            }
            Label::ManifestKey => {
                assert_eq!(id, SENTINEL_ID);
                derive_manifest_key(w).into_bytes().to_vec()
            }
        }
    }

    /// C2 accept: info bytes for a known (label, id) pair match the
    /// hand-computed `u8(len) ‖ label ‖ LE64(id)` fixture.
    #[test]
    fn info_bytes_match_hand_computed_fixture() {
        // "unit-key" (8 bytes), id = 5.
        let expected: [u8; 17] = [
            0x08, // u8(len("unit-key"))
            0x75, 0x6E, 0x69, 0x74, 0x2D, 0x6B, 0x65, 0x79, // "unit-key"
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // LE64(5)
        ];
        assert_eq!(Label::UnitKey.info_bytes(5), expected);

        // "manifest-key" (12 bytes), sentinel id.
        let mut expected_manifest = vec![0x0C];
        expected_manifest.extend_from_slice(b"manifest-key");
        expected_manifest.extend_from_slice(&[0xFF; 8]);
        assert_eq!(
            Label::ManifestKey.info_bytes(SENTINEL_ID),
            expected_manifest
        );
    }

    /// C2 accept: the sentinel encodes as exactly `0xFFFFFFFFFFFFFFFF` LE
    /// (eight 0xFF bytes).
    #[test]
    fn sentinel_encodes_as_eight_ff_bytes() {
        assert_eq!(SENTINEL_ID, 0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(le64(SENTINEL_ID), [0xFF; 8]);
    }

    /// The shared LE64 helper is little-endian (spec line 76).
    #[test]
    fn le64_is_little_endian() {
        assert_eq!(
            le64(0x0123_4567_89AB_CDEF),
            [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]
        );
        assert_eq!(le64(0), [0x00; 8]);
        assert_eq!(le64(1), [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    /// Registry sanity: labels are ASCII, unique, ≤ 255 bytes (single-byte
    /// length prefix), with the frozen 16/32-byte output lengths and id
    /// domains from the module table.
    #[test]
    fn registry_is_frozen_and_consistent() {
        assert_eq!(Label::ALL.len(), 8);
        for (i, label) in Label::ALL.iter().enumerate() {
            let s = label.as_str();
            assert!(s.is_ascii(), "{s}");
            assert!(!s.is_empty() && s.len() <= 255, "{s}");
            assert!(matches!(label.output_len(), 16 | 32), "{s}");
            for other in &Label::ALL[i + 1..] {
                assert_ne!(s, other.as_str());
            }
        }
        let expected: [(&str, usize, IdDomain); 8] = [
            ("unit-key", 32, IdDomain::UnitId),
            ("unit-salt", 16, IdDomain::UnitId),
            ("path-salt", 16, IdDomain::FileId),
            ("file-salt", 16, IdDomain::FileId),
            ("fine-seed", 32, IdDomain::FileId),
            ("sig-ed25519", 32, IdDomain::Sentinel),
            ("sig-mldsa65", 32, IdDomain::Sentinel),
            ("manifest-key", 32, IdDomain::Sentinel),
        ];
        for (label, (name, len, domain)) in Label::ALL.iter().zip(expected) {
            assert_eq!(label.as_str(), name);
            assert_eq!(label.output_len(), len);
            assert_eq!(label.id_domain(), domain);
        }
    }

    /// C2 accept: RFC 5869 empty-salt semantics confirmed against an
    /// independently-computed reference — every typed derivation equals a
    /// raw HMAC-SHA256 extract/expand with salt = empty, and the RFC's
    /// "absent salt = HashLen zeros" convention coincides with the empty
    /// salt for HMAC-SHA256 (zero-padding of short HMAC keys).
    #[test]
    fn matches_raw_hmac_reference_with_empty_salt() {
        let w = MasterSecretRef::from_bytes(&TEST_W);
        for label in Label::ALL {
            let ids: &[u64] = match label.id_domain() {
                IdDomain::Sentinel => &[SENTINEL_ID],
                IdDomain::UnitId | IdDomain::FileId => &[0, 1, u64::MAX - 1],
            };
            for &id in ids {
                let via_api = derive_via_typed_api(w, label, id);
                let via_reference =
                    reference_hkdf_sha256(b"", &TEST_W, &label.info_bytes(id), label.output_len());
                assert_eq!(via_api, via_reference, "{} id={id:#x}", label.as_str());
            }
        }

        // RFC 5869 §2.2: "if not provided, [salt] is set to a string of
        // HashLen zeros". For HMAC-SHA256 the empty key and the 32-zero-byte
        // key both zero-pad to the same 64-byte block key, so PRKs coincide.
        assert_eq!(hmac_sha256(b"", &TEST_W), hmac_sha256(&[0u8; 32], &TEST_W));
        // And the hkdf crate agrees: `None` (absent) and `Some(&[])` (empty)
        // derive identical output.
        let info = Label::UnitKey.info_bytes(7);
        let mut with_none = [0u8; 32];
        let mut with_empty = [0u8; 32];
        Hkdf::<Sha256>::new(None, &TEST_W)
            .expand(&info, &mut with_none)
            .expect("okm within RFC 5869 bound");
        Hkdf::<Sha256>::new(Some(&[]), &TEST_W)
            .expand(&info, &mut with_empty)
            .expect("okm within RFC 5869 bound");
        assert_eq!(with_none, with_empty);
    }

    /// Distinct labels with the same id, and the same label with distinct
    /// ids, derive distinct outputs (PRF independence smoke check on top of
    /// info injectivity).
    #[test]
    fn distinct_roles_derive_distinct_outputs() {
        let w = MasterSecretRef::from_bytes(&TEST_W);
        // Same file_id, different labels: path-salt vs file-salt must differ
        // (spec line 95's two independent per-file salts).
        let path_salt = derive_path_salt(w, FileId(3));
        let file_salt = derive_file_salt(w, FileId(3));
        assert_ne!(path_salt.as_bytes(), file_salt.as_salt().as_bytes());
        // Same label, different ids.
        let key_0 = derive_unit_key(w, UnitId(0));
        let key_1 = derive_unit_key(w, UnitId(1));
        assert_ne!(key_0.as_bytes(), key_1.as_bytes());
    }

    /// C3: structural injectivity of the info encoding — for ANY two pairs
    /// (label, id) ≠ (label′, id′) with labels up to 255 bytes, the encoded
    /// infos differ (spec line 77: injective by construction, not by the
    /// current registry's accident).
    ///
    /// # Why this drives `TestRunner` directly instead of using `proptest!`
    ///
    /// The spec mandates a **≥ 10 000-case floor** here, and a floor that
    /// something else can lower is not a floor. The `proptest!` macro passes
    /// its config through `contextualize_config`, which **overwrites**
    /// `cases` from `PROPTEST_CASES` whenever that variable is set — and the
    /// CI `test` lane sets it to 1024. Declaring `cases: 10_000` inside the
    /// macro therefore ran 1024 cases in CI, silently.
    ///
    /// Note that computing the floor in the config (`max(10_000, …)`) does
    /// **not** fix it either: contextualization happens *after* the config is
    /// built, so it overrides any value the literal computed. Constructing
    /// the runner directly is what makes the floor hold, because
    /// `TestRunner::new` does not re-contextualize.
    #[cfg(feature = "test-util")]
    #[test]
    fn info_encoding_is_structurally_injective() {
        use proptest::test_runner::{Config, TestRunner};

        /// The spec's floor (line 77). Deliberately not overridable.
        const C3_CASE_FLOOR: u32 = 10_000;

        let config = Config {
            cases: C3_CASE_FLOOR,
            rng_seed: RngSeed::Fixed(0xA57E_A1C3),
            ..ProptestConfig::default()
        };
        assert_eq!(
            config.cases, C3_CASE_FLOOR,
            "the C3 case floor must not be overridable by PROPTEST_CASES"
        );

        let strategy = (
            proptest::collection::vec(any::<u8>(), 0..=255),
            proptest::collection::vec(any::<u8>(), 0..=255),
            any::<u64>(),
            any::<u64>(),
        );

        TestRunner::new(config)
            .run(&strategy, |(label_a, label_b, id_a, id_b)| {
                let info_a = encode_info(&label_a, id_a);
                let info_b = encode_info(&label_b, id_b);
                if label_a == label_b && id_a == id_b {
                    prop_assert_eq!(info_a, info_b);
                } else {
                    prop_assert_ne!(info_a, info_b);
                }
                Ok(())
            })
            .expect("info encoding is injective");
    }
}
