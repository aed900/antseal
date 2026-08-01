//! The vault record AEAD (U6, D42 rider): XChaCha20-Poly1305 under the
//! single vault key, with **every** encryption binding the serialized KDF
//! header plus the record's identity as AAD.
//!
//! ```text
//! key       = the 32-byte KDF output (vault/kdf.rs — the recorded key
//!             schedule: one vault key, no per-record sub-keys)
//! nonce     = 24 random bytes, drawn HERE, fresh per record write
//! AAD       = header_bytes ‖ identity.aad_suffix()
//! blob      = nonce ‖ ciphertext(plaintext ‖ tag)
//! ```
//!
//! # Why the AAD carries the whole header (D42 rider 1)
//!
//! `header_bytes` are the exact bytes [`crate::vault::header::VaultHeader::encode`]
//! produces — magic, version envelope, KDF block (algorithm + parameters +
//! salt), wrap mode. Binding them into every record makes any header edit
//! an authentication failure on every record, not just a monolith: a
//! parameter downgrade that survives the D40 §3 caps, a wrap-mode flip, a
//! salt substitution — all fail decrypt even in the hypothetical where the
//! derived key were somehow unchanged.
//!
//! # Why the AAD carries the record identity (D42 rider 2 — splice
//! resistance)
//!
//! The identity suffix is a canonical-CBOR array naming the record class
//! and its keys ([`RecordIdentity`]), so a valid AEAD blob moved between
//! slots of one vault — another work's slot, another journal entry,
//! another record class — fails authentication instead of being silently
//! accepted where it does not belong. Cross-vault splices already fail on
//! the header half (each vault has its own salt, hence its own header
//! bytes *and* its own key). Injectivity: within one vault the header half
//! is constant, and canonical CBOR encoding of the identity array is
//! injective over identities, so distinct identities never collide into
//! one AAD.
//!
//! Honest limit (D42 rider 3, recorded): whole-vault rollback — restoring
//! an older copy of the entire directory — is out of scope; no offline
//! scheme detects it.
//!
//! # Nonce discipline (the C9/C10 house pattern)
//!
//! No public API accepts a caller-supplied encryption nonce:
//! [`seal_record`] draws 24 fresh random bytes from the injected CSPRNG on
//! every call. XChaCha20's 192-bit nonce makes random collision
//! negligible, which is the entire separation between two writes of the
//! same record slot under the one vault key.
//!
//! # AEAD is confidentiality-only
//!
//! XChaCha20-Poly1305 is not key-committing. As with the unit/manifest
//! AEADs, no verdict-bearing check relies on a vault ciphertext decrypting
//! to a unique plaintext — decrypt-success here gates only "this vault,
//! this slot, this key", and the record *content* is trusted because the
//! vault key is secret, not because decryption succeeded under it.

use antseal_core::codec::encode_item;
use antseal_core::crypto::secrets::{SealId, SecretBuf};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::TryCryptoRng;
use thiserror::Error;

use super::kdf::VaultKey;
use crate::error::CliError;

/// Nonce length (XChaCha20-Poly1305).
pub const RECORD_NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const RECORD_TAG_LEN: usize = 16;
/// Smallest well-formed record blob: nonce + tag over an empty plaintext.
pub const MIN_RECORD_BLOB_LEN: usize = RECORD_NONCE_LEN + RECORD_TAG_LEN;

/// Record-class ids (the wire values inside the AAD identity array).
/// Registry — growing it is a deliberate event, ids are never reused:
/// `0` key-check (U6) · `1` wallet (reserved, U10) · `2` work meta (U9) ·
/// `3` journal entry (U9) · `4` receipt (U9) · `5` anchor artifact (U9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
enum RecordClass {
    KeyCheck = 0,
    Wallet = 1,
    WorkMeta = 2,
    JournalEntry = 3,
    Receipt = 4,
    Anchor = 5,
}

/// The identity every record AEAD binds (D42 rider 2). One variant per
/// record class; the per-class keys are exactly the ones that place the
/// record in the store, so "same bytes, different slot" is always a
/// different AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordIdentity<'a> {
    /// The vault key-check record (`store/check`, U6): one per vault.
    KeyCheck,
    /// The wallet record (`store/wallet`) — id reserved here, record
    /// landed by U10 under its own sub-key.
    Wallet,
    /// A work's meta record (`store/works/<seal-id>/meta`, U9).
    WorkMeta {
        /// The work's store key.
        seal_id: &'a SealId,
    },
    /// One journal entry (`store/works/<seal-id>/journal/<entry>`, U9).
    JournalEntry {
        /// The work's store key.
        seal_id: &'a SealId,
        /// The entry key (content contract S10's; typically the unit id).
        entry: u64,
    },
    /// The journaled payment receipt (`store/works/<seal-id>/receipt`).
    Receipt {
        /// The work's store key.
        seal_id: &'a SealId,
    },
    /// One anchor-artifact slot (`store/works/<seal-id>/anchors/<slot>`).
    Anchor {
        /// The work's store key.
        seal_id: &'a SealId,
        /// The slot name (validated by the store layer).
        slot: &'a str,
    },
}

impl RecordIdentity<'_> {
    /// The canonical-CBOR identity suffix appended to the header bytes to
    /// form the record AAD. Arrays of differing arity/content are
    /// injective under canonical CBOR, so no two identities share a
    /// suffix.
    fn aad_suffix(&self) -> Result<Vec<u8>, CipherError> {
        let bytes = match *self {
            RecordIdentity::KeyCheck => {
                encode_item(|e| e.array(|a| a.item(|e| e.u64(RecordClass::KeyCheck as u64))))
            }
            RecordIdentity::Wallet => {
                encode_item(|e| e.array(|a| a.item(|e| e.u64(RecordClass::Wallet as u64))))
            }
            RecordIdentity::WorkMeta { seal_id } => encode_item(|e| {
                e.array(|a| {
                    a.item(|e| e.u64(RecordClass::WorkMeta as u64))?;
                    a.item(|e| e.bytes(seal_id.as_bytes()))
                })
            }),
            RecordIdentity::JournalEntry { seal_id, entry } => encode_item(|e| {
                e.array(|a| {
                    a.item(|e| e.u64(RecordClass::JournalEntry as u64))?;
                    a.item(|e| e.bytes(seal_id.as_bytes()))?;
                    a.item(|e| e.u64(entry))
                })
            }),
            RecordIdentity::Receipt { seal_id } => encode_item(|e| {
                e.array(|a| {
                    a.item(|e| e.u64(RecordClass::Receipt as u64))?;
                    a.item(|e| e.bytes(seal_id.as_bytes()))
                })
            }),
            RecordIdentity::Anchor { seal_id, slot } => encode_item(|e| {
                e.array(|a| {
                    a.item(|e| e.u64(RecordClass::Anchor as u64))?;
                    a.item(|e| e.bytes(seal_id.as_bytes()))?;
                    a.item(|e| e.bytes(slot.as_bytes()))
                })
            }),
        };
        bytes.map_err(|_| CipherError::AadEncode)
    }

    /// The full AAD: serialized KDF header ‖ identity suffix.
    fn aad(&self, header_bytes: &[u8]) -> Result<Vec<u8>, CipherError> {
        let suffix = self.aad_suffix()?;
        let mut aad = Vec::with_capacity(header_bytes.len() + suffix.len());
        aad.extend_from_slice(header_bytes);
        aad.extend_from_slice(&suffix);
        Ok(aad)
    }
}

/// Vault AEAD failures. Decrypt failure is deliberately opaque (wrong
/// key, tampered blob, wrong slot, and edited header are one class — the
/// AEAD cannot and must not say which).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CipherError {
    /// Authentication failed: wrong passphrase-derived key, modified
    /// blob/header, or a record spliced into the wrong slot.
    #[error("vault record failed authentication")]
    AuthFailure,

    /// Blob shorter than nonce + tag (structurally not a record).
    #[error("vault record blob is {len} bytes, below the {MIN_RECORD_BLOB_LEN}-byte minimum")]
    BlobTooShort { len: usize },

    /// The injected CSPRNG failed while drawing the nonce.
    #[error("the OS random source failed while drawing a record nonce")]
    RngFailure,

    /// Identity/AAD encode failure (unreachable for the fixed shapes;
    /// kept total — library discipline).
    #[error("could not encode the record identity AAD")]
    AadEncode,

    /// Encrypt-side cipher failure (unreachable for in-memory buffers;
    /// kept total).
    #[error("vault record encryption failed")]
    EncryptFailure,
}

impl From<CipherError> for CliError {
    fn from(err: CipherError) -> Self {
        match err {
            // A short blob is corrupt-store; collapses with tamper (U6
            // "insofar as safe").
            CipherError::AuthFailure | CipherError::BlobTooShort { .. } => {
                CliError::VaultAuthFailure
            }
            CipherError::RngFailure => CliError::Internal {
                detail: "OS random source failed while drawing a record nonce".to_owned(),
            },
            CipherError::AadEncode | CipherError::EncryptFailure => CliError::Internal {
                detail: "vault record encryption failed on a fixed-shape input".to_owned(),
            },
        }
    }
}

/// Encrypt one record: fresh random nonce, AAD = header ‖ identity.
/// Returns the on-disk blob `nonce ‖ ciphertext`.
///
/// # Errors
///
/// [`CipherError::RngFailure`] when the injected CSPRNG fails; the
/// remaining classes are unreachable-kept-total.
pub fn seal_record<R: TryCryptoRng + ?Sized>(
    key: &VaultKey,
    header_bytes: &[u8],
    identity: RecordIdentity<'_>,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, CipherError> {
    let mut nonce = [0u8; RECORD_NONCE_LEN];
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| CipherError::RngFailure)?;
    let aad = identity.aad(header_bytes)?;
    // 32 bytes is the XChaCha20-Poly1305 key size, so `new_from_slice`
    // cannot fail (same reasoning as C9's unit cipher).
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CipherError::EncryptFailure)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CipherError::EncryptFailure)?;
    let mut blob = Vec::with_capacity(RECORD_NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt one record blob under the same key/header/identity that sealed
/// it. Returns the plaintext in a zeroizing buffer — meta records carry
/// `W`-class material, so every record plaintext is treated as secret by
/// default (journal entries, whose content is public-destined AEAD
/// ciphertext, simply pay a free wipe).
///
/// # Errors
///
/// [`CipherError::BlobTooShort`] for structurally impossible blobs;
/// [`CipherError::AuthFailure`] for everything the AEAD rejects.
pub fn open_record(
    key: &VaultKey,
    header_bytes: &[u8],
    identity: RecordIdentity<'_>,
    blob: &[u8],
) -> Result<SecretBuf, CipherError> {
    if blob.len() < MIN_RECORD_BLOB_LEN {
        return Err(CipherError::BlobTooShort { len: blob.len() });
    }
    let (nonce, ciphertext) = blob.split_at(RECORD_NONCE_LEN);
    // Sized by the split above; the conversion cannot fail.
    let nonce_bytes: [u8; RECORD_NONCE_LEN] =
        nonce.try_into().map_err(|_| CipherError::AuthFailure)?;
    let aad = identity.aad(header_bytes)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| CipherError::AuthFailure)?;
    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CipherError::AuthFailure)?;
    Ok(SecretBuf::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    /// Fixed, public, NON-SECRET test material (project rule 6).
    const TEST_SEED: [u8; 32] = [0x42u8; 32];

    fn test_key() -> VaultKey {
        VaultKey::from_bytes([0x21u8; 32])
    }

    fn seal_a() -> SealId {
        SealId::from_bytes([0xA0u8; 16])
    }

    fn seal_b() -> SealId {
        SealId::from_bytes([0xB0u8; 16])
    }

    #[test]
    fn round_trip_and_fresh_nonces() {
        let mut rng = ChaCha20Rng::from_seed(TEST_SEED);
        let key = test_key();
        let header = b"header-bytes-fixture";
        let id = seal_a();
        let identity = RecordIdentity::WorkMeta { seal_id: &id };
        let blob1 = seal_record(&key, header, identity, b"payload", &mut rng).expect("seal");
        let blob2 = seal_record(&key, header, identity, b"payload", &mut rng).expect("seal");
        assert_ne!(blob1, blob2, "fresh nonce per write");
        let pt = open_record(&key, header, identity, &blob1).expect("open");
        assert_eq!(pt.as_bytes(), b"payload");
    }

    /// The splice matrix at the cipher layer: every identity axis (class,
    /// work, entry key, slot name) and the header itself each flip the
    /// AAD, so the same blob fails authentication anywhere but its own
    /// slot. (The file-level splice tests live with the U9 store suite.)
    #[test]
    fn identity_and_header_axes_all_bind() {
        let mut rng = ChaCha20Rng::from_seed(TEST_SEED);
        let key = test_key();
        let header = b"header-bytes-fixture";
        let (a, b) = (seal_a(), seal_b());
        let sealed_under = RecordIdentity::JournalEntry {
            seal_id: &a,
            entry: 0,
        };
        let blob = seal_record(&key, header, sealed_under, b"staged", &mut rng).expect("seal");

        let wrong_slots = [
            // Different work, same class + entry.
            RecordIdentity::JournalEntry {
                seal_id: &b,
                entry: 0,
            },
            // Same work, different entry key.
            RecordIdentity::JournalEntry {
                seal_id: &a,
                entry: 1,
            },
            // Same work, different class.
            RecordIdentity::Receipt { seal_id: &a },
            RecordIdentity::WorkMeta { seal_id: &a },
            // Class with no work key at all.
            RecordIdentity::KeyCheck,
        ];
        for wrong in wrong_slots {
            assert_eq!(
                open_record(&key, header, wrong, &blob).expect_err("must fail"),
                CipherError::AuthFailure,
                "{wrong:?}"
            );
        }

        // The pure-AAD header direction: identical key, identical
        // identity, edited header bytes (e.g. a wrap-mode flip that does
        // not change the KDF inputs) — authentication failure.
        assert_eq!(
            open_record(&key, b"header-bytes-EDITED!", sealed_under, &blob).expect_err("must fail"),
            CipherError::AuthFailure
        );

        // And its own slot still opens (the matrix is falsifiable).
        assert!(open_record(&key, header, sealed_under, &blob).is_ok());
    }

    #[test]
    fn tampered_blob_and_short_blob_fail() {
        let mut rng = ChaCha20Rng::from_seed(TEST_SEED);
        let key = test_key();
        let identity = RecordIdentity::KeyCheck;
        let mut blob = seal_record(&key, b"h", identity, b"check", &mut rng).expect("seal");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(
            open_record(&key, b"h", identity, &blob).expect_err("must fail"),
            CipherError::AuthFailure
        );
        assert_eq!(
            open_record(&key, b"h", identity, &blob[..MIN_RECORD_BLOB_LEN - 1])
                .expect_err("must fail"),
            CipherError::BlobTooShort {
                len: MIN_RECORD_BLOB_LEN - 1
            }
        );
    }

    /// Identity suffixes are pairwise distinct (the injectivity claim the
    /// module docs make, executed over every class).
    #[test]
    fn identity_suffixes_are_pairwise_distinct() {
        let a = seal_a();
        let ids = [
            RecordIdentity::KeyCheck,
            RecordIdentity::Wallet,
            RecordIdentity::WorkMeta { seal_id: &a },
            RecordIdentity::JournalEntry {
                seal_id: &a,
                entry: 0,
            },
            RecordIdentity::Receipt { seal_id: &a },
            RecordIdentity::Anchor {
                seal_id: &a,
                slot: "ots-pending",
            },
        ];
        let suffixes: Vec<Vec<u8>> = ids
            .iter()
            .map(|i| i.aad_suffix().expect("suffix"))
            .collect();
        for i in 0..suffixes.len() {
            for j in (i + 1)..suffixes.len() {
                assert_ne!(suffixes[i], suffixes[j], "{:?} vs {:?}", ids[i], ids[j]);
            }
        }
    }
}
