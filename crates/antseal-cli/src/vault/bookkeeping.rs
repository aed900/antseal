//! The vault-global bookkeeping record (U34) — facts about *the vault*
//! rather than about any work — and the loss/theft copy those facts
//! govern (U18).
//!
//! # Why this slot had to exist before U18 could be honest
//!
//! MVP-SPEC.md line 143 asks `seal` to nag, after the first seal in a
//! vault with no backup, that the user run `vault export` — and to stop
//! nagging once they have. Until this module the store had exactly two
//! singletons (`store/check`, `store/wallet`) and no place at all to
//! record a vault-scope fact, so U18 could only have shipped a nag that
//! fires forever. A warning that cannot be satisfied is worse than no
//! warning: it teaches the reader that antseal's warnings are noise, and
//! the one warning that must never be skimmed is the permanence gate two
//! screens later.
//!
//! # Shape
//!
//! ```text
//! store/bookkeeping := nonce ‖ AEAD_vaultkey(record, AAD = header ‖ [6])
//! record (v1)       := canonical CBOR map { 0: version, 1: exports,
//!                                           2: last_export_unix_secs? }
//! ```
//!
//! Inside the AEAD, per D42 (bookkeeping is enumerated as inside), and
//! bound to [`RecordIdentity::Bookkeeping`] so the D42 splice matrix
//! extends by one row: a blob moved into or out of this slot fails
//! authentication rather than being read as a different record class.
//!
//! **Absent is a state, not a failure.** Every vault created before this
//! record existed has no such file, and so does every freshly-created
//! one: [`load`] returns [`Bookkeeping::default`] for a missing slot. Only
//! a *present but unreadable* record is an error — that is tamper or
//! corruption, and the vault-auth class already covers it.
//!
//! # What it deliberately does not hold
//!
//! No secret material (project rule 6): a count and a timestamp. It is
//! encrypted anyway because D42 puts everything that is not the header,
//! the lockfile or `config.toml` inside the AEAD — "how often has this
//! person backed up, and when" is metadata about a user, and the vault
//! does not leak metadata just because it is not key material.

use rand_core::TryCryptoRng;

use antseal_core::codec::{CanonicalDecoder, encode_item};

use super::cipher::RecordIdentity;
use super::fs::atomic_write;
use super::session::{UnlockedVault, read_bounded};
use crate::error::CliError;

/// Record schema version. Bumping it is a vault-format event.
pub const BOOKKEEPING_VERSION: u32 = 1;

/// Bounded-read cap for the slot (a real blob is well under 100 bytes;
/// the cap is defensive slack, the D10 house style).
const MAX_BOOKKEEPING_RECORD_BYTES: usize = 4096;

/// The **loss** half of the standing warning (MVP-SPEC.md line 143 and
/// the Risks section), in possession language.
///
/// One author for both places it appears: `init`'s closing message
/// ([`crate::init::standing_warnings`]) and the first-seal export nag.
/// They are the same sentence because they are the same fact, and a user
/// who read it at `init` must recognise it at `seal` rather than parse a
/// second phrasing of the same risk.
pub const LOSS_WARNING: &str = "  LOSS  — lose this vault and its passphrase, and no one can \
     ever reveal or restore your sealed works again. The sealed data itself stays safely \
     unreadable. Run `antseal vault export` and keep the backup somewhere else.";

/// The **theft** half of the standing warning: retroactive, permanent,
/// unrotatable.
pub const THEFT_WARNING: &str = "  THEFT — whoever holds this vault (or an export) and the \
     passphrase can decrypt every work you have ever sealed, retroactively and permanently. \
     The ciphertexts are public and undeletable, and there is no key rotation. Treat the \
     passphrase as a long-term, high-value key.";

/// The vault-global bookkeeping facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bookkeeping {
    /// How many successful `vault export` runs this vault has recorded.
    pub exports: u64,
    /// When the most recent one finished (unix seconds), if any.
    pub last_export_unix_secs: Option<u64>,
}

impl Bookkeeping {
    /// Has this vault ever been exported? The single question U18's nag
    /// asks.
    #[must_use]
    pub const fn ever_exported(&self) -> bool {
        self.exports > 0
    }

    /// Serialize (deterministic canonical CBOR; project rule 5).
    ///
    /// # Errors
    ///
    /// [`CliError::Internal`] on an encode failure — unreachable for this
    /// fixed shape, and an error rather than a panic (library discipline).
    pub fn encode(&self) -> Result<Vec<u8>, CliError> {
        encode_item(|e| {
            e.map(|m| {
                m.entry(0, |e| e.u64(u64::from(BOOKKEEPING_VERSION)))?;
                m.entry(1, |e| e.u64(self.exports))?;
                if let Some(at) = self.last_export_unix_secs {
                    m.entry(2, |e| e.u64(at))?;
                }
                Ok(())
            })
        })
        .map_err(|source| CliError::Internal {
            detail: format!("vault bookkeeping record encode failed: {source}"),
        })
    }

    /// Parse a record body. Total over adversarial input — the bytes come
    /// from inside the AEAD, but an *import* payload's copy is attacker-
    /// chosen up to the export's own authentication, so no shortcut.
    ///
    /// # Errors
    ///
    /// [`CliError::Internal`] with a naming detail for every malformed
    /// shape (the post-authentication bug class the store and export
    /// layers already use), and [`CliError::VaultNewerVersion`] for a
    /// record written by a newer build.
    pub fn decode(bytes: &[u8]) -> Result<Self, CliError> {
        let bad = |detail: &str| CliError::Internal {
            detail: format!("vault bookkeeping record invalid: {detail}"),
        };
        let mut d = CanonicalDecoder::new(bytes);
        let mut map = d.map().map_err(|_| bad("not a canonical CBOR map"))?;
        let mut version: Option<u64> = None;
        let mut exports: Option<u64> = None;
        let mut last_export_unix_secs: Option<u64> = None;
        loop {
            let key = match map.next_key(&mut d) {
                Ok(Some(key)) => key,
                Ok(None) => break,
                Err(_) => return Err(bad("malformed map key")),
            };
            match key {
                0 => version = Some(d.u64().map_err(|_| bad("version is not a uint"))?),
                1 => exports = Some(d.u64().map_err(|_| bad("exports is not a uint"))?),
                2 => {
                    last_export_unix_secs =
                        Some(d.u64().map_err(|_| bad("last export is not a uint"))?);
                }
                // Strict: an unknown key means a schema this build does
                // not understand, and silently dropping it would let a
                // round trip lose data (the export's own rule).
                _ => return Err(bad("unknown key (strict v1 schema)")),
            }
        }
        d.finish().map_err(|_| bad("trailing bytes"))?;

        let version = version.ok_or_else(|| bad("version missing"))?;
        if version > u64::from(BOOKKEEPING_VERSION) {
            return Err(CliError::VaultNewerVersion {
                found: version,
                supported: BOOKKEEPING_VERSION,
            });
        }
        Ok(Bookkeeping {
            exports: exports.ok_or_else(|| bad("exports missing"))?,
            last_export_unix_secs,
        })
    }
}

/// Read the vault's bookkeeping record. A missing slot is
/// [`Bookkeeping::default`] — see the module docs on why absence is a
/// state.
///
/// # Errors
///
/// [`CliError::VaultAuthFailure`] for a present-but-unauthentic record;
/// [`CliError::Io`] for a read that fails for any other reason; the
/// decode classes for a malformed body.
pub fn load(vault: &UnlockedVault) -> Result<Bookkeeping, CliError> {
    let path = vault.layout().bookkeeping_record_path();
    let blob = match read_bounded(&path, MAX_BOOKKEEPING_RECORD_BYTES) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Bookkeeping::default()),
        Err(source) => {
            return Err(CliError::Io {
                context: format!("reading {}", path.display()),
                source,
            });
        }
    };
    let plaintext = vault.open_record(RecordIdentity::Bookkeeping, &blob)?;
    Bookkeeping::decode(plaintext.as_bytes())
}

/// Write the vault's bookkeeping record (atomic; the caller holds the U5
/// single-writer lock, as every store mutation does).
///
/// # Errors
///
/// Cipher/RNG failures via [`CliError`]; I/O errors from the atomic write.
pub fn store<R: TryCryptoRng + ?Sized>(
    vault: &UnlockedVault,
    record: &Bookkeeping,
    rng: &mut R,
) -> Result<(), CliError> {
    let body = record.encode()?;
    let blob = vault.seal_record(RecordIdentity::Bookkeeping, &body, rng)?;
    let path = vault.layout().bookkeeping_record_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| CliError::Io {
            context: format!("creating {}", parent.display()),
            source,
        })?;
    }
    atomic_write(&path, &blob).map_err(|source| CliError::Io {
        context: format!("writing {}", path.display()),
        source,
    })
}

/// Record that a `vault export` completed — the write that stops U18's
/// nag.
///
/// Read-modify-write, so the count survives and a later staleness rule
/// (how *old* is the backup) has the timestamp it would need without
/// another format event.
///
/// # Errors
///
/// As [`load`] and [`store`].
pub fn record_export<R: TryCryptoRng + ?Sized>(
    vault: &UnlockedVault,
    at_unix_secs: u64,
    rng: &mut R,
) -> Result<Bookkeeping, CliError> {
    let mut record = load(vault)?;
    record.exports = record.exports.saturating_add(1);
    record.last_export_unix_secs = Some(at_unix_secs);
    store(vault, &record, rng)?;
    Ok(record)
}

/// The first-seal export nag (U18): what to do, and both failure modes it
/// protects against, in possession language.
///
/// Returned as data rather than printed so the seal report renders it on
/// the same channel as everything else (stdout in plain mode, stderr
/// under `--json` — D51 invariant 2) and the `--json` document can carry
/// it too.
///
/// Positioning discipline (U31): no "notary", no unqualified "priority" —
/// this says what a backup does and what losing one costs, nothing about
/// legal effect.
#[must_use]
pub fn export_nag() -> Vec<String> {
    vec![
        "  NO BACKUP YET — this vault has never been exported.".to_owned(),
        "  Run `antseal vault export` now and put the file somewhere else: another disk, \
         another machine, a safe. The keys to everything you seal live in this one directory."
            .to_owned(),
        LOSS_WARNING.to_owned(),
        THEFT_WARNING.to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_round_trips_and_absent_fields_stay_absent() {
        for record in [
            Bookkeeping::default(),
            Bookkeeping {
                exports: 1,
                last_export_unix_secs: Some(1_800_000_000),
            },
            Bookkeeping {
                exports: u64::MAX,
                last_export_unix_secs: None,
            },
        ] {
            let bytes = record.encode().expect("encodes");
            assert_eq!(Bookkeeping::decode(&bytes).expect("decodes"), record);
        }
        // The optional key really is optional on the wire.
        assert!(
            Bookkeeping::default().encode().expect("encodes").len()
                < Bookkeeping {
                    exports: 0,
                    last_export_unix_secs: Some(1),
                }
                .encode()
                .expect("encodes")
                .len()
        );
    }

    #[test]
    fn ever_exported_is_the_one_question_the_nag_asks() {
        assert!(!Bookkeeping::default().ever_exported());
        assert!(
            Bookkeeping {
                exports: 1,
                last_export_unix_secs: Some(7),
            }
            .ever_exported()
        );
    }

    #[test]
    fn decode_is_total_over_malformed_input_and_never_panics() {
        for bytes in [
            &b""[..],
            &b"\xff"[..],
            &[0xA0][..],                   // empty map: version missing
            &[0xA1, 0x00, 0x01][..],       // version only: exports missing
            &[0xA1, 0x09, 0x01][..],       // unknown key
            &[0xA1, 0x00, 0x60][..],       // version is a string
            &[0xA2, 0x00, 0x01, 0x01][..], // truncated
        ] {
            assert!(
                Bookkeeping::decode(bytes).is_err(),
                "accepted malformed bytes {bytes:?}"
            );
        }
    }

    #[test]
    fn a_newer_record_version_is_its_own_class_not_a_generic_failure() {
        let bytes = encode_item(|e| {
            e.map(|m| {
                m.entry(0, |e| e.u64(u64::from(BOOKKEEPING_VERSION) + 1))?;
                m.entry(1, |e| e.u64(3))
            })
        })
        .expect("encodes");
        let err = Bookkeeping::decode(&bytes).expect_err("refused");
        assert_eq!(err.class(), crate::error::ErrorClass::VaultNewerVersion);
    }

    /// The nag says both failure modes, and says them in the *same* words
    /// `init` used — one author, one sentence per fact.
    #[test]
    fn the_nag_carries_both_failure_modes_and_no_positioning_overreach() {
        let text = export_nag().join("\n");
        assert!(text.contains(LOSS_WARNING), "{text}");
        assert!(text.contains(THEFT_WARNING), "{text}");
        assert!(text.contains("LOSS"), "{text}");
        assert!(text.contains("THEFT"), "{text}");
        assert!(text.contains("antseal vault export"), "{text}");
        // U31 positioning: this is not a legal claim.
        let lower = text.to_lowercase();
        assert!(!lower.contains("notary"), "{text}");
        assert!(!lower.contains("notaris"), "{text}");
        assert!(!lower.contains("priority"), "{text}");
    }
}
