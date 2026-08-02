//! `vault export` / `vault import` — the D47 single-file encrypted backup
//! format and its two engines (U12).
//!
//! # File format (D47, normative properties; schema details fixed here)
//!
//! ```text
//! file := MAGIC ("ANTSEAL VAULT EXPORT", 20 bytes — the Q2-reserved
//!                literal; its ONE sanctioned source occurrence is this
//!                module, recorded in the secret-guard lane's exclusion)
//!       ‖ header: canonical CBOR array(2) [ format_version: uint,
//!                                           body: bstr ]
//!         body (v1): map { 0: kdf_block (bstr ≤ 512 B — EXACTLY the U6
//!                             schema, D40 caps and all; fresh salt),
//!                          1: nonce (bstr, exactly 24 B) }
//!       ‖ ciphertext: XChaCha20-Poly1305 over the payload,
//!                     key = KDF(passphrase, header's kdf block),
//!                     AAD = MAGIC ‖ header
//! ```
//!
//! One AEAD over the whole logical state is the property the verbatim
//! archive could not have (D47 §why-A-loses): any deletion, truncation,
//! or flip — including a *missing work* — is an authentication failure.
//! The KDF parameters are copied from the vault's own header (they
//! already satisfy D40's floors) with a **fresh 16-byte salt**; never the
//! vault's salt, never the vault's derived key (a distinct AEAD domain
//! gets a distinct key). The passphrase is the vault passphrase, proven
//! by the unlock the export performs before it becomes the backup's only
//! key.
//!
//! # A keyfile-wrapped vault is refused, not exported (U8, overturned)
//!
//! U8's entry expected this format to "carry the keyfile factor
//! unchanged". Implementing it exposed why it cannot, and the evidence is
//! four lines above: the export's own AEAD key is
//! `KDF(passphrase, fresh salt)` — **the passphrase alone**, as this
//! module's own format block says ("the passphrase … becomes the backup's
//! only key").
//!
//! So writing a v1 export of a two-factor vault would silently convert
//! two factors into one. The backup would become the weakest link — steal
//! the file, attack the passphrase, and the keyfile that was supposed to
//! stand between an attacker and every sealed work never enters the
//! problem. That is exactly the silent downgrade U12 refused to perform
//! on the import side, arriving from the other direction.
//!
//! Making the *export* two-factor is the right fix and is a **D47 format
//! event** (its header would need a wrap mode and the same combine),
//! which is a recorded decision rather than an implementation detail —
//! the reasoning D50 used to keep the OS keystore out of M1 applies
//! unchanged. Until that lands:
//!
//! - `vault export` **refuses** a vault whose header wrap mode is not 0,
//!   naming the reason and the workaround;
//! - `vault import` **refuses** a payload whose wrap mode is not 0,
//!   because installing it as mode 0 would drop the factor and installing
//!   it as mode 1 would need a keyfile the payload does not contain.
//!
//! Mode-0 vaults — every vault this build creates by default — export and
//! import byte-for-byte as before.
//!
//! # Payload (plaintext under the AEAD; versioned by `format_version`)
//!
//! ```text
//! payload := map {
//!   0: writer_version (bstr ≤ 64 — informational ONLY, never acted on
//!      at import; recorded because D47 names "format/app versions")
//!   1: wrap_mode (uint, D50 registry). **A wrapped vault is refused, in
//!      both directions, and U8's expected "carry the factor unchanged"
//!      is deliberately overturned — see the section below.**
//!   2: config (bstr, optional) — raw `config.toml` bytes (D47: config
//!      sits beside the vault AEAD on disk but belongs inside the backup)
//!   3: wallet (bstr, exactly 32, optional) — the U10 wallet secret
//!   4: works (array, sorted strictly ascending by seal_id) of
//!      work := map {
//!        0: meta (bstr) — the U9 versioned meta-record plaintext
//!        1: journal (array of [entry: uint, bytes: bstr], strictly
//!           ascending, optional) — every entry for a work whose state is
//!           not `complete`; for a `complete` work only the record-scale
//!           entries below `UNIT_ENTRY_BASE` (state, plan, encrypted-
//!           manifest record). The D43 journal/cache split as amended by
//!           S29: the cache is the staged *unit* blobs, enforced on write
//!           AND rejected on read if violated
//!        2: receipt (bstr, optional)
//!        3: anchors (array of [slot: bstr, bytes: bstr], strictly
//!           ascending, optional)
//!      }
//!   5: bookkeeping (bstr, optional) — the U34 vault-global bookkeeping
//!      record's plaintext (U18's export-performed flag). **Optional on
//!      read**: exports written before the slot existed simply omit it and
//!      still import, which is the whole reason this extends format v1
//!      rather than bumping it (pre-release, writer and reader move
//!      together; post-release the same change would be a
//!      `format_version` event — see EXPORT_FORMAT_VERSION)
//! }
//! ```
//!
//! All sequences are arrays of pairs (never text-keyed maps — the house
//! codec is uint-map-only by design), each sorted, so the payload byte
//! stream is deterministic (project rule 5). The payload plaintext
//! contains `W` for every work: it exists only inside [`SecretBuf`]s and
//! is wiped as soon as the AEAD (or the comparison digest) is done with
//! it.
//!
//! # Export sequence
//!
//! serialize → KDF (fresh salt) → seal → **temp file + fsync →
//! MANDATORY SELF-VERIFY → rename → parent fsync**. The self-verify is
//! D47's: re-read the written bytes from disk, run the FULL import-side
//! validation (same function, [`validate_export_bytes`] — one rule, two
//! call sites), KDF from the file's own header, decrypt, and compare a
//! SHA-256 digest of the decoded payload against the in-memory
//! serialization. Deviation-in-mechanism, recorded: D47 sketches
//! "atomic write, then self-verify"; this implementation verifies the
//! synced temp file and only THEN renames it over the target — the same
//! bytes are verified (rename never changes content), and a re-export
//! onto an existing backup path can no longer replace a good old backup
//! with a bad new file. Strictly stronger failure containment, no
//! property lost.
//!
//! # Import sequence
//!
//! refuse-existing-target → bounded read → **pre-auth header parse under
//! the D40 §3 caps** (the KDF-bomb rule's second call site — and it runs
//! before the passphrase is even collected, so garbage files are
//! rejected without prompting) → KDF → decrypt → decode → full logical
//! validation in memory → build a complete fresh vault in a dot-prefixed
//! temp directory beside the target → one atomic directory rename →
//! post-install verify (fresh unlock + walk). A crash at any point
//! leaves either nothing or an inert temp directory — never a partial
//! `~/.antseal/`. The import creates a NEW vault (fresh vault salt,
//! fresh vault key, every record re-encrypted): the export schema maps
//! into the *current* on-disk layout, which is exactly the layout
//! independence D47 chose option B for.
//!
//! # Error classes (D47 → U2 codes)
//!
//! `export-self-verify-failed` (32); `import-auth-failed` (33 — wrong
//! passphrase, bad magic, tamper, truncation: one class, deliberately,
//! like U6's vault-auth; the over-cap file collapses here too, being
//! outside the format); `import-newer-version` (34); D40's
//! `vault-kdf-params-out-of-range` (14) and `vault-kdf-memory` (13) at
//! the import header; `import-refused-existing-vault` → the D51
//! consent-not-obtained class (10). Post-authentication payload
//! malformation maps to `internal`: nothing but our own writer (or the
//! passphrase holder) can produce an authenticated-but-malformed
//! payload, so it is a bug class, not an input class. A post-release
//! payload schema change is therefore a `format_version` bump event —
//! recorded here for U18, whose export-bookkeeping flag is the first
//! candidate extension.

use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use antseal_core::codec::{CanonicalDecoder, encode_item};
use antseal_core::crypto::secrets::{SealId, SecretBuf};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};

use super::fs::atomic_write;
use super::header::{VaultHeader, WRAP_MODE_NONE};
use super::kdf::{KdfError, KdfParams};
use super::layout::{BesideFile, VaultLayout};
use super::session::{UnlockedVault, create_vault, read_bounded, unlock_vault};
use super::store::{
    MAX_RECORD_FILE_BYTES, StoreError, WorkRecord, WorkState, WorkStore, validate_slot_name,
};
use super::wallet::{WALLET_KEY_LEN, WalletKeyHandle, load_wallet_key, store_wallet_key};
use crate::config::MAX_CONFIG_BYTES;
use crate::error::CliError;
use crate::pipeline::journal::UNIT_ENTRY_BASE;

/// The Q2-reserved export magic — exact bytes, frozen forever
/// (testdata/README.md §secret-material: the guard greps for this
/// literal, and this module is its one sanctioned source occurrence).
pub const EXPORT_MAGIC: &[u8; 20] = b"ANTSEAL VAULT EXPORT";

/// Export format version. Its OWN series, deliberately decoupled from the
/// vault's on-disk format version (D47 §versioning): the export schema is
/// interchange surface, the layout is an implementation detail.
pub const EXPORT_FORMAT_VERSION: u32 = 1;

/// Advisory file extension (identification is by magic, not name — D47).
pub const EXPORT_FILE_EXTENSION: &str = "sealvault";

/// Hard cap on an import file read (defensive, D10 discipline: the file
/// is adversary-suppliable). Sized far above any v1 vault: the payload is
/// record-scale plus the staged unit blobs of *incomplete* works only
/// (the D43 cache is excluded — a complete work contributes only its
/// record-scale entries 0–2), and a single staged blob is one chunk.
pub const MAX_EXPORT_FILE_BYTES: usize = 1024 * 1024 * 1024;

/// Cap on the export header's CBOR body (a real body is ~60 bytes).
const MAX_EXPORT_HEADER_BODY_BYTES: usize = 1024;

/// Cap on the U34 bookkeeping record body inside the payload (a real
/// body is under 30 bytes; defensive slack in the D10 house style).
const MAX_BOOKKEEPING_PAYLOAD_BYTES: usize = 4096;

/// Cap on the informational writer-version string in the payload.
const MAX_WRITER_VERSION_BYTES: usize = 64;

/// AEAD nonce length (XChaCha20-Poly1305).
const EXPORT_NONCE_LEN: usize = 24;

/// What `vault export` reports on success.
#[derive(Debug)]
pub struct ExportSummary {
    /// The written backup file.
    pub path: PathBuf,
    /// Number of works captured.
    pub works: usize,
    /// Total file size in bytes.
    pub bytes: u64,
}

/// What `vault import` reports on success.
#[derive(Debug)]
pub struct ImportSummary {
    /// The reconstructed vault directory.
    pub vault_dir: PathBuf,
    /// Number of works installed.
    pub works: usize,
    /// Whether a wallet record was present and installed.
    pub wallet_present: bool,
    /// Whether a `config.toml` was present and installed.
    pub config_present: bool,
}

/// One work's slice of the payload. Record bodies ride in [`SecretBuf`]
/// (the meta plaintext contains `W`).
struct WorkPayload {
    meta: SecretBuf,
    journal: Vec<(u64, SecretBuf)>,
    receipt: Option<SecretBuf>,
    anchors: Vec<(String, SecretBuf)>,
}

/// The full decoded logical state of an export.
pub(crate) struct ExportPayload {
    writer_version: Vec<u8>,
    wrap_mode: u8,
    config: Option<Vec<u8>>,
    wallet: Option<WalletKeyHandle>,
    works: Vec<WorkPayload>,
    /// The U34 bookkeeping record body. Not a `SecretBuf`: it holds a
    /// count and a timestamp, no key material (see `vault::bookkeeping`).
    bookkeeping: Option<Vec<u8>>,
}

/// Injected failure points for the kill/corruption tests (the fs.rs
/// pattern: abort with no cleanup, modelling `SIGKILL`; or corrupt the
/// temp so the self-verify must catch it).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportFailPoint {
    /// No injected failure (the production path).
    None,
    /// Killed after the temp file was written and synced, before the
    /// self-verify/rename — the target path must be untouched.
    KilledAfterTempWrite,
    /// A byte of the synced temp file is flipped before the self-verify
    /// runs — the self-verify MUST fail and the target stay untouched.
    CorruptTempBeforeVerify,
}

/// Injected failure for the import kill test.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportFailPoint {
    /// No injected failure (the production path).
    None,
    /// Killed after the temp vault is partially built, before the
    /// rename — the target must not exist.
    KilledMidInstall,
}

// ─────────────────────────────────────────────────────────────────────
// Payload codec
// ─────────────────────────────────────────────────────────────────────

fn internal(detail: &str) -> CliError {
    CliError::Internal {
        detail: detail.to_owned(),
    }
}

/// Serialize the payload (deterministic canonical CBOR; the caller owns
/// wiping the returned buffer — it contains every work's `W`).
fn encode_payload(payload: &ExportPayload) -> Result<SecretBuf, CliError> {
    let err = |_| internal("export payload encode failed on a fixed shape");
    let bytes = encode_item(|e| {
        e.map(|m| {
            m.entry(0, |e| e.bytes(&payload.writer_version))?;
            m.entry(1, |e| e.u64(u64::from(payload.wrap_mode)))?;
            if let Some(config) = &payload.config {
                m.entry(2, |e| e.bytes(config))?;
            }
            if let Some(wallet) = &payload.wallet {
                m.entry(3, |e| e.bytes(wallet.secret_bytes()))?;
            }
            m.entry(4, |e| {
                e.array(|works| {
                    for work in &payload.works {
                        works.item(|e| {
                            e.map(|w| {
                                w.entry(0, |e| e.bytes(work.meta.as_bytes()))?;
                                if !work.journal.is_empty() {
                                    w.entry(1, |e| {
                                        e.array(|entries| {
                                            for (key, bytes) in &work.journal {
                                                entries.item(|e| {
                                                    e.array(|pair| {
                                                        pair.item(|e| e.u64(*key))?;
                                                        pair.item(|e| e.bytes(bytes.as_bytes()))
                                                    })
                                                })?;
                                            }
                                            Ok(())
                                        })
                                    })?;
                                }
                                if let Some(receipt) = &work.receipt {
                                    w.entry(2, |e| e.bytes(receipt.as_bytes()))?;
                                }
                                if !work.anchors.is_empty() {
                                    w.entry(3, |e| {
                                        e.array(|slots| {
                                            for (slot, bytes) in &work.anchors {
                                                slots.item(|e| {
                                                    e.array(|pair| {
                                                        pair.item(|e| e.bytes(slot.as_bytes()))?;
                                                        pair.item(|e| e.bytes(bytes.as_bytes()))
                                                    })
                                                })?;
                                            }
                                            Ok(())
                                        })
                                    })?;
                                }
                                Ok(())
                            })
                        })?;
                    }
                    Ok(())
                })
            })?;
            if let Some(bookkeeping) = &payload.bookkeeping {
                m.entry(5, |e| e.bytes(bookkeeping))?;
            }
            Ok(())
        })
    })
    .map_err(err)?;
    Ok(SecretBuf::new(bytes))
}

/// Parse and validate a payload (post-authentication: malformation here
/// is a bug class — see the module docs — except the version-family
/// errors, which stay typed).
fn decode_payload(bytes: &[u8]) -> Result<ExportPayload, CliError> {
    let bad = |detail: &str| internal(&format!("export payload invalid: {detail}"));
    let codec = |_| bad("not canonical CBOR");

    let mut d = CanonicalDecoder::new(bytes);
    let mut map = d.map().map_err(codec)?;

    let mut writer_version: Option<Vec<u8>> = None;
    let mut wrap_mode: Option<u8> = None;
    let mut config: Option<Vec<u8>> = None;
    let mut wallet: Option<WalletKeyHandle> = None;
    let mut works: Option<Vec<WorkPayload>> = None;
    let mut bookkeeping: Option<Vec<u8>> = None;

    while let Some(key) = map.next_key(&mut d).map_err(codec)? {
        match key {
            0 => {
                let raw = d.bytes().map_err(codec)?;
                if raw.len() > MAX_WRITER_VERSION_BYTES {
                    return Err(bad("writer version over cap"));
                }
                writer_version = Some(raw.to_vec());
            }
            1 => {
                let raw = d.u64().map_err(codec)?;
                let mode = u8::try_from(raw).map_err(|_| bad("wrap mode out of range"))?;
                wrap_mode = Some(mode);
            }
            2 => {
                let raw = d.bytes().map_err(codec)?;
                if raw.len() > MAX_CONFIG_BYTES {
                    return Err(bad("embedded config over cap"));
                }
                config = Some(raw.to_vec());
            }
            3 => {
                let raw = d.bytes().map_err(codec)?;
                let arr: [u8; WALLET_KEY_LEN] = raw
                    .try_into()
                    .map_err(|_| bad("wallet record must be exactly 32 bytes"))?;
                wallet = Some(WalletKeyHandle::from_bytes(arr));
            }
            4 => {
                let count = d.array().map_err(codec)?;
                let mut list = Vec::new();
                for _ in 0..count {
                    list.push(decode_work(&mut d)?);
                }
                works = Some(list);
            }
            5 => {
                let raw = d.bytes().map_err(codec)?;
                if raw.len() > MAX_BOOKKEEPING_PAYLOAD_BYTES {
                    return Err(bad("bookkeeping record over cap"));
                }
                bookkeeping = Some(raw.to_vec());
            }
            _ => return Err(bad("unknown payload key (strict v1 schema)")),
        }
    }
    d.finish().map_err(codec)?;

    let payload = ExportPayload {
        writer_version: writer_version.ok_or_else(|| bad("writer version missing"))?,
        wrap_mode: wrap_mode.ok_or_else(|| bad("wrap mode missing"))?,
        config,
        wallet,
        works: works.ok_or_else(|| bad("works array missing"))?,
        // Absent is valid: an export written before the U34 slot existed
        // carries no key 5 and imports unchanged.
        bookkeeping,
    };
    validate_payload(&payload)?;
    Ok(payload)
}

fn decode_work(d: &mut CanonicalDecoder<'_>) -> Result<WorkPayload, CliError> {
    let bad = |detail: &str| internal(&format!("export payload invalid: {detail}"));
    let codec = |_| bad("not canonical CBOR");

    let mut map = d.map().map_err(codec)?;
    let mut meta: Option<SecretBuf> = None;
    let mut journal: Vec<(u64, SecretBuf)> = Vec::new();
    let mut receipt: Option<SecretBuf> = None;
    let mut anchors: Vec<(String, SecretBuf)> = Vec::new();

    while let Some(key) = map.next_key(d).map_err(codec)? {
        match key {
            0 => {
                let raw = d.bytes().map_err(codec)?;
                if raw.len() > MAX_RECORD_FILE_BYTES {
                    return Err(bad("meta record over cap"));
                }
                meta = Some(SecretBuf::new(raw.to_vec()));
            }
            1 => {
                let count = d.array().map_err(codec)?;
                for _ in 0..count {
                    if d.array().map_err(codec)? != 2 {
                        return Err(bad("journal entry must be a [key, bytes] pair"));
                    }
                    let entry = d.u64().map_err(codec)?;
                    let raw = d.bytes().map_err(codec)?;
                    if raw.len() > MAX_RECORD_FILE_BYTES {
                        return Err(bad("journal entry over cap"));
                    }
                    journal.push((entry, SecretBuf::new(raw.to_vec())));
                }
                if journal.is_empty() {
                    return Err(bad("journal key present but empty (writer omits it)"));
                }
            }
            2 => {
                let raw = d.bytes().map_err(codec)?;
                if raw.len() > MAX_RECORD_FILE_BYTES {
                    return Err(bad("receipt over cap"));
                }
                receipt = Some(SecretBuf::new(raw.to_vec()));
            }
            3 => {
                let count = d.array().map_err(codec)?;
                for _ in 0..count {
                    if d.array().map_err(codec)? != 2 {
                        return Err(bad("anchor entry must be a [slot, bytes] pair"));
                    }
                    let slot_raw = d.bytes().map_err(codec)?;
                    let slot = String::from_utf8(slot_raw.to_vec())
                        .map_err(|_| bad("anchor slot is not UTF-8"))?;
                    validate_slot_name(&slot).map_err(|_| bad("anchor slot outside grammar"))?;
                    let raw = d.bytes().map_err(codec)?;
                    if raw.len() > MAX_RECORD_FILE_BYTES {
                        return Err(bad("anchor artifact over cap"));
                    }
                    anchors.push((slot, SecretBuf::new(raw.to_vec())));
                }
                if anchors.is_empty() {
                    return Err(bad("anchors key present but empty (writer omits it)"));
                }
            }
            _ => return Err(bad("unknown work key (strict v1 schema)")),
        }
    }

    Ok(WorkPayload {
        meta: meta.ok_or_else(|| bad("work meta missing"))?,
        journal,
        receipt,
        anchors,
    })
}

/// Cross-field validation over the decoded payload: every meta decodes,
/// works strictly ascending by seal_id (unique by construction),
/// journal/anchor sequences strictly ascending, the D43 exclusion holds
/// (a complete work carries no journal bytes), wrap mode is registered.
fn validate_payload(payload: &ExportPayload) -> Result<(), CliError> {
    let bad = |detail: &str| internal(&format!("export payload invalid: {detail}"));

    if payload.wrap_mode != WRAP_MODE_NONE {
        // The module docs' overturned-U8 section: a v1 export is keyed by
        // the passphrase alone, so it cannot carry a second factor.
        // Installing this as mode 0 would silently drop the wrap;
        // installing it as mode 1 would need a keyfile the payload does
        // not contain. Neither is acceptable, so neither happens.
        return Err(CliError::Usage {
            message: format!(
                "this backup was written from a vault with wrap mode {} (a keyfile or \
                 keystore factor), and the v1 export format cannot carry a second factor — \
                 its own encryption is keyed by the passphrase alone. Importing it would \
                 either drop the factor silently or need a keyfile this file does not \
                 contain, so antseal refuses instead. Nothing was written",
                payload.wrap_mode
            ),
        });
    }

    let mut previous: Option<SealId> = None;
    for work in &payload.works {
        let record = decode_meta(work.meta.as_bytes())?;
        if let Some(prev) = &previous
            && prev.as_bytes() >= record.seal_id.as_bytes()
        {
            return Err(bad("works are not strictly ascending by seal id"));
        }
        // D43, read side (as amended 2026-08-02 by S29): the cache is
        // the *staged unit blobs*, and those have no business in an
        // export. A complete work's record-scale entries 0–2 do, and
        // entry 2 is the only surviving locator for its encrypted
        // manifest.
        if record.state == WorkState::Complete
            && work.journal.iter().any(|(key, _)| *key >= UNIT_ENTRY_BASE)
        {
            return Err(bad(
                "a complete work carries staged unit blobs (the D43 cache is never exported)",
            ));
        }
        if !strictly_ascending(work.journal.iter().map(|(k, _)| *k)) {
            return Err(bad("journal entries are not strictly ascending"));
        }
        if !strictly_ascending(work.anchors.iter().map(|(slot, _)| slot.clone())) {
            return Err(bad("anchor slots are not strictly ascending"));
        }
        previous = Some(record.seal_id);
    }
    Ok(())
}

/// Decode a meta record from the payload, mapping version-family errors
/// to the import classes.
fn decode_meta(bytes: &[u8]) -> Result<WorkRecord, CliError> {
    match WorkRecord::decode(bytes) {
        Ok(record) => Ok(record),
        // A meta schema newer than this build: same "newer antseal"
        // family as the header version (can only arise from a
        // hand-crafted or future-written export).
        Err(StoreError::NewerRecord { found }) => Err(CliError::ImportNewerVersion {
            found,
            supported: EXPORT_FORMAT_VERSION,
        }),
        Err(_) => Err(internal(
            "export payload invalid: a work meta record does not decode",
        )),
    }
}

fn strictly_ascending<T: PartialOrd>(iter: impl Iterator<Item = T>) -> bool {
    let mut previous: Option<T> = None;
    for item in iter {
        if let Some(prev) = &previous
            && *prev >= item
        {
            return false;
        }
        previous = Some(item);
    }
    true
}

// ─────────────────────────────────────────────────────────────────────
// Header parse (pre-auth; the D40 cap call site)
// ─────────────────────────────────────────────────────────────────────

/// Pre-authentication parse of an export file's preamble: magic, version,
/// KDF block (under the D40 §3 caps — no KDF has run yet), nonce, and the
/// byte offset where ciphertext begins. Runs before any passphrase is
/// collected.
fn parse_export_header(
    bytes: &[u8],
) -> Result<(KdfParams, [u8; EXPORT_NONCE_LEN], usize), CliError> {
    let auth = || CliError::ImportAuthFailed;

    let rest = bytes
        .strip_prefix(EXPORT_MAGIC.as_slice())
        .ok_or_else(auth)?;

    let mut d = CanonicalDecoder::new(rest);
    if d.array().map_err(|_| auth())? != 2 {
        return Err(auth());
    }
    let version = d.u64().map_err(|_| auth())?;
    if version == 0 {
        return Err(auth());
    }
    if version > u64::from(EXPORT_FORMAT_VERSION) {
        return Err(CliError::ImportNewerVersion {
            found: version,
            supported: EXPORT_FORMAT_VERSION,
        });
    }
    let body = d.bytes().map_err(|_| auth())?;
    if body.len() > MAX_EXPORT_HEADER_BODY_BYTES {
        return Err(auth());
    }
    // NOTE: no `finish()` — the ciphertext follows the header item.
    let header_len = d.position();

    // v1 body: strict {0: kdf_block, 1: nonce}.
    let mut b = CanonicalDecoder::new(body);
    let mut map = b.map().map_err(|_| auth())?;
    if map.remaining() != 2 {
        return Err(auth());
    }
    if map.next_key(&mut b).map_err(|_| auth())? != Some(0) {
        return Err(auth());
    }
    let kdf_block = b.bytes().map_err(|_| auth())?;
    if map.next_key(&mut b).map_err(|_| auth())? != Some(1) {
        return Err(auth());
    }
    let nonce_raw = b.bytes().map_err(|_| auth())?;
    b.finish().map_err(|_| auth())?;
    let nonce: [u8; EXPORT_NONCE_LEN] = nonce_raw.try_into().map_err(|_| auth())?;

    // The D40 §3 caps run inside this decode, before any allocation —
    // with import-specific error routing (a malformed block is
    // indistinguishable from tamper ⇒ the import-auth class, NOT the
    // vault-auth class the unlock path uses).
    let params = KdfParams::decode(kdf_block).map_err(|e| match e {
        KdfError::ParamsOutOfRange { detail } => CliError::VaultKdfParamsOutOfRange { detail },
        KdfError::Codec { .. } | KdfError::Schema { .. } => CliError::ImportAuthFailed,
        other => CliError::from(other),
    })?;

    Ok((params, nonce, header_len))
}

/// Full import-side validation of export-file bytes: header (pre-auth
/// caps), KDF, AEAD open, payload decode + cross-validation. Shared by
/// `vault import` and by export's mandatory self-verify — one rule, two
/// call sites (D47).
///
/// Returns the decoded payload plus the payload plaintext (for the
/// self-verify digest comparison; wiped by the caller via `SecretBuf`).
pub(crate) fn validate_export_bytes(
    bytes: &[u8],
    passphrase: &SecretBuf,
) -> Result<(ExportPayload, SecretBuf), CliError> {
    let (params, nonce, header_len) = parse_export_header(bytes)?;
    let key = params.derive_key(passphrase).map_err(|e| match e {
        KdfError::Memory { required_mib } => CliError::VaultKdfMemory { required_mib },
        other => CliError::from(other),
    })?;

    let header = &bytes[..EXPORT_MAGIC.len() + header_len];
    let ciphertext = &bytes[EXPORT_MAGIC.len() + header_len..];

    // 32 bytes is the XChaCha20-Poly1305 key size; cannot fail.
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| CliError::ImportAuthFailed)?;
    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| CliError::ImportAuthFailed)?;
    let plaintext = SecretBuf::new(plaintext);

    let payload = decode_payload(plaintext.as_bytes())?;
    Ok((payload, plaintext))
}

// ─────────────────────────────────────────────────────────────────────
// Export
// ─────────────────────────────────────────────────────────────────────

/// Gather the full logical vault state (D47's enumeration; D43's cache
/// excluded by the state tag).
fn gather_payload(vault: &UnlockedVault) -> Result<ExportPayload, CliError> {
    // Config: beside the AEAD on disk, inside the backup (D47).
    let config_path = vault.layout().beside_path(BesideFile::Config);
    let config = match read_bounded(&config_path, MAX_CONFIG_BYTES + 1) {
        Ok(bytes) => {
            if bytes.len() > MAX_CONFIG_BYTES {
                return Err(CliError::Usage {
                    message: format!(
                        "{} exceeds the {} KiB config cap and cannot be exported",
                        config_path.display(),
                        MAX_CONFIG_BYTES / 1024
                    ),
                });
            }
            Some(bytes)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(source) => {
            return Err(CliError::Io {
                context: format!("reading {}", config_path.display()),
                source,
            });
        }
    };

    // Refuse before a single record is read (the module docs' overturned-
    // U8 section): a v1 export of a wrapped vault would be a
    // passphrase-only backup of a two-factor vault, and a backup that is
    // weaker than the thing it backs up is worse than no backup, because
    // the user believes they are covered.
    let header_wrap = VaultHeader::decode(vault.header_bytes())
        .map_err(CliError::from)?
        .wrap_mode();
    if header_wrap != WRAP_MODE_NONE {
        return Err(CliError::Usage {
            message: format!(
                "this vault uses wrap mode {header_wrap} (a keyfile or keystore factor), and \
                 the v1 export format cannot carry a second factor — the backup file is \
                 encrypted under the passphrase alone, so writing one would quietly turn \
                 your two-factor vault into a one-factor backup. Back up the vault \
                 directory and the keyfile separately by hand until the export format \
                 carries the wrap (nothing was written)"
            ),
        });
    }

    let wrap_mode = VaultHeader::decode(vault.header_bytes())
        .map_err(CliError::from)?
        .wrap_mode();
    let wallet = load_wallet_key(vault)?;

    let store = WorkStore::new(vault);
    let mut works = Vec::new();
    for seal_id in store.list_works().map_err(CliError::from)? {
        let record = store.load_meta(&seal_id).map_err(CliError::from)?;
        // D43 (as amended 2026-08-02 by S29): journal-state bytes (work
        // not complete) are resume-critical and always exported. For a
        // complete work the exclusion is scoped to the *staged unit
        // blobs* — entries `>= UNIT_ENTRY_BASE`, the content-scale bytes
        // D43 §3's size reasoning is actually about. Entries 0–2 (state,
        // plan, encrypted-manifest record) are record-scale metadata and
        // are always exported: without entry 2's `{address, nonce}` an
        // encrypted manifest is unlocatable on a content-addressed
        // network, so dropping it made an imported complete work
        // impossible to restore at all.
        let complete = record.state == WorkState::Complete;
        let mut journal = Vec::new();
        for entry in store
            .list_journal_entries(&seal_id)
            .map_err(CliError::from)?
        {
            if complete && entry >= UNIT_ENTRY_BASE {
                continue;
            }
            let bytes = store
                .get_journal_entry(&seal_id, entry)
                .map_err(CliError::from)?
                .ok_or_else(|| internal("journal entry vanished during export"))?;
            journal.push((entry, bytes));
        }
        let receipt = store.get_receipt(&seal_id).map_err(CliError::from)?;
        let mut anchors = Vec::new();
        for slot in store.list_anchors(&seal_id).map_err(CliError::from)? {
            let bytes = store
                .get_anchor(&seal_id, &slot)
                .map_err(CliError::from)?
                .ok_or_else(|| internal("anchor artifact vanished during export"))?;
            anchors.push((slot, bytes));
        }
        let meta = SecretBuf::new(record.encode().map_err(CliError::from)?);
        works.push(WorkPayload {
            meta,
            journal,
            receipt,
            anchors,
        });
    }

    // U34/U18: the vault-global bookkeeping record travels, so a restored
    // vault remembers that it HAS a backup. Absent (never exported, or a
    // vault older than the slot) simply omits the key.
    let bookkeeping = match super::bookkeeping::load(vault)? {
        record if record == super::bookkeeping::Bookkeeping::default() => None,
        record => Some(record.encode()?),
    };

    Ok(ExportPayload {
        writer_version: env!("CARGO_PKG_VERSION").as_bytes().to_vec(),
        wrap_mode,
        config,
        wallet,
        works,
        bookkeeping,
    })
}

/// Write the export file per D47 (see the module docs for the sequence).
/// The caller holds the vault lock (a consistent multi-record snapshot
/// needs the single writer excluded) and has already proven the
/// passphrase by unlocking `vault`.
///
/// # Errors
///
/// [`CliError::ExportSelfVerifyFailed`] when the written bytes fail the
/// mandatory re-read validation (the target path is left untouched);
/// KDF/cipher/I/O errors otherwise.
pub fn export_vault<R: TryCryptoRng + ?Sized>(
    vault: &UnlockedVault,
    passphrase: &SecretBuf,
    out_path: &Path,
    rng: &mut R,
) -> Result<ExportSummary, CliError> {
    export_vault_impl(vault, passphrase, out_path, rng, ExportFailPoint::None)
}

pub(crate) fn export_vault_impl<R: TryCryptoRng + ?Sized>(
    vault: &UnlockedVault,
    passphrase: &SecretBuf,
    out_path: &Path,
    rng: &mut R,
    fail: ExportFailPoint,
) -> Result<ExportSummary, CliError> {
    let payload = gather_payload(vault)?;
    let works = payload.works.len();
    let plaintext = encode_payload(&payload)?;

    // KDF parameters: the vault's own algorithm + parameters, FRESH salt
    // (never the vault's salt, never the vault's key — D47).
    let vault_params = KdfParams::decode(
        VaultHeader::decode(vault.header_bytes())
            .map_err(CliError::from)?
            .kdf_block(),
    )
    .map_err(CliError::from)?;
    let params = vault_params.with_fresh_salt(rng).map_err(CliError::from)?;
    let key = params.derive_key(passphrase).map_err(CliError::from)?;

    let kdf_block = params.encode().map_err(CliError::from)?;
    let mut nonce = [0u8; EXPORT_NONCE_LEN];
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| internal("OS random source failed while drawing the export nonce"))?;

    let header = encode_item(|e| {
        e.array(|a| {
            a.item(|e| e.u64(u64::from(EXPORT_FORMAT_VERSION)))?;
            a.item(|e| {
                e.bytes(&encode_item(|e| {
                    e.map(|m| {
                        m.entry(0, |e| e.bytes(&kdf_block))?;
                        m.entry(1, |e| e.bytes(&nonce))
                    })
                })?)
            })
        })
    })
    .map_err(|_| internal("export header encode failed on a fixed shape"))?;

    let mut aad = Vec::with_capacity(EXPORT_MAGIC.len() + header.len());
    aad.extend_from_slice(EXPORT_MAGIC);
    aad.extend_from_slice(&header);

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| internal("export cipher construction failed"))?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| internal("export encryption failed"))?;

    let mut file_bytes = Vec::with_capacity(aad.len() + ciphertext.len());
    file_bytes.extend_from_slice(&aad);
    file_bytes.extend_from_slice(&ciphertext);

    // In-memory digest for the self-verify comparison.
    let expected_digest = Sha256::digest(plaintext.as_bytes());
    drop(plaintext); // wiped

    // Temp write + fsync (same-directory temp, the U5 discipline).
    let parent = out_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = out_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault-export".to_owned());
    let temp = parent.join(format!(
        ".{file_name}.export-tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0),
    ));
    let io_err = |context: String| move |source| CliError::Io { context, source };
    let write_temp = || -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(&file_bytes)?;
        file.sync_all()?;
        Ok(())
    };
    write_temp().map_err(io_err(format!("writing {}", temp.display())))?;

    if fail == ExportFailPoint::KilledAfterTempWrite {
        // Modelled SIGKILL: no cleanup, no rename. The target path is
        // untouched; the dot-prefixed temp is inert residue.
        return Err(internal("simulated kill during export (test failpoint)"));
    }
    if fail == ExportFailPoint::CorruptTempBeforeVerify {
        // Model a disk that lied about the write: flip one ciphertext
        // byte in the file the self-verify is about to read.
        let mut on_disk = std::fs::read(&temp).map_err(io_err(format!(
            "re-reading {} for corruption injection",
            temp.display()
        )))?;
        let last = on_disk.len() - 1;
        on_disk[last] ^= 0x01;
        std::fs::write(&temp, &on_disk)
            .map_err(io_err(format!("corrupting {}", temp.display())))?;
    }

    // MANDATORY self-verify (D47): fresh read, full import-side
    // validation (KDF from the file's own header), digest comparison.
    let self_verify = || -> Result<(), CliError> {
        let written = read_bounded(&temp, MAX_EXPORT_FILE_BYTES + 1)
            .map_err(io_err(format!("re-reading {}", temp.display())))?;
        if written.len() > MAX_EXPORT_FILE_BYTES {
            return Err(CliError::ExportSelfVerifyFailed);
        }
        let (_payload, decoded_plaintext) = validate_export_bytes(&written, passphrase)
            .map_err(|_| CliError::ExportSelfVerifyFailed)?;
        let actual = Sha256::digest(decoded_plaintext.as_bytes());
        if actual != expected_digest {
            return Err(CliError::ExportSelfVerifyFailed);
        }
        Ok(())
    };
    if let Err(err) = self_verify() {
        // The bad bytes never reach the target path; remove the temp
        // best-effort so no unverified export lingers.
        let _ = std::fs::remove_file(&temp);
        return Err(err);
    }

    // Verified: publish atomically.
    std::fs::rename(&temp, out_path).map_err(io_err(format!(
        "renaming the export into place at {}",
        out_path.display()
    )))?;
    #[cfg(unix)]
    {
        if let Ok(dir) = std::fs::File::open(&parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(ExportSummary {
        path: out_path.to_path_buf(),
        works,
        bytes: file_bytes.len() as u64,
    })
}

// ─────────────────────────────────────────────────────────────────────
// Import
// ─────────────────────────────────────────────────────────────────────

/// Reconstruct a vault from an export file (see the module docs for the
/// sequence and its guarantees). `passphrase_source` is called only
/// after the pre-auth header checks pass, so garbage files never prompt.
///
/// # Errors
///
/// [`CliError::ImportRefusedExistingVault`] (before anything is read)
/// when the target holds a vault; the D47 classes per the module docs.
pub fn import_vault<R: TryCryptoRng + ?Sized>(
    file: &Path,
    target: &VaultLayout,
    passphrase_source: impl FnOnce() -> Result<SecretBuf, CliError>,
    rng: &mut R,
) -> Result<ImportSummary, CliError> {
    import_vault_impl(file, target, passphrase_source, rng, ImportFailPoint::None)
}

pub(crate) fn import_vault_impl<R: TryCryptoRng + ?Sized>(
    file: &Path,
    target: &VaultLayout,
    passphrase_source: impl FnOnce() -> Result<SecretBuf, CliError>,
    rng: &mut R,
    fail: ImportFailPoint,
) -> Result<ImportSummary, CliError> {
    // 1. Refusal precedes everything — even reading the file (D39/D51:
    //    the manual move/remove of the existing vault IS the consent, and
    //    no flag bypasses this in any mode).
    refuse_existing_target(target)?;

    // 2. Bounded read; a file over the cap is outside the v1 format
    //    (documented collapse into the import-auth class).
    let bytes = match read_bounded(file, MAX_EXPORT_FILE_BYTES + 1) {
        Ok(bytes) => bytes,
        Err(source) => {
            return Err(CliError::Io {
                context: format!("reading {}", file.display()),
                source,
            });
        }
    };
    if bytes.len() > MAX_EXPORT_FILE_BYTES {
        return Err(CliError::ImportAuthFailed);
    }

    // 3. Pre-auth header parse (D40 caps) BEFORE the passphrase.
    parse_export_header(&bytes)?;

    // 4. Passphrase, KDF, decrypt, decode, full in-memory validation.
    let passphrase = passphrase_source()?;
    let (payload, plaintext) = validate_export_bytes(&bytes, &passphrase)?;
    drop(plaintext); // wiped; the decoded payload is what installs

    // 5. Build the complete new vault in a temp directory beside the
    //    target (same filesystem, so the final rename is atomic).
    let root = target.root().to_path_buf();
    let parent = root
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .ok_or_else(|| CliError::Usage {
            message: format!(
                "cannot import into {} — the vault path has no parent directory",
                root.display()
            ),
        })?;
    std::fs::create_dir_all(&parent).map_err(|source| CliError::Io {
        context: format!("creating {}", parent.display()),
        source,
    })?;
    let root_name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "antseal-vault".to_owned());
    let temp_root = parent.join(format!(
        ".{root_name}.import-tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0),
    ));

    let mut build = || -> Result<(usize, bool, bool), CliError> {
        let temp_layout = VaultLayout::at(temp_root.clone());
        // A fresh vault: fresh salt, fresh vault key, same KDF algorithm
        // family as the export (v1 creation values are the frozen D40
        // set either way).
        let export_params = parse_export_header(&bytes)?.0;
        let new_vault = create_vault(&temp_layout, &passphrase, export_params.selection(), rng)?;

        if let Some(config) = &payload.config {
            let config_path = temp_layout.beside_path(BesideFile::Config);
            atomic_write(&config_path, config).map_err(|source| CliError::Io {
                context: format!("writing {}", config_path.display()),
                source,
            })?;
        }
        if let Some(wallet) = &payload.wallet {
            store_wallet_key(&new_vault, wallet, rng)?;
        }
        // U34/U18. Two rules, and the second is the interesting one:
        //
        // 1. A carried record is decoded **before** it is written — a
        //    malformed body must fail the import rather than install a
        //    record no later read can parse.
        // 2. An import always ends with at least one recorded export,
        //    even when the payload carried none. Reaching this line means
        //    an export file was just consumed, and that file *is* a
        //    backup: a vault restored from one must not greet its owner
        //    with "NO BACKUP YET" while they are holding the thing. The
        //    count is the honest minimum and the timestamp stays absent,
        //    because when that backup was taken is genuinely unknown to
        //    an export that predates the slot.
        let mut record = match &payload.bookkeeping {
            Some(bytes) => super::bookkeeping::Bookkeeping::decode(bytes)?,
            None => super::bookkeeping::Bookkeeping::default(),
        };
        if record.exports == 0 {
            record.exports = 1;
        }
        super::bookkeeping::store(&new_vault, &record, rng)?;

        let store = WorkStore::new(&new_vault);
        let mut installed = 0usize;
        for (index, work) in payload.works.iter().enumerate() {
            let record = decode_meta(work.meta.as_bytes())?;
            store.create_work(&record, rng).map_err(CliError::from)?;
            for (entry, bytes) in &work.journal {
                store
                    .put_journal_entry(&record.seal_id, *entry, bytes.as_bytes(), rng)
                    .map_err(CliError::from)?;
            }
            if let Some(receipt) = &work.receipt {
                store
                    .put_receipt(&record.seal_id, receipt.as_bytes(), rng)
                    .map_err(CliError::from)?;
            }
            for (slot, bytes) in &work.anchors {
                store
                    .put_anchor(&record.seal_id, slot, bytes.as_bytes(), rng)
                    .map_err(CliError::from)?;
            }
            installed += 1;
            if fail == ImportFailPoint::KilledMidInstall && index == 0 {
                return Err(internal("simulated kill during import (test failpoint)"));
            }
        }
        Ok((
            installed,
            payload.wallet.is_some(),
            payload.config.is_some(),
        ))
    };

    let (works, wallet_present, config_present) = match build() {
        Ok(counts) => counts,
        Err(err) => {
            // Real failures clean the temp tree up; the simulated kill
            // deliberately leaves it (that is what SIGKILL leaves).
            if fail == ImportFailPoint::None {
                let _ = std::fs::remove_dir_all(&temp_root);
            }
            return Err(err);
        }
    };

    // 6. Publish: one atomic directory rename onto the (re-checked)
    //    absent target. A concurrent creation between the check and the
    //    rename surfaces as a rename error, never a merge.
    refuse_existing_target(target).inspect_err(|_| {
        let _ = std::fs::remove_dir_all(&temp_root);
    })?;
    std::fs::rename(&temp_root, &root).map_err(|source| {
        let _ = std::fs::remove_dir_all(&temp_root);
        CliError::Io {
            context: format!("installing the imported vault at {}", root.display()),
            source,
        }
    })?;
    #[cfg(unix)]
    {
        if let Ok(dir) = std::fs::File::open(&parent) {
            let _ = dir.sync_all();
        }
    }

    // 7. Post-install verify: a fresh unlock from the final path, plus a
    //    full walk of what was installed. Failure here is loud and names
    //    the situation exactly (the vault exists but did not verify).
    post_install_verify(target, &passphrase, works, wallet_present)?;

    Ok(ImportSummary {
        vault_dir: root,
        works,
        wallet_present,
        config_present,
    })
}

/// The absolute existing-vault refusal (D39 precedent; D51: no bypass
/// flag exists in any mode — the manual move/remove is the consent).
fn refuse_existing_target(target: &VaultLayout) -> Result<(), CliError> {
    if target.beside_path(BesideFile::Header).exists() {
        return Err(CliError::ImportRefusedExistingVault {
            vault_dir: target.root().to_path_buf(),
        });
    }
    if target.root().exists() {
        return Err(CliError::Usage {
            message: format!(
                "{} exists but is not a vault (no vault header inside) — move it aside \
                 before importing",
                target.root().display()
            ),
        });
    }
    Ok(())
}

/// Fresh-unlock verification of the installed vault.
fn post_install_verify(
    target: &VaultLayout,
    passphrase: &SecretBuf,
    expected_works: usize,
    expect_wallet: bool,
) -> Result<(), CliError> {
    let fail = |detail: &str| {
        internal(&format!(
            "the imported vault was installed but failed its post-install verification \
             ({detail}) — the vault directory exists; do not trust it until `antseal list` \
             succeeds"
        ))
    };
    let vault = unlock_vault(target, passphrase).map_err(|_| fail("unlock failed"))?;
    let store = WorkStore::new(&vault);
    let ids = store
        .list_works()
        .map_err(|_| fail("work enumeration failed"))?;
    if ids.len() != expected_works {
        return Err(fail("work count mismatch"));
    }
    for id in &ids {
        store
            .load_meta(id)
            .map_err(|_| fail("a work meta record does not decrypt"))?;
    }
    if expect_wallet
        && load_wallet_key(&vault)
            .map_err(|_| fail("the wallet record does not decrypt"))?
            .is_none()
    {
        return Err(fail("the wallet record is missing"));
    }
    Ok(())
}

/// The failpoint matrix (kill/corruption seams are crate-private, so
/// these live with the engine — the session.rs precedent). The full
/// acceptance suite is `tests/vault_export.rs`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::kdf::KdfSelection;
    use crate::vault::session::create_vault;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    /// Fixed, public, NON-SECRET fixtures (project rule 6).
    const TEST_RNG_SEED: [u8; 32] = [0x42u8; 32];
    const FIXTURE_PASSPHRASE: &[u8] = b"correct horse battery staple fixture";

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "antseal-cli-export-unit-{tag}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("create test dir");
            TestDir(dir)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn passphrase() -> SecretBuf {
        SecretBuf::new(FIXTURE_PASSPHRASE.to_vec())
    }

    fn make_vault(dir: &Path) -> (VaultLayout, UnlockedVault) {
        let layout = VaultLayout::at(dir.join("vault"));
        let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);
        let vault = create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng)
            .expect("create vault");
        (layout, vault)
    }

    /// Kill after the temp write: the target path never appears; the
    /// dot-prefixed temp residue is inert; a clean re-run succeeds on
    /// the same path.
    #[test]
    fn export_killed_before_rename_leaves_no_target() {
        let dir = TestDir::new("kill");
        let (_layout, vault) = make_vault(&dir.0);
        let out = dir.0.join("backup.sealvault");
        let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);
        let err = export_vault_impl(
            &vault,
            &passphrase(),
            &out,
            &mut rng,
            ExportFailPoint::KilledAfterTempWrite,
        )
        .expect_err("simulated kill");
        assert!(matches!(err, CliError::Internal { .. }));
        assert!(!out.exists(), "no partial file at the target path");
        // Re-run completes despite the residue.
        export_vault(&vault, &passphrase(), &out, &mut rng).expect("re-run");
        assert!(out.exists());
    }

    /// A disk that lied (temp corrupted between write and verify): the
    /// mandatory self-verify fails with its distinct loud class and the
    /// target path is never written.
    #[test]
    fn export_self_verify_catches_injected_corruption() {
        let dir = TestDir::new("selfverify");
        let (_layout, vault) = make_vault(&dir.0);
        let out = dir.0.join("backup.sealvault");
        let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);
        let err = export_vault_impl(
            &vault,
            &passphrase(),
            &out,
            &mut rng,
            ExportFailPoint::CorruptTempBeforeVerify,
        )
        .expect_err("corruption must be caught");
        assert!(matches!(err, CliError::ExportSelfVerifyFailed), "{err:?}");
        assert_eq!(err.exit_code(), 32);
        assert!(
            !out.exists(),
            "an unverified export never reaches the target"
        );
    }

    /// Kill mid-install: the import validated fully, began building the
    /// temp vault, and died — the target vault does not exist at all
    /// (never a partial `~/.antseal/`), and a re-run succeeds.
    #[test]
    fn import_killed_mid_install_leaves_no_partial_vault() {
        let dir = TestDir::new("import-kill");
        let (_layout, vault) = make_vault(&dir.0);
        let out = dir.0.join("backup.sealvault");
        let mut rng = ChaCha20Rng::from_seed(TEST_RNG_SEED);

        // A vault with one work so the install loop has an iteration.
        let store = WorkStore::new(&vault);
        let record = WorkRecord {
            w: antseal_core::crypto::secrets::MasterSecret::from_bytes([0x21u8; 32]),
            seal_id: SealId::from_bytes([0xD0u8; 16]),
            network: "devnet".to_owned(),
            state: WorkState::IncompletePrePay,
            degraded: false,
            unanchored: false,
            input_paths_as_given: vec!["a.txt".to_owned()],
            input_paths_absolute: vec!["/home/fixture/a.txt".to_owned()],
            shaping: super::super::store::SealShapingFlags::default(),
            work_id: None,
            cost_atto: None,
            consent: None,
        };
        store.create_work(&record, &mut rng).expect("fixture work");
        export_vault(&vault, &passphrase(), &out, &mut rng).expect("export");

        let target = VaultLayout::at(dir.0.join("restored"));
        let err = import_vault_impl(
            &out,
            &target,
            || Ok(passphrase()),
            &mut rng,
            ImportFailPoint::KilledMidInstall,
        )
        .expect_err("simulated kill");
        assert!(matches!(err, CliError::Internal { .. }));
        assert!(
            !target.root().exists(),
            "the target vault must not exist after a mid-install kill"
        );

        // Recovery: the identical import now completes.
        let summary =
            import_vault(&out, &target, || Ok(passphrase()), &mut rng).expect("clean re-run");
        assert_eq!(summary.works, 1);
        assert!(target.beside_path(BesideFile::Header).exists());
    }
}
