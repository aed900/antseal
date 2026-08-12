//! `show <work-id>` (U27): every unit of a work — file, kind, byte-range,
//! size — and the local snippet when one can be produced.
//!
//! MVP-SPEC.md line 149: `show <work-id>` *"(every unit: file, byte-range,
//! size, local snippet when available — **the preview for `reveal
//! --units`**)"*; line 36 names the same four fields on the reveal consent
//! surface. This module is the read half of that pair: it renders the whole
//! unit table so a user can choose ids **before** anything becomes
//! irreversible.
//!
//! # What is already built, and what is here
//!
//! The computation is R15's ([`crate::preview`], under D67): the window, the
//! form judgment, the escape set, the `…` marker, the absent arm, the
//! value/rendering split, and the D43 cache-first [`VaultSnippetSource`].
//! Nothing of that is repeated here. What this module adds is exactly what
//! `show` still owed:
//!
//! - the **selection** — every normal unit of the work
//!   ([`all_normal_units`]), which makes every file fully revealed and so
//!   pulls every raw mirror in as a row of its own (D70). `show`'s table is
//!   therefore total over the manifest's units, which is what line 149's
//!   *"every unit"* asks for;
//! - the **second rung of the D43 ladder** — the current on-disk file,
//!   sliced **in the unit's commitment domain** ([`ShowSnippets`]);
//! - the vault-local **manifest resolution** (no backend exists on this
//!   path — see below);
//! - the **rendering** and the `--json` document.
//!
//! # `show` never fetches (D67 §1 j)
//!
//! U27 has no S dependency and this module holds no [`StorageBackend`]:
//! *"cache-first per D43, then current-file-marked-may-differ, then
//! absent"*. So the ladder has three rungs and no network rung — where
//! `reveal` (R16) silently **refetches** a cache copy that fails its
//! integrity recheck, `show` simply falls through to the next rung. That is
//! not a weakening of D43's rule: cache loss is never an error on either
//! path, and the row keeps file, byte-range and size regardless (D67 §3 R5).
//! The manifest is resolved the same way — the journaled plaintext copy
//! first, else the D43 cache copy of the encrypted manifest opened with
//! `k_m`, and never from Autonomi.
//!
//! # The current-file rung slices in the commitment domain, or not at all
//!
//! Unit offsets are domain-dependent (spec line 83): canonical-rendition
//! bytes for a text file's normal units, raw bytes for a binary file's, and
//! raw bytes for a raw mirror whatever its file's kind. So the fallback
//! **re-canonicalizes** a text file's current bytes with the
//! **descriptor-recorded** Unicode version — never `UnicodeVersion::CURRENT`
//! (spec line 83's "never latest") — before applying the range, and hands
//! the slice to R15 with [`SnippetProvenance::CurrentFile`] so D67's rules
//! cannot fork. Anything that stops the slice being produced in-domain — the
//! file is gone, is not a regular file, is larger than
//! [`CURRENT_FILE_READ_CAP_BYTES`], records a Unicode version this build
//! does not ship, or is now shorter than the range — degrades to the absent
//! arm. **Never an approximate raw-offset slice**: a byte window that is not
//! the committed bytes would misstate the disclosure a user is about to
//! choose.
//!
//! # Raw mirrors are marked, in the refusal's own words
//!
//! Spec line 92: a raw mirror is *"includable only via a whole-file reveal
//! (or `--all`); a bare `--units <mirror-id>` is rejected"*. The mark under
//! a mirror row is [`RevealError::RawMirrorNotUnitSelectable`]'s own
//! `Display` — the sentence R16 will actually print if the id is typed — so
//! the preview and the refusal cannot drift apart by review. In `--json` the
//! same fact is the unit row's `selectable` flag.
//!
//! # Not a verdict surface
//!
//! `show` states what a work contains, never what has been proven. It
//! borrows no sentence from [`antseal_core::verify::wording`] and coins no
//! verdict-shaped one: possession language only, no "notary", no unqualified
//! "priority" (U31).
//!
//! # Secret hygiene (project rule 6)
//!
//! `W` is borrowed from the loaded [`WorkRecord`] and reaches only
//! `antseal-core`'s `decrypt_unit`/`decrypt_manifest`; no key, salt or nonce
//! is rendered or logged. The snippet windows are ≤ 64 bytes of the user's
//! own plaintext, shown to the user who sealed it, on the surface whose job
//! is to show it (R15's Accept carves exactly this out of the secret class).
//!
//! [`StorageBackend`]: antseal_net::StorageBackend
//! [`WorkRecord`]: crate::vault::store::WorkRecord
//! [`VaultSnippetSource`]: crate::preview::VaultSnippetSource

use std::borrow::Cow;
use std::collections::BTreeMap;

use antseal_core::canon::{CanonicalBytes, canonicalize_v_forced};
use antseal_core::crypto::manifest_aead::decrypt_manifest;
use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::unit_aead::Nonce24 as AeadNonce;
use antseal_core::manifest::{
    CanonMode, DescriptorKind, FineTreeDomain, Manifest, ManifestBodyV1, UnitEntry, UnitKind,
    work_id as manifest_work_id,
};

use crate::error::CliError;
use crate::pipeline::journal::{BlobSlot, StagedBlob, check_staged_integrity, recorded_plan};
use crate::pipeline::restore::{ManifestSource, RestoreError, hex32};
use crate::pipeline::reveal::RevealError;
use crate::preview::{
    DisclosurePreview, PreviewRow, Snippet, SnippetProvenance, SnippetSource, SnippetWindow,
    SourcedPlaintext, VaultSnippetSource, all_normal_units, disclosure_preview,
    escape_for_terminal, render_snippet,
};
use crate::status::{hex_seal, work_state_name};
use crate::vault::store::{WorkState, WorkStore};

/// How large a current on-disk file may be before the fallback rung
/// declines to read it (64 MiB).
///
/// The rung exists to show a **≤ 64-byte** window of a file the user still
/// has. Reading a multi-gigabyte input into memory to produce one is a real
/// cost with no snippet gain, and `show` is an interactive command. The
/// whole file is what must be read — a snippet is cut from the unit's
/// *complete* plaintext (R15 treats a short source as unavailable rather
/// than window a partial one), and a raw mirror's unit **is** the whole
/// file — so the cap is on the file, not on the window.
///
/// Over the cap the row takes the absent arm, which D67 §3 R5 permits with
/// no reason carried. There is deliberately **no cap on the cache rung**:
/// that rung reads one unit's stored ciphertext, whose size the seal already
/// chose.
pub const CURRENT_FILE_READ_CAP_BYTES: u64 = 64 * 1024 * 1024;

/// Indent of a file row (the house's two spaces — `status::WorkStatus::render`,
/// `redaction_out::FILE_INDENT`).
const FILE_INDENT: &str = "  ";

/// Indent of a unit row beneath its file.
const UNIT_INDENT: &str = "      ";

/// Indent of a note beneath a unit row.
const NOTE_INDENT: &str = "          ";

// ─────────────────────────────────────────────────────────────────────────
// The current-file rung (D43's second source; D67 §3 R5's domain rule)
// ─────────────────────────────────────────────────────────────────────────

/// Which byte domain a unit's offsets index into (spec line 83).
///
/// Spelled with the registry's own [`FineTreeDomain`] values (`raw` /
/// `canonical`) rather than a second vocabulary: line 83 makes the offset
/// domain and the fine-tree domain the same domain — canonical for text,
/// raw for binary — so a file whose fine tree is **absent** still has the
/// domain its kind implies, and its offsets still mean that.
#[must_use]
pub const fn offset_domain(canon: &CanonMode, kind: UnitKind) -> FineTreeDomain {
    match kind {
        // A mirror is raw-domain whatever its file's kind — that is what it
        // is for (spec line 92).
        UnitKind::RawMirror => FineTreeDomain::Raw,
        UnitKind::Normal => canon.kind().fine_tree_domain(),
    }
}

/// `show`'s snippet source: the D43 ladder, whole.
///
/// Rung 1 is R15's [`VaultSnippetSource`] verbatim — the retained
/// journal→cache ciphertext, integrity-rechecked against the **manifest's**
/// address and decrypted with the unit's own `k_u`. Rung 2 is the current
/// on-disk file, sliced in the unit's commitment domain. Rung 3 is `None`,
/// the absent arm.
///
/// Every failure at every rung is a fall-through, never an error: under D43
/// cache loss is never an error, and under D67 §3 R5 an absent snippet still
/// leaves a complete row.
pub struct ShowSnippets<'a, 'v> {
    vault: VaultSnippetSource<'a, 'v>,
    body: &'a ManifestBodyV1,
    absolute_paths: &'a [String],
    /// `unit_id` → index into `body.files()`. Built once so a lookup is not
    /// a scan of the whole unit table per unit.
    file_of_unit: BTreeMap<u64, usize>,
    /// `(file index, domain)` → that file's current bytes in that domain,
    /// or `None` for "tried, and it cannot be produced". Cached so a
    /// multi-unit file is read and canonicalized once. The domain half of
    /// the key is [`FineTreeDomain::to_wire`] — the registry's own value —
    /// because the enum is `Hash + Eq` but not `Ord`.
    domains: BTreeMap<(usize, u64), Option<Vec<u8>>>,
}

impl<'a, 'v> ShowSnippets<'a, 'v> {
    /// A source over one work: the unlocked vault's store, the work's seal
    /// id and `W` (rung 1), and the manifest plus the vault-recorded
    /// **absolute** paths (rung 2).
    ///
    /// The absolute spellings are the ones D45 stores for exactly this kind
    /// of use — the as-given spellings are relative to the cwd the seal ran
    /// in, which is not necessarily this one.
    #[must_use]
    pub fn new(
        store: &'a WorkStore<'v>,
        seal_id: SealId,
        w: MasterSecretRef<'a>,
        body: &'a ManifestBodyV1,
        absolute_paths: &'a [String],
    ) -> Self {
        let file_of_unit = body
            .files()
            .iter()
            .enumerate()
            .flat_map(|(index, file)| file.units().iter().map(move |u| (u.unit_id(), index)))
            .collect();
        Self {
            vault: VaultSnippetSource::new(store, seal_id, w),
            body,
            absolute_paths,
            file_of_unit,
            domains: BTreeMap::new(),
        }
    }

    /// Rung 1, forced to an owned value so no borrow of `self.vault`
    /// outlives the call and rung 2 can still borrow `self`.
    fn sealed_bytes(&mut self, unit: &UnitEntry) -> Option<Vec<u8>> {
        self.vault
            .plaintext(unit)
            .map(|sourced| sourced.bytes.into_owned())
    }

    /// Rung 2: the unit's byte range taken from the **current** file, in the
    /// unit's own commitment domain, or `None`.
    fn current_file_slice(&mut self, unit: &UnitEntry) -> Option<&[u8]> {
        let index = *self.file_of_unit.get(&unit.unit_id())?;
        let file = self.body.files().get(index)?;
        let domain = offset_domain(file.canon(), unit.kind());
        let key = (index, domain.to_wire());
        if !self.domains.contains_key(&key) {
            // Computed before the insert, not inside it: `read_domain`
            // borrows `self` shared and `domains` would be borrowed mutably.
            let loaded = self.read_domain(index, domain);
            self.domains.insert(key, loaded);
        }
        let bytes = self.domains.get(&key)?.as_ref()?;
        let start = usize::try_from(unit.range().start()).ok()?;
        let end = start.checked_add(usize::try_from(unit.range().length()).ok()?)?;
        bytes.get(start..end)
    }

    /// One file's current bytes in `domain`, or `None` when they cannot be
    /// produced. Never an error: every arm here is a fall-through.
    ///
    /// The `stat` comes **before** the open, deliberately: opening a fifo
    /// blocks until a writer appears, so a path that is no longer a regular
    /// file has to be rejected without opening it. The read is then bounded
    /// independently of that `stat` — a file that grew past the cap in
    /// between is refused rather than read whole.
    fn read_domain(&self, index: usize, domain: FineTreeDomain) -> Option<Vec<u8>> {
        use std::io::Read as _;

        let path = self.absolute_paths.get(index)?;
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() {
            // A directory, a fifo or a device where a file was sealed: the
            // bytes could not be the sealed ones anyway.
            tracing::debug!(
                file_id = index,
                "no snippet: the sealed path is not a regular file"
            );
            return None;
        }
        if meta.len() > CURRENT_FILE_READ_CAP_BYTES {
            tracing::debug!(
                file_id = index,
                "no snippet: the current file is over the read cap"
            );
            return None;
        }
        let handle = std::fs::File::open(path).ok()?;
        let mut raw = Vec::new();
        handle
            .take(CURRENT_FILE_READ_CAP_BYTES.saturating_add(1))
            .read_to_end(&mut raw)
            .ok()?;
        if raw.len() as u64 > CURRENT_FILE_READ_CAP_BYTES {
            tracing::debug!(
                file_id = index,
                "no snippet: the current file grew past the read cap"
            );
            return None;
        }
        match domain {
            FineTreeDomain::Raw => Some(raw),
            FineTreeDomain::Canonical => {
                // Spec line 83: the **descriptor-recorded** version, never
                // "latest" — the same rule the verifier's raw-mirror
                // recompute follows. `_forced` is the seal side's own mode
                // (`content::assemble` canonicalizes forced), so unchanged
                // bytes reproduce the sealed canonical rendition exactly,
                // and modified bytes still canonicalize totally.
                let version = self.body.files().get(index)?.canon().unicode_version()?;
                canonicalize_v_forced(version, &raw)
                    .ok()
                    .map(CanonicalBytes::into_bytes)
            }
        }
    }
}

impl SnippetSource for ShowSnippets<'_, '_> {
    fn plaintext(&mut self, unit: &UnitEntry) -> Option<SourcedPlaintext<'_>> {
        if let Some(bytes) = self.sealed_bytes(unit) {
            return Some(SourcedPlaintext {
                bytes: Cow::Owned(bytes),
                provenance: SnippetProvenance::SealedBytes,
            });
        }
        let slice = self.current_file_slice(unit)?;
        Some(SourcedPlaintext {
            bytes: Cow::Borrowed(slice),
            provenance: SnippetProvenance::CurrentFile,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The document
// ─────────────────────────────────────────────────────────────────────────

/// One file of the work, as `show` states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    /// Manifest file id (= index into the vault's recorded path list).
    pub file_id: u64,
    /// The path as the vault recorded it at seal time.
    pub path: String,
    /// Text or binary, as committed in the signed manifest — never
    /// re-sniffed at display time (D67 §3 R2).
    pub kind: DescriptorKind,
    /// Which byte domain this file's normal units' offsets index into.
    pub offset_domain: FineTreeDomain,
    /// Whether a fine tree covers this file. `false` is `--no-fine-tree`
    /// (or an empty file) and means the file is whole-file-reveal only,
    /// permanently — which is also why it is single-unit (D24).
    pub fine_tree: bool,
    /// The tiling-domain byte count: canonical bytes for text, raw for
    /// binary (spec line 98). A text file's *raw* size travels as its
    /// mirror's `true_length`.
    pub size: u64,
    /// The exact Unicode data version NFC was frozen at, for a text file
    /// (spec line 83).
    pub unicode_version: Option<String>,
    /// This file's raw-mirror unit id, when it has one.
    pub raw_mirror_unit_id: Option<u64>,
}

/// One work's complete unit table — the `show` document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkUnits {
    /// `work_id = SHA-256(manifest body)`; absent until the manifest
    /// exists (unreachable through the CLI, which resolves *by* work id).
    pub work_id: Option<[u8; 32]>,
    /// The vault's store key.
    pub seal_id: SealId,
    /// `--title`, as recorded.
    pub title: Option<String>,
    /// The work's network, canonical CLI spelling.
    pub network: String,
    /// The coarse completion state.
    pub state: WorkState,
    /// Where the manifest was recovered from. Never
    /// [`ManifestSource::Network`]: `show` holds no backend.
    pub manifest_source: ManifestSource,
    /// Every file, in manifest order.
    pub files: Vec<FileRow>,
    /// R15's preview over **every** unit of the work, with the D67
    /// snippets. `preview.rows` is the unit table this command prints.
    pub preview: DisclosurePreview,
}

impl WorkUnits {
    /// Read one work and build its unit table, snippets included.
    ///
    /// Reads only: no lock is taken (the U5 lock serializes writers, and
    /// making the command you reach for when something looks wrong wait
    /// behind a running seal is the trade `list` and `status` already
    /// refused), and nothing is written anywhere.
    ///
    /// # Errors
    ///
    /// The manifest-resolution classes ([`RestoreError`] through its
    /// existing mapping — no new error class is minted here) and
    /// store-level failures. A missing snippet is **not** among them.
    pub fn gather(store: &WorkStore<'_>, seal_id: &SealId) -> Result<Self, CliError> {
        let record = store.load_meta(seal_id).map_err(CliError::from)?;
        let w = record.w.secret_ref();
        let (manifest_bytes, manifest_source) = local_manifest(store, seal_id, w)?;
        let manifest =
            Manifest::decode(&manifest_bytes).map_err(|err| RestoreError::ManifestMalformed {
                detail: err.to_string(),
            })?;
        let body = manifest.body();

        // Identity binding, exactly as `restore` does it: the manifest this
        // vault holds under this key must be *this* work's, and must be the
        // one whose hash the record names.
        if body.seal_id() != seal_id {
            return Err(RestoreError::ManifestIdentityMismatch { detail: "seal_id" }.into());
        }
        let work_id = manifest_work_id(manifest.body_bytes()).into_bytes();
        if let Some(recorded) = record.work_id
            && recorded != work_id
        {
            return Err(RestoreError::ManifestIdentityMismatch { detail: "work_id" }.into());
        }

        let paths = &record.input_paths_as_given;
        if paths.len() != body.files().len() {
            return Err(RestoreError::MalformedRecord {
                detail: format!(
                    "the vault records {} original path(s) for a work whose manifest has {} \
                     file(s)",
                    paths.len(),
                    body.files().len()
                ),
            }
            .into());
        }

        let files = body
            .files()
            .iter()
            .enumerate()
            .map(|(index, file)| FileRow {
                file_id: index as u64,
                path: paths[index].clone(),
                kind: file.canon().kind(),
                offset_domain: offset_domain(file.canon(), UnitKind::Normal),
                fine_tree: file.fine_tree().is_present(),
                size: file.size(),
                unicode_version: file.canon().unicode_version().map(ToOwned::to_owned),
                raw_mirror_unit_id: file.raw_mirror().map(UnitEntry::unit_id),
            })
            .collect();

        // Every normal unit: each file is then fully revealed under D28's
        // frozen predicate, so every raw mirror rides along (D70) and the
        // table is total over the manifest's units — line 149's "every
        // unit".
        let selection = all_normal_units(body);
        let mut source = ShowSnippets::new(
            store,
            *seal_id,
            w,
            body,
            record.input_paths_absolute.as_slice(),
        );
        let preview = disclosure_preview(body, paths, &selection, &mut source).map_err(|err| {
            RestoreError::MalformedRecord {
                detail: err.to_string(),
            }
        })?;

        Ok(Self {
            work_id: record.work_id,
            seal_id: *seal_id,
            title: record.shaping.title.clone(),
            network: record.network.clone(),
            state: record.state,
            manifest_source,
            files,
            preview,
        })
    }

    /// The unit rows, in manifest order.
    #[must_use]
    pub fn rows(&self) -> &[PreviewRow] {
        &self.preview.rows
    }

    /// The human report, as lines (the caller routes them to stdout or —
    /// under `--json` — to stderr, D51).
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let id = self.work_id.as_ref().map_or_else(
            || format!("(no work id yet; seal {})", hex_seal(&self.seal_id)),
            hex32,
        );
        let mut out = vec![
            format!("{id}  {}", work_state_name(self.state)),
            format!(
                "{FILE_INDENT}{}   {}",
                self.title.as_deref().unwrap_or("(untitled)"),
                self.network
            ),
            format!(
                "{FILE_INDENT}{} unit(s) across {} file(s); {} byte(s) sealed",
                self.preview.totals.units,
                self.files.len(),
                self.preview.totals.bytes,
            ),
            format!("{FILE_INDENT}{UNIT_IDS_NOTE}"),
        ];

        // The **file list** drives the loop, not the row list: a file whose
        // rows are all missing still gets a header, so a work cannot lose a
        // file from its own table silently. (Rows carry `file_id`, so this
        // holds whatever order they arrive in.)
        for file in &self.files {
            out.push(format!("{FILE_INDENT}{}", file_line(file)));
            for row in self.rows().iter().filter(|row| row.file_id == file.file_id) {
                out.push(format!("{UNIT_INDENT}{}", unit_line(row, file)));
                if row.kind == UnitKind::RawMirror {
                    out.push(format!("{NOTE_INDENT}{}", mirror_note(row.unit_id)));
                }
            }
        }
        out
    }

    /// The `--json` result document (U3's envelope wraps it).
    ///
    /// **Tier C** under D65 §3 — reviewed by the committed fixture, not
    /// promised until U32 — and it carries no tier-A member, so the
    /// alphabetization every `serde_json::Value` document undergoes here
    /// (`serde_json::Map` is a `BTreeMap` in this build; D65 §1 f) costs
    /// nothing: no key order in this document is contractual. D65 §7's two
    /// rules that ride tier C anyway are honoured — **every key is always
    /// present**, `null` where the value is absent, and no key's JSON type
    /// varies run to run.
    ///
    /// Byte counts ride as JSON numbers (`restore`'s per-file `bytes`
    /// precedent) except the work total, which is a `u128` sum of
    /// sealer-authored lengths and therefore a **decimal string** — D65 §7's
    /// rule for any integer that can exceed 2⁵³, and the same reason
    /// `cost_atto` is one.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "work_id": self.work_id.as_ref().map(hex32),
            "seal_id": hex_seal(&self.seal_id),
            "title": self.title,
            "network": self.network,
            "state": work_state_name(self.state),
            "manifest_source": self.manifest_source.name(),
            "counts": {
                "units": self.preview.totals.units,
                "files": self.files.len(),
                "bytes": self.preview.totals.bytes.to_string(),
            },
            "files": self.files.iter().map(|file| serde_json::json!({
                "file_id": file.file_id,
                "path": file.path,
                "kind": file.kind.registry_value_name(),
                "offset_domain": file.offset_domain.registry_value_name(),
                "fine_tree": file.fine_tree,
                "whole_file_reveal_only": !file.fine_tree,
                "size": file.size,
                "unicode_version": file.unicode_version,
                "raw_mirror_unit_id": file.raw_mirror_unit_id,
            })).collect::<Vec<_>>(),
            "units": self.rows().iter().map(|row| serde_json::json!({
                "unit_id": row.unit_id,
                "file_id": row.file_id,
                "path": row.path,
                "kind": row.kind.registry_value_name(),
                // Spec line 92, as the machine fact: a raw mirror is never
                // selectable by id. The human form is `mirror_note`.
                "selectable": row.kind != UnitKind::RawMirror,
                "offset_domain": self.domain_of(row).registry_value_name(),
                "byte_range": {
                    "start": row.range.start(),
                    "length": row.range.length(),
                },
                "size": row.size,
                "snippet": row.snippet.as_ref().map(snippet_json),
            })).collect::<Vec<_>>(),
        })
    }

    /// A row's byte domain, resolved through its file's committed kind.
    fn domain_of(&self, row: &PreviewRow) -> FineTreeDomain {
        match row.kind {
            UnitKind::RawMirror => FineTreeDomain::Raw,
            UnitKind::Normal => self
                .files
                .iter()
                .find(|file| file.file_id == row.file_id)
                .map_or(FineTreeDomain::Raw, |file| file.offset_domain),
        }
    }
}

/// The one sentence that says what the ids are for (spec line 149's *"the
/// preview for `reveal --units`"*).
const UNIT_IDS_NOTE: &str = "the unit ids below are the ones `reveal --units` takes; snippets are shown from your own \
     copy and are not part of any proof";

/// The `[…]` provenance tag after a snippet (D67 §3 R5 leaves the copy to
/// U27; the **discriminant** is carried in the data and never re-derived).
///
/// The sealed-bytes tag is short because it is the ordinary case; the
/// current-file tag carries its whole warning because it is the one a reader
/// must act on.
const fn provenance_tag(provenance: SnippetProvenance) -> &'static str {
    match provenance {
        SnippetProvenance::SealedBytes => "[sealed bytes]",
        SnippetProvenance::CurrentFile => "[current file — may differ if modified since sealing]",
    }
}

/// One file's header line.
///
/// The path goes through D67 §3 R3's **closed** escape set
/// ([`escape_for_terminal`], the one R19's redaction view also calls) rather
/// than through `{:?}`: `escape_debug` tracks Unicode data across
/// toolchains, which is the exact rot D67 refused for a snapshot-frozen
/// rendering. Escaping LF is the load-bearing half here too — it makes the
/// header exactly one line, so a path carrying `"\n      unit 9   normal …"`
/// cannot forge a unit row beneath it. The quotes are the delimiter, and
/// with `\"` in the set nothing inside can close them early.
fn file_line(file: &FileRow) -> String {
    format!(
        "file #{} \"{}\" — {}, {} byte(s); unit offsets are {} bytes; {}",
        file.file_id,
        escape_for_terminal(&file.path),
        file.kind.registry_value_name(),
        file.size,
        file.offset_domain.registry_value_name(),
        if file.fine_tree {
            "fine tree present"
        } else {
            "no fine tree — whole-file reveal only"
        }
    )
}

/// One unit's row: id, kind, size, position, snippet, provenance.
///
/// The three figures a reader needs to place the unit — size, offset and the
/// domain total it sits in — are on every row by construction, with no arm
/// that drops one (the discipline `redaction_out` states for the verify
/// side; here it is what makes a `--units` choice an informed one).
fn unit_line(row: &PreviewRow, file: &FileRow) -> String {
    // A mirror's domain total is its own raw size; a normal unit's is the
    // file's tiling-domain size.
    let total = match row.kind {
        UnitKind::RawMirror => row.size,
        UnitKind::Normal => file.size,
    };
    let rendered = render_snippet(row.snippet.as_ref());
    let tag = row
        .snippet
        .as_ref()
        .map_or("", |snippet| provenance_tag(snippet.provenance));
    format!(
        "unit {}   {}   {} byte(s) at offset {} of {}   {rendered}{}{tag}",
        row.unit_id,
        row.kind.registry_value_name(),
        row.size,
        row.range.start(),
        total,
        if tag.is_empty() { "" } else { "   " },
    )
}

/// The raw-mirror mark, **in the refusal's own words**.
///
/// This is [`RevealError::RawMirrorNotUnitSelectable`]'s `Display` — the
/// exact sentence a user who types `--units <mirror-id>` will be told (R16
/// produces it through G7's `mirror_selectable`, spec line 92). Taking the
/// string from the error rather than restating it is what makes the preview
/// and the refusal agree by construction: a reworded refusal moves this mark
/// with it, and `show`'s snapshot goes red so the change is reviewed.
fn mirror_note(unit_id: u64) -> String {
    RevealError::RawMirrorNotUnitSelectable { unit_id }.to_string()
}

/// One snippet as `--json` (D67 §3 R6): the **raw window value**, the form
/// discriminant, the truncation flag and the provenance. Quotes, `hex:` and
/// the `…` marker are terminal rendering and never appear here, so no
/// consumer parses a marker out of data.
fn snippet_json(snippet: &Snippet) -> serde_json::Value {
    let (form, value) = match &snippet.window {
        // serde's own string escaping, not D67 §3 R3's — the value is the
        // window, unmodified.
        SnippetWindow::Text(text) => ("text", text.clone()),
        // Bare lowercase pairs, without the `hex:` label.
        SnippetWindow::Hex(bytes) => ("hex", {
            use std::fmt::Write as _;
            let mut out = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                let _ = write!(out, "{byte:02x}");
            }
            out
        }),
    };
    serde_json::json!({
        "form": form,
        "value": value,
        "truncated": snippet.truncated,
        "provenance": snippet.provenance.name(),
    })
}

// ─────────────────────────────────────────────────────────────────────────
// Vault-local manifest resolution (S14's two local sources, no network)
// ─────────────────────────────────────────────────────────────────────────

/// The manifest envelope bytes from the vault alone: the journaled
/// plaintext copy first (free, vault-AEAD-authenticated), else the D43 cache
/// copy of the encrypted manifest blob, integrity-rechecked and opened with
/// `k_m`.
///
/// `show` has no backend, so a work holding neither is
/// [`RestoreError::ManifestUnavailable`] — the same class `restore` raises
/// for the same vault state, through the same existing mapping.
fn local_manifest(
    store: &WorkStore<'_>,
    seal_id: &SealId,
    w: MasterSecretRef<'_>,
) -> Result<(Vec<u8>, ManifestSource), CliError> {
    if let Some(plan) = recorded_plan(store, seal_id).map_err(CliError::from)?
        && let Some(bytes) = plan.manifest_bytes
    {
        return Ok((bytes, ManifestSource::VaultCopy));
    }

    let Some(blob) = staged_blob(store, seal_id, BlobSlot::EncryptedManifest)? else {
        return Err(RestoreError::ManifestUnavailable.into());
    };
    // D43's recheck before use. A failure here is not an error: with no
    // backend there is nothing to refetch, so it is the same state as no
    // cache copy at all.
    if check_staged_integrity(&blob).is_err() {
        tracing::debug!("the cached encrypted-manifest copy failed its integrity recheck");
        return Err(RestoreError::ManifestUnavailable.into());
    }
    let nonce = AeadNonce::from_bytes(blob.nonce);
    let bytes =
        decrypt_manifest(w, &nonce, &blob.ciphertext).map_err(|_| RestoreError::ManifestDecrypt)?;
    Ok((bytes, ManifestSource::Cache))
}

/// One staged blob record, decoded; `None` when the slot holds nothing or
/// the record does not name the slot it was filed under.
fn staged_blob(
    store: &WorkStore<'_>,
    seal_id: &SealId,
    slot: BlobSlot,
) -> Result<Option<StagedBlob>, CliError> {
    let Some(entry) = slot.entry_key() else {
        return Ok(None);
    };
    let Some(record) = store
        .get_journal_entry(seal_id, entry)
        .map_err(CliError::from)?
    else {
        return Ok(None);
    };
    let Ok(blob) = StagedBlob::decode(record.as_bytes()) else {
        return Ok(None);
    };
    Ok((blob.slot == slot).then_some(blob))
}

#[cfg(test)]
#[path = "show/tests.rs"]
mod tests;
