//! The disclosure-preview computation (R15) under decision **D67**
//! (docs/decisions/D67-disclosure-preview-snippet-format.md).
//!
//! For a resolved reveal selection this module produces the exact data the
//! irreversible-disclosure confirmation prints and that `show` reuses
//! (MVP-SPEC.md lines 36 and 149): one row per disclosed unit — file path
//! from the vault, byte-range, size, snippet — plus totals (units, bytes,
//! files touched, which files become fully revealed, whether a raw mirror
//! rides along). Consumers: R16's reveal flow feeds it to U29's consent
//! gate; U27's `show` renders it for every unit of a work. This module
//! ships **no CLI surface** — rendering copy, prompts and `--json` shape
//! belong to U27/U28/U29.
//!
//! # Home (D34 / D67 §3 R8)
//!
//! Per D34 the reveal-flow orchestration lives in this `antseal_cli`
//! library target, and D67 R8 puts the window/escape/hex helpers and both
//! caps beside R15's computation here. `antseal-core` is untouched: the
//! verifier never renders a snippet and its report types are prohibited
//! from growing one (`verify/report.rs`, `UnrevealedFilePlaceholder`).
//!
//! # Value vs rendering (D67 §3 R6)
//!
//! [`Snippet`] is the **value**: the raw window bytes, the form judgment,
//! the `truncated` flag and the provenance discriminant. Quotes, the
//! `hex:` label, the escape set and the `…` marker are **terminal
//! rendering only** ([`Snippet::render`] / [`render_snippet`]) and never
//! appear inside the value — a later `--json` surface carries the value
//! side untouched (serde's own string escaping, bare hex pairs), so no
//! consumer ever parses a marker out of data.
//!
//! # The snippet rules, in force here (D67 §3)
//!
//! - **R1 window**: a prefix of the unit's **post-padding-strip**
//!   plaintext — [`TEXT_SNIPPET_CAP_BYTES`] (64) for the text form,
//!   [`HEX_SNIPPET_CAP_BYTES`] (16) for the hex form;
//!   `truncated ⟺ window length < true_length`.
//! - **R2 form**: judged from the manifest's committed domain only —
//!   `Text` iff `kind = Normal ∧ CanonMode::Text` and the boundary-cut
//!   window is valid UTF-8; everything else (raw mirrors always, binary
//!   files always, UTF-8 failure) is `Hex`. Never `from_utf8_lossy`,
//!   never content re-sniffing.
//! - **R3 text rendering**: cut backed off ≤ 3 bytes to a UTF-8
//!   code-point boundary (the house `truncate_for_echo` pattern; grapheme
//!   handling stays parked per spec lines 96/161); the closed escape set
//!   below; marker outside the closing quote so content cannot forge it.
//! - **R4 hex rendering**: `hex:` + ungrouped lowercase pairs — the
//!   product's only hex spelling.
//! - **R5 absent arm**: the snippet slot is `Option`-shaped with **no
//!   reason carried**; rendering is the literal [`SNIPPET_UNAVAILABLE`],
//!   and the row keeps file/byte-range/size intact.
//!
//! # Plaintext sourcing
//!
//! Sourcing is a seam ([`SnippetSource`]), because the two consumers
//! differ (D67 §1 j): R16 already holds every touched file's decrypted
//! plaintext (it gathers and decrypts for the tree rebuild) and hands it
//! over via [`SealedPlaintexts`]; `show` never fetches — it decrypts the
//! D43 journal→cache ciphertext via [`VaultSnippetSource`]
//! (integrity-rechecked, degrading to the absent arm on any failure,
//! because cache loss is never an error under D43). U27's
//! current-file-marked-may-differ fallback stays U27's: it must slice in
//! the unit's commitment domain (re-canonicalize per spec line 83) and
//! then feeds the slice through [`cut_snippet`] with
//! [`SnippetProvenance::CurrentFile`], so the D67 rules cannot fork. The
//! data carries the provenance discriminant; the label copy is U27's and
//! is never re-derived at render time (D67 §3 R5).
//!
//! Only disclosed units are ever sourced — a unit outside the selection
//! is never decrypted by this module.
//!
//! # Annotations the consent gate must say (D28, D70)
//!
//! Selecting every normal unit of a file — by `--all` or by enumerating
//! ids — **is** a full reveal (`full(F) ⟺ N(F) ≠ ∅ ∧ R(F) = N(F)`, the
//! frozen D28 predicate, same as `verify/file_stages.rs`), and a full
//! reveal opens the whole-file commitments and pulls the raw mirror in
//! (D70). Rows carry `file_fully_revealed`; [`FilePreview`] and
//! [`PreviewTotals`] carry the mirror-rides-along annotation, derived
//! from the same `full(F) ∧ has-mirror` predicate the builder uses so the
//! preview matches the eventual bundle by construction (D70 §7.6).
//!
//! # Secret hygiene (project rule 6)
//!
//! Nothing here derives or stores `W`, unit keys or any salt beyond the
//! transient `k_u` inside [`VaultSnippetSource`]'s decrypt call, which
//! lives and dies inside `antseal-core`'s `decrypt_unit`. The snippet
//! window is ≤ 64 bytes of the plaintext being **deliberately disclosed**
//! — R15's Accept carves exactly this out of the secret class — so the
//! preview types derive ordinary `Debug`. No error variant carries key
//! material.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use antseal_core::crypto::hkdf::UnitId;
use antseal_core::crypto::material::MasterSecretRef;
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::unit_aead::{Nonce24 as AeadNonce, decrypt_unit};
use antseal_core::manifest::{ByteRange, CanonMode, ManifestBodyV1, UnitEntry, UnitKind};
use thiserror::Error;

use crate::pipeline::journal::{BlobSlot, StagedBlob, check_staged_integrity};
use crate::vault::store::WorkStore;

// ─────────────────────────────────────────────────────────────────────────
// D67 constants (§3 R1, R3, R4, R5) — pinned by this module's tests
// ─────────────────────────────────────────────────────────────────────────

/// Text-form window cap in **bytes** (D67 §3 R1): the house's measured
/// bound for user-controlled text echoed to a terminal (64 — the
/// `truncate_for_echo` bound). Bytes, not chars: every neighbouring row
/// figure is byte-denominated.
pub const TEXT_SNIPPET_CAP_BYTES: usize = 64;

/// Hex-form window cap in **bytes** (D67 §3 R1): one classic hexdump row,
/// covering the leading file magics that make binary bytes recognisable
/// (PNG 8, PDF 5, ZIP 4, gzip 3, ELF `e_ident` exactly 16).
pub const HEX_SNIPPET_CAP_BYTES: usize = 16;

/// The truncation marker (D67 §3 R3): rendered **outside** the closing
/// quote (text) or after the pairs (hex), so content — where U+2026 is an
/// ordinary passthrough code point — cannot forge it.
pub const TRUNCATION_MARKER: char = '\u{2026}';

/// The absent-arm rendering (D67 §3 R5). Reason-free by ruling: the
/// causes differ by surface and a reasoned string would lie on one of
/// them.
pub const SNIPPET_UNAVAILABLE: &str = "(snippet unavailable)";

/// Maximum boundary back-off in bytes (D67 §3 R3: "0–3 bytes"): a UTF-8
/// code point is at most 4 bytes, so a cut landing inside one is at most
/// 3 bytes past its start. Bounded so adversarial non-UTF-8 windows
/// cannot walk the cut backwards; a window still invalid after the
/// back-off takes the hex arm via the R2 validity check.
const MAX_BOUNDARY_BACKOFF_BYTES: usize = 3;

// ─────────────────────────────────────────────────────────────────────────
// The snippet value (D67 §3 R1/R2 + R6)
// ─────────────────────────────────────────────────────────────────────────

/// Where a snippet's plaintext came from (D67 §3 R5). Carried in the
/// data so the rendering label ("sealed bytes" vs "current file — may
/// differ if modified since sealing", U27's copy) is never re-derived at
/// render time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnippetProvenance {
    /// Decrypted exact sealed bytes (D43 cache, or R16's gathered
    /// plaintexts).
    SealedBytes,
    /// Sliced from the current on-disk file in the unit's commitment
    /// domain (U27's fallback; the file may have changed since sealing).
    CurrentFile,
}

impl SnippetProvenance {
    /// Stable kebab identifier for machine renders (the `--json` shape
    /// itself is the D65/U50 family's, not R15's).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SealedBytes => "sealed-bytes",
            Self::CurrentFile => "current-file",
        }
    }
}

/// The raw snippet window with its D67 §3 R2 form judgment.
///
/// The invariant "text form ⇒ valid UTF-8" is carried by the type: the
/// `Text` variant holds a `String`, so a window that failed validation is
/// unrepresentable as text (it takes the [`SnippetWindow::Hex`] arm at
/// construction — never `from_utf8_lossy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnippetWindow {
    /// A valid-UTF-8 text window (≤ [`TEXT_SNIPPET_CAP_BYTES`] bytes,
    /// boundary-cut). Raw value: control and bidi code points are
    /// **present unescaped** here; escaping is rendering-only.
    Text(String),
    /// A raw-byte window (≤ [`HEX_SNIPPET_CAP_BYTES`] bytes): raw
    /// mirrors always, binary-file units always, and the defensive
    /// UTF-8-failure arm of a text-domain unit.
    Hex(Vec<u8>),
}

/// One unit's snippet **value** (D67 §3 R6): window + form + truncated
/// flag + provenance. Rendering (quotes, `hex:`, escapes, the marker) is
/// [`Snippet::render`]'s and never part of the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snippet {
    /// The window and its judged form.
    pub window: SnippetWindow,
    /// `true ⟺ window length < true_length` (D67 §3 R1).
    pub truncated: bool,
    /// Where the plaintext came from.
    pub provenance: SnippetProvenance,
}

impl Snippet {
    /// Terminal rendering of this snippet (D67 §3 R3/R4): the escaped
    /// window inside quotes (text) or `hex:` + ungrouped lowercase pairs
    /// (hex), with the `…` marker appended outside iff truncated.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        match &self.window {
            SnippetWindow::Text(text) => {
                out.push('"');
                out.push_str(&escape_text_window(text));
                out.push('"');
            }
            SnippetWindow::Hex(bytes) => {
                out.push_str("hex:");
                for byte in bytes {
                    let _ = write!(out, "{byte:02x}");
                }
            }
        }
        if self.truncated {
            out.push(TRUNCATION_MARKER);
        }
        out
    }
}

/// Render a row's snippet slot, absent arm included (D67 §3 R5): `None`
/// renders as the literal [`SNIPPET_UNAVAILABLE`].
#[must_use]
pub fn render_snippet(snippet: Option<&Snippet>) -> String {
    match snippet {
        Some(snippet) => snippet.render(),
        None => SNIPPET_UNAVAILABLE.to_owned(),
    }
}

/// Cut one unit's snippet from its full plaintext — the single
/// implementation of D67 §3 R1 (window) + R2 (form judgment), shared by
/// this module's row builder and by U27's current-file fallback so the
/// rules cannot fork.
///
/// `plaintext` is the unit's complete **post-padding-strip** bytes in its
/// commitment domain (canonical for a text file's normal units, raw for
/// binary files and raw mirrors) — exactly what `decrypt_unit` returns.
/// The form is judged from the committed domain (`kind` × `canon`), never
/// by sniffing `plaintext`:
///
/// - `kind = Normal` ∧ `CanonMode::Text` → the text arm: first
///   [`TEXT_SNIPPET_CAP_BYTES`] bytes, cut backed off to a UTF-8
///   code-point boundary (≤ 3 bytes); if the cut
///   window is not valid UTF-8 (impossible for honest sealed data — D67
///   §1 f; reachable via a corrupt cache or a modified current file) it
///   **drops to the hex arm**, never to lossy substitution.
/// - everything else → the hex arm: first [`HEX_SNIPPET_CAP_BYTES`]
///   bytes. Raw mirrors take this arm even for text files (a BOM renders
///   invisibly as text — D67 §1 g), and binary-file units take it even
///   when their bytes happen to decode as UTF-8 (the committed domain is
///   what is being disclosed).
#[must_use]
pub fn cut_snippet(
    kind: UnitKind,
    canon: &CanonMode,
    plaintext: &[u8],
    provenance: SnippetProvenance,
) -> Snippet {
    if kind == UnitKind::Normal && matches!(canon, CanonMode::Text { .. }) {
        if plaintext.len() <= TEXT_SNIPPET_CAP_BYTES {
            // The window is the whole plaintext and no cut exists
            // (D67 §3 R3); empty units land here as `""`.
            if let Ok(text) = core::str::from_utf8(plaintext) {
                return Snippet {
                    window: SnippetWindow::Text(text.to_owned()),
                    truncated: false,
                    provenance,
                };
            }
        } else {
            let mut end = TEXT_SNIPPET_CAP_BYTES;
            let floor = TEXT_SNIPPET_CAP_BYTES - MAX_BOUNDARY_BACKOFF_BYTES;
            while end > floor && !starts_code_point(plaintext[end]) {
                end -= 1;
            }
            if let Ok(text) = core::str::from_utf8(&plaintext[..end]) {
                return Snippet {
                    window: SnippetWindow::Text(text.to_owned()),
                    truncated: true,
                    provenance,
                };
            }
        }
    }
    // The hex arm (R2's "otherwise"): mirrors, binary domains, and the
    // defensive UTF-8-failure drop. A zero-length window renders as bare
    // `hex:` (R4 totality).
    let end = plaintext.len().min(HEX_SNIPPET_CAP_BYTES);
    Snippet {
        window: SnippetWindow::Hex(plaintext[..end].to_vec()),
        truncated: end < plaintext.len(),
        provenance,
    }
}

/// Whether `byte` begins a UTF-8 code point (i.e. is not a continuation
/// byte) — `str::is_char_boundary`'s byte-level test, usable on raw,
/// possibly-invalid windows.
const fn starts_code_point(byte: u8) -> bool {
    (byte & 0xC0) != 0x80
}

/// Apply D67 §3 R3's **closed, frozen** escape set to a text window, per
/// code point. Everything outside the set passes through unmodified —
/// the user's prose renders as prose.
///
/// The set: `\\`, `\"`, `\n`/`\r`/`\t`, and `\u{…}` (minimal-length
/// lowercase hex) for the remaining **C0** controls, **DEL**, **C1**
/// controls, and the bidirectional format controls `U+061C`, `U+200E`,
/// `U+200F`, `U+202A`–`U+202E`, `U+2066`–`U+2069` (the CVE-2021-42574
/// "Trojan Source" set). Deliberately not `escape_debug` or a
/// printability table: those track Unicode data across toolchains,
/// whereas this set is closed and version-independent, so the M3
/// snapshots that freeze the rendering cannot rot under a pin bump.
fn escape_text_window(window: &str) -> String {
    let mut out = String::with_capacity(window.len());
    for c in window.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if escapes_as_u(c) => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// Membership in the `\u{…}` half of the R3 escape set (LF/CR/TAB are
/// members of C0 but take their short escapes above).
const fn escapes_as_u(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001f}'   // C0
        | '\u{007f}'              // DEL
        | '\u{0080}'..='\u{009f}' // C1
        | '\u{061c}'              // ALM
        | '\u{200e}' | '\u{200f}' // LRM, RLM
        | '\u{202a}'..='\u{202e}' // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
    )
}

// ─────────────────────────────────────────────────────────────────────────
// Plaintext sourcing seam
// ─────────────────────────────────────────────────────────────────────────

/// One unit's plaintext as a source produced it: the complete
/// post-padding-strip bytes in the unit's commitment domain, plus where
/// they came from.
pub struct SourcedPlaintext<'a> {
    /// The full plaintext. Its length must equal the unit's
    /// `true_length`; [`disclosure_preview`] treats a disagreeing source
    /// as unavailable rather than showing a window that cannot be the
    /// sealed bytes.
    pub bytes: Cow<'a, [u8]>,
    /// Provenance, carried into the [`Snippet`].
    pub provenance: SnippetProvenance,
}

impl core::fmt::Debug for SourcedPlaintext<'_> {
    /// Length, not bytes (the house fixture-`Debug` discipline): the
    /// value is a whole unit's plaintext, and while a *disclosed* unit's
    /// bytes are outside the secret class, a seam type has no business
    /// dumping megabytes into a log line.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SourcedPlaintext")
            .field("len", &self.bytes.len())
            .field("provenance", &self.provenance)
            .finish()
    }
}

/// Supplies unit plaintexts to [`disclosure_preview`].
///
/// Returning `None` is the **absent arm**, never a failure: the row still
/// renders with file/byte-range/size intact and consent may proceed on
/// those (D67 §3 R5). [`disclosure_preview`] calls this only for units it
/// actually discloses.
pub trait SnippetSource {
    /// The unit's full post-padding-strip plaintext, or `None` when no
    /// plaintext is available.
    fn plaintext(&mut self, unit: &UnitEntry) -> Option<SourcedPlaintext<'_>>;
}

/// R16's source shape: decrypted plaintexts the reveal flow already holds
/// (it gathers and decrypts every touched file's units for the tree
/// rebuild — D67 §1 j), keyed by work-global `unit_id`. Provenance is
/// always [`SnippetProvenance::SealedBytes`].
#[derive(Debug, Default)]
pub struct SealedPlaintexts(BTreeMap<u64, Vec<u8>>);

impl SealedPlaintexts {
    /// An empty map (every row degrades to the absent arm).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one unit's decrypted plaintext.
    pub fn insert(&mut self, unit_id: u64, plaintext: Vec<u8>) {
        self.0.insert(unit_id, plaintext);
    }
}

impl FromIterator<(u64, Vec<u8>)> for SealedPlaintexts {
    fn from_iter<I: IntoIterator<Item = (u64, Vec<u8>)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl SnippetSource for SealedPlaintexts {
    fn plaintext(&mut self, unit: &UnitEntry) -> Option<SourcedPlaintext<'_>> {
        self.0.get(&unit.unit_id()).map(|bytes| SourcedPlaintext {
            bytes: Cow::Borrowed(bytes),
            provenance: SnippetProvenance::SealedBytes,
        })
    }
}

/// The no-plaintext source: every row takes the absent arm. The
/// degenerate `show` case (no cache, no readable current file), and the
/// test double for the unavailable arm.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLocalPlaintext;

impl SnippetSource for NoLocalPlaintext {
    fn plaintext(&mut self, _unit: &UnitEntry) -> Option<SourcedPlaintext<'_>> {
        None
    }
}

/// `show`'s cache-first source (D43): decrypt the retained journal→cache
/// ciphertext of each disclosed unit with the vault's `W`.
///
/// **No network** — by type: this source holds no backend, so a preview
/// built over it can never fetch (U27 has no S dependency; D67 §1 j).
///
/// Every failure degrades to the absent arm rather than erroring,
/// because under D43 cache loss is never an error: a missing or
/// malformed cache record, an integrity-recheck failure (the S4 address
/// recompute, plus equality with the **manifest's** address — the
/// authoritative copy), an AEAD/padding failure, or a store-level read
/// failure all return `None`. The row's load-bearing fields do not
/// depend on this source.
pub struct VaultSnippetSource<'a, 'v> {
    store: &'a WorkStore<'v>,
    seal_id: SealId,
    w: MasterSecretRef<'a>,
}

impl<'a, 'v> VaultSnippetSource<'a, 'v> {
    /// A source over one work's cache: the unlocked vault's store, the
    /// work's seal id (the store key), and its master secret `W` (from
    /// the work record — needed to derive each unit's `k_u`).
    #[must_use]
    pub fn new(store: &'a WorkStore<'v>, seal_id: SealId, w: MasterSecretRef<'a>) -> Self {
        Self { store, seal_id, w }
    }
}

impl SnippetSource for VaultSnippetSource<'_, '_> {
    fn plaintext(&mut self, unit: &UnitEntry) -> Option<SourcedPlaintext<'_>> {
        let unit_id = unit.unit_id();
        let slot = BlobSlot::Unit { unit_id };
        let entry = slot.entry_key()?;
        let record = self.store.get_journal_entry(&self.seal_id, entry).ok()??;
        let blob = StagedBlob::decode(record.as_bytes()).ok()?;
        if blob.slot != slot {
            return None;
        }
        // Integrity recheck before use (D43, via R16's Notes): the cached
        // bytes must hash to the address the *manifest* records — the
        // recorded address matching proves nothing if the bytes moved,
        // and matching bytes under a different address are another blob.
        if blob.address.as_bytes() != unit.address().as_bytes() {
            return None;
        }
        check_staged_integrity(&blob).ok()?;
        let true_length = usize::try_from(unit.true_length()).ok()?;
        // The nonce comes from the manifest unit table — the single
        // authoritative copy (spec line 91); the staged duplicate is for
        // resume only.
        let nonce = AeadNonce::from_bytes(*unit.nonce().as_bytes());
        let plaintext = decrypt_unit(
            self.w,
            &self.seal_id,
            UnitId(unit_id),
            &nonce,
            &blob.ciphertext,
            true_length,
        )
        .ok()?;
        Some(SourcedPlaintext {
            bytes: Cow::Owned(plaintext),
            provenance: SnippetProvenance::SealedBytes,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The preview data
// ─────────────────────────────────────────────────────────────────────────

/// One disclosed unit's preview row: the spec's `file, byte-range, size,
/// snippet` (lines 36/149), plus the coordinates consumers group by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewRow {
    /// Work-global unit id — the id `reveal --units` takes.
    pub unit_id: u64,
    /// Manifest file id (= index into the vault's recorded path list).
    pub file_id: u64,
    /// The file's path as the vault recorded it at seal time.
    pub path: String,
    /// Normal or raw-mirror. A raw-mirror row appears **only** by riding
    /// along with its file's full reveal (D70) — there is no other way a
    /// mirror enters a selection — so `kind` doubles as the row's
    /// rides-along discriminant.
    pub kind: UnitKind,
    /// Byte range in the unit's committed domain: canonical-byte offsets
    /// for a text file's normal units, raw-byte offsets for binary files
    /// and raw mirrors (spec line 83; a mirror's range is `[0, raw_size)`).
    pub range: ByteRange,
    /// `true_length` — the unit's pre-padding byte size (the row's
    /// "size" column).
    pub size: u64,
    /// The D28 promotion annotation: `true` iff this row's file becomes
    /// **fully revealed** under the selection, opening its whole-file
    /// commitments (`file_salt`, and `s_root` when a fine tree exists).
    /// A user selecting "one more unit" must see this before it is
    /// irreversible.
    pub file_fully_revealed: bool,
    /// The snippet value, or `None` for the absent arm (D67 §3 R5).
    pub snippet: Option<Snippet>,
}

/// Per-file classification of a touched file — the same `full(F)`
/// predicate the builder uses (D28; D70 §7.6), exposed so R16 can drive
/// the bundle build from the identical classification the user consented
/// to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePreview {
    /// Manifest file id.
    pub file_id: u64,
    /// The vault-recorded path.
    pub path: String,
    /// `full(F) ⟺ N(F) ≠ ∅ ∧ R(F) = N(F)` (D28's frozen predicate over
    /// the file's `kind = Normal` units).
    pub fully_revealed: bool,
    /// `full(F) ∧ has-mirror`: the file's raw mirror is auto-included in
    /// the disclosure (D70) and has its own row.
    pub mirror_rides_along: bool,
}

/// The preview totals (R15's Accept): what the confirmation's summary
/// line states.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PreviewTotals {
    /// Disclosed units — selected normal units plus riding mirrors
    /// (= number of rows).
    pub units: u64,
    /// Total disclosed bytes: the sum of every row's `true_length`.
    /// `u128` so a sum of sealer-authored `u64` lengths is total without
    /// wrapping or erroring.
    pub bytes: u128,
    /// Files with at least one disclosed unit.
    pub files_touched: u64,
    /// How many touched files become fully revealed (their ids are in
    /// [`DisclosurePreview::files`]).
    pub files_fully_revealed: u64,
    /// Whether any raw mirror rides along (D70's consent-gate
    /// annotation).
    pub mirror_rides_along: bool,
}

/// The disclosure preview: everything the irreversible-disclosure
/// confirmation prints (U29) and `show` reuses (U27).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosurePreview {
    /// One row per disclosed unit, in manifest order (file-table order,
    /// unit-table order within a file — so work-global `unit_id` order
    /// for any honest manifest).
    pub rows: Vec<PreviewRow>,
    /// Touched files in file-table order, with the D28/D70
    /// classification.
    pub files: Vec<FilePreview>,
    /// The summary totals.
    pub totals: PreviewTotals,
}

/// Why a preview could not be computed. These are library-seam
/// invariants (R16 validates the user-facing selection with its own
/// typed errors before resolving it); none carries content or key
/// material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PreviewError {
    /// The vault's recorded path list disagrees with the manifest's file
    /// table — the record cannot name the rows.
    #[error("the vault records {paths} path(s) for a manifest with {files} file(s)")]
    PathCountMismatch {
        /// Recorded path count.
        paths: usize,
        /// Manifest file count.
        files: usize,
    },
    /// The selection names a unit id the manifest does not contain.
    #[error("the selection names unit {unit_id}, which does not exist in this work")]
    UnknownUnitId {
        /// The offending id.
        unit_id: u64,
    },
    /// The selection names a raw-mirror unit directly. Mirrors are
    /// includable only via a whole-file reveal (spec line 92) — they
    /// ride along when `full(F)` holds; a resolved selection contains
    /// normal units only.
    #[error(
        "the selection names raw-mirror unit {unit_id}; mirrors are includable only via a \
         whole-file reveal"
    )]
    RawMirrorSelected {
        /// The offending id.
        unit_id: u64,
    },
}

/// Every `kind = Normal` unit id of the work — the resolved form of
/// `--all`, and the selection `show` previews (its unit table is "the
/// preview for `reveal --units`", spec line 149; mirrors then ride along
/// per file automatically).
#[must_use]
pub fn all_normal_units(body: &ManifestBodyV1) -> BTreeSet<u64> {
    body.files()
        .iter()
        .flat_map(|file| file.units())
        .filter(|unit| unit.kind() == UnitKind::Normal)
        .map(UnitEntry::unit_id)
        .collect()
}

/// Compute the disclosure preview for a resolved selection (R15).
///
/// Inputs: the plaintext manifest body, the vault-recorded path list in
/// `file_id` order (`WorkRecord::input_paths_as_given`), the resolved
/// selection — the work-global ids of the **normal** units to reveal
/// (deduplicated by the set type; [`all_normal_units`] resolves `--all`)
/// — and a [`SnippetSource`].
///
/// Per file the selection is classified with D28's frozen predicate;
/// fully revealed files pull their raw mirror in as an extra row (D70).
/// The source is consulted **only** for disclosed units; a source
/// returning `None` — or a plaintext whose length disagrees with the
/// manifest's `true_length`, or a `true_length` this platform cannot
/// address — yields the absent arm for that row, never a failure.
///
/// # Errors
///
/// [`PreviewError::PathCountMismatch`], [`PreviewError::UnknownUnitId`],
/// [`PreviewError::RawMirrorSelected`] — defensive seam checks; a
/// preview over a selection R16 resolved and a record U9 wrote cannot
/// hit them.
pub fn disclosure_preview<S: SnippetSource + ?Sized>(
    body: &ManifestBodyV1,
    paths: &[String],
    selection: &BTreeSet<u64>,
    source: &mut S,
) -> Result<DisclosurePreview, PreviewError> {
    if paths.len() != body.files().len() {
        return Err(PreviewError::PathCountMismatch {
            paths: paths.len(),
            files: body.files().len(),
        });
    }

    // Validate the selection against the whole unit table first, so a
    // malformed selection is an error before any plaintext is sourced.
    let mut known: BTreeSet<u64> = BTreeSet::new();
    for file in body.files() {
        for unit in file.units() {
            if unit.kind() == UnitKind::RawMirror && selection.contains(&unit.unit_id()) {
                return Err(PreviewError::RawMirrorSelected {
                    unit_id: unit.unit_id(),
                });
            }
            known.insert(unit.unit_id());
        }
    }
    if let Some(unknown) = selection.iter().find(|id| !known.contains(id)) {
        return Err(PreviewError::UnknownUnitId { unit_id: *unknown });
    }

    let mut rows = Vec::new();
    let mut files = Vec::new();
    let mut totals = PreviewTotals::default();

    for (index, file) in body.files().iter().enumerate() {
        let file_id = index as u64;
        let path = &paths[index];

        let normal_count = file
            .units()
            .iter()
            .filter(|unit| unit.kind() == UnitKind::Normal)
            .count();
        let selected_count = file
            .units()
            .iter()
            .filter(|unit| unit.kind() == UnitKind::Normal && selection.contains(&unit.unit_id()))
            .count();
        if selected_count == 0 {
            // Untouched: no rows, no classification entry — the preview
            // derives and emits nothing for it (the generation-side
            // isolation posture, mirrored on the display side).
            continue;
        }

        // D28's frozen predicate: full(F) ⟺ N(F) ≠ ∅ ∧ R(F) = N(F).
        // Selecting every normal unit by enumeration IS a full reveal.
        let fully_revealed = normal_count > 0 && selected_count == normal_count;
        let mirror_rides_along = fully_revealed && file.raw_mirror().is_some();

        for unit in file.units() {
            let disclosed = match unit.kind() {
                UnitKind::Normal => selection.contains(&unit.unit_id()),
                UnitKind::RawMirror => mirror_rides_along,
            };
            if !disclosed {
                continue;
            }
            let snippet = source.plaintext(unit).and_then(|sourced| {
                (sourced.bytes.len() as u64 == unit.true_length()).then(|| {
                    cut_snippet(
                        unit.kind(),
                        file.canon(),
                        &sourced.bytes,
                        sourced.provenance,
                    )
                })
            });
            totals.units += 1;
            totals.bytes += u128::from(unit.true_length());
            rows.push(PreviewRow {
                unit_id: unit.unit_id(),
                file_id,
                path: path.clone(),
                kind: unit.kind(),
                range: unit.range(),
                size: unit.true_length(),
                file_fully_revealed: fully_revealed,
                snippet,
            });
        }

        totals.files_touched += 1;
        if fully_revealed {
            totals.files_fully_revealed += 1;
        }
        totals.mirror_rides_along |= mirror_rides_along;
        files.push(FilePreview {
            file_id,
            path: path.clone(),
            fully_revealed,
            mirror_rides_along,
        });
    }

    Ok(DisclosurePreview {
        rows,
        files,
        totals,
    })
}

// ─────────────────────────────────────────────────────────────────────────
// Tests (R15 Accept; D67's rules pinned)
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use antseal_core::crypto::disclosure::UnitBinding;
    use antseal_core::crypto::error::SigAlg;
    use antseal_core::manifest::fixtures as mf;
    use antseal_core::manifest::{FileEntry, FineTree};

    use super::*;

    // ── fixture helpers (synthetic, NON-SECRET — manifest::fixtures) ──

    /// A single-file body around `units`, text or binary.
    fn one_file_body(text: bool, fine_tree: bool, units: Vec<UnitEntry>) -> ManifestBodyV1 {
        let canon = if text {
            CanonMode::Text {
                canon_commit: mf::commit32(0x03),
                unicode_version: mf::UNICODE_VERSION.to_owned(),
            }
        } else {
            CanonMode::Binary
        };
        let size = units
            .iter()
            .filter(|u| u.kind() == UnitKind::Normal)
            .map(|u| u.range().length())
            .sum();
        let tree = if fine_tree {
            FineTree::Present {
                root: mf::commit32(0x04),
            }
        } else {
            FineTree::Absent
        };
        let file = FileEntry::new(
            mf::commit32(0x01),
            mf::commit32(0x02),
            canon,
            size,
            tree,
            units,
        )
        .expect("test file entry is well formed");
        body_of(vec![file])
    }

    fn body_of(files: Vec<FileEntry>) -> ManifestBodyV1 {
        ManifestBodyV1::new(
            mf::APP_VERSION.to_owned(),
            mf::seal_id(),
            "preview fixture".to_owned(),
            mf::CLAIMED_TIME,
            mf::hybrid_pubkeys(),
            vec![SigAlg::Ed25519, SigAlg::MlDsa65],
            files,
        )
        .expect("test body is well formed")
    }

    /// A fine-tree-covered normal unit of `length` bytes at `start`.
    fn covered(unit_id: u64, start: u64, length: u64) -> UnitEntry {
        UnitEntry::new(
            unit_id,
            UnitKind::Normal,
            ByteRange::new(start, length),
            length,
            UnitBinding::FineTreeCovered,
            mf::nonce(unit_id as u8),
            mf::address(unit_id as u8),
        )
    }

    /// A non-covered unit (`--no-fine-tree` normal, or a raw mirror).
    fn noncovered(unit_id: u64, kind: UnitKind, length: u64) -> UnitEntry {
        UnitEntry::new(
            unit_id,
            kind,
            ByteRange::new(0, length),
            length,
            UnitBinding::NonCovered {
                unit_commit: mf::commit32(0x20 ^ unit_id as u8),
            },
            mf::nonce(unit_id as u8),
            mf::address(unit_id as u8),
        )
    }

    /// A body with one text file: two covered units (`a_len` + `b_len`
    /// bytes) and a raw mirror of `mirror_len` bytes, ids 0/1/2.
    fn mirror_body(a_len: u64, b_len: u64, mirror_len: u64) -> ManifestBodyV1 {
        one_file_body(
            true,
            true,
            vec![
                covered(0, 0, a_len),
                covered(1, a_len, b_len),
                noncovered(2, UnitKind::RawMirror, mirror_len),
            ],
        )
    }

    fn ids(list: &[u64]) -> BTreeSet<u64> {
        list.iter().copied().collect()
    }

    fn paths_for(body: &ManifestBodyV1) -> Vec<String> {
        (0..body.files().len())
            .map(|i| format!("file-{i}"))
            .collect()
    }

    fn preview_with<S: SnippetSource>(
        body: &ManifestBodyV1,
        selection: &BTreeSet<u64>,
        source: &mut S,
    ) -> DisclosurePreview {
        disclosure_preview(body, &paths_for(body), selection, source).expect("preview computes")
    }

    fn sealed(pairs: &[(u64, &[u8])]) -> SealedPlaintexts {
        pairs.iter().map(|(id, b)| (*id, b.to_vec())).collect()
    }

    /// A source that records which unit ids were asked for.
    #[derive(Default)]
    struct Recording {
        asked: Vec<u64>,
        inner: SealedPlaintexts,
    }

    impl SnippetSource for Recording {
        fn plaintext(&mut self, unit: &UnitEntry) -> Option<SourcedPlaintext<'_>> {
            self.asked.push(unit.unit_id());
            self.inner.plaintext(unit)
        }
    }

    // ── the D67 constants, pinned (R7: "pinned by R15's unit tests") ──

    #[test]
    fn the_d67_constants_are_pinned() {
        assert_eq!(TEXT_SNIPPET_CAP_BYTES, 64);
        assert_eq!(HEX_SNIPPET_CAP_BYTES, 16);
        assert_eq!(TRUNCATION_MARKER, '…');
        assert_eq!(SNIPPET_UNAVAILABLE, "(snippet unavailable)");
    }

    // ── text arm (R1/R3) ──

    #[test]
    fn short_text_renders_quoted_without_a_marker() {
        let body = one_file_body(true, true, vec![covered(0, 0, 11)]);
        let mut source = sealed(&[(0, b"hello world")]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert_eq!(
            snippet.window,
            SnippetWindow::Text("hello world".to_owned())
        );
        assert!(!snippet.truncated);
        assert_eq!(snippet.render(), "\"hello world\"");
    }

    #[test]
    fn an_empty_unit_renders_empty_quotes_with_no_marker() {
        // true_length = 0: the window is the complete representation of
        // zero bytes (D67 §3 R3).
        let body = one_file_body(true, false, vec![noncovered(0, UnitKind::Normal, 0)]);
        let mut source = sealed(&[(0, b"")]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert_eq!(snippet.render(), "\"\"");
        assert!(!snippet.truncated);
    }

    #[test]
    fn long_text_truncates_at_64_bytes_with_the_marker_outside_the_quote() {
        let content = [b'a'; 100];
        let body = one_file_body(true, true, vec![covered(0, 0, 100)]);
        let mut source = sealed(&[(0, &content)]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert_eq!(
            snippet.window,
            SnippetWindow::Text("a".repeat(64)),
            "ASCII cuts exactly at the 64-byte cap"
        );
        assert!(snippet.truncated);
        assert_eq!(snippet.render(), format!("\"{}\"…", "a".repeat(64)));
    }

    #[test]
    fn the_cut_backs_off_to_a_utf8_code_point_boundary() {
        // 63 ASCII bytes, then '€' (E2 82 AC) straddling byte 64: the cut
        // backs off 1 byte to the boundary at 63 and never splits the
        // code point (D67 §3 R3).
        let mut content = vec![b'a'; 63];
        content.extend_from_slice("€tail".as_bytes());
        let body = one_file_body(true, true, vec![covered(0, 0, content.len() as u64)]);
        let mut source = sealed(&[(0, &content)]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert_eq!(
            snippet.window,
            SnippetWindow::Text("a".repeat(63)),
            "the window backed off to 63 bytes rather than splitting '€'"
        );
        assert!(snippet.truncated);
        assert_eq!(snippet.render(), format!("\"{}\"…", "a".repeat(63)));
    }

    // ── hex arm (R1/R4) and the R2 form judgment ──

    #[test]
    fn binary_units_render_hex_with_the_16_byte_cap() {
        let long: Vec<u8> = (0u8..30).collect();
        let body = one_file_body(false, true, vec![covered(0, 0, 30)]);
        let mut source = sealed(&[(0, &long)]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert_eq!(snippet.window, SnippetWindow::Hex((0u8..16).collect()));
        assert!(snippet.truncated);
        assert_eq!(
            snippet.render(),
            "hex:000102030405060708090a0b0c0d0e0f…",
            "ungrouped lowercase pairs, no 0x, marker after the pairs"
        );

        // At or under the cap: no marker.
        let short = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let body = one_file_body(false, true, vec![covered(0, 0, 4)]);
        let mut source = sealed(&[(0, &short)]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert!(!snippet.truncated);
        assert_eq!(snippet.render(), "hex:deadbeef");
    }

    #[test]
    fn a_binary_domain_unit_is_hex_even_when_its_bytes_decode_as_utf8() {
        // R2: the committed domain is what is being disclosed — content
        // re-sniffing would mint the classifier the code does not have.
        let body = one_file_body(false, true, vec![covered(0, 0, 11)]);
        let mut source = sealed(&[(0, b"plain ascii")]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert!(matches!(snippet.window, SnippetWindow::Hex(_)));
        assert_eq!(snippet.render(), "hex:706c61696e206173636969");
    }

    #[test]
    fn raw_mirrors_render_hex_even_for_text_files() {
        // D67 §1 g: a BOM renders invisibly as text; hex shows `efbbbf`.
        let mirror_bytes = b"\xEF\xBB\xBFcaf\xC3\xA9\r\n";
        let body = mirror_body(4, 4, mirror_bytes.len() as u64);
        let mut source = sealed(&[
            (0, b"caf\xC3"),
            (1, b"\xA9\x0Aab"),
            (2, mirror_bytes.as_slice()),
        ]);
        let preview = preview_with(&body, &ids(&[0, 1]), &mut source);
        let mirror_row = preview
            .rows
            .iter()
            .find(|row| row.kind == UnitKind::RawMirror)
            .expect("the mirror rides along");
        let snippet = mirror_row.snippet.as_ref().expect("snippet present");
        assert!(matches!(snippet.window, SnippetWindow::Hex(_)));
        assert_eq!(
            snippet.render(),
            "hex:efbbbf636166c3a90d0a",
            "the BOM and the CRLF are visible as bytes, never invisible text"
        );
    }

    #[test]
    fn a_utf8_invalid_text_domain_window_takes_the_hex_arm_never_lossy() {
        // R2's defensive arm: impossible for honest sealed data,
        // reachable via a corrupt cache — degrade to hex, never U+FFFD.
        let content = b"ok\xFF\xFEbroken text window";
        let body = one_file_body(true, true, vec![covered(0, 0, content.len() as u64)]);
        let mut source = sealed(&[(0, content.as_slice())]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert_eq!(
            snippet.window,
            SnippetWindow::Hex(content[..16].to_vec()),
            "the hex arm re-cuts at its own 16-byte cap"
        );
        let rendered = snippet.render();
        assert_eq!(rendered, "hex:6f6bfffe62726f6b656e207465787420…");
        assert!(!rendered.contains('\u{FFFD}'), "no lossy substitution");
    }

    #[test]
    fn an_all_continuation_window_exhausts_the_backoff_and_takes_hex() {
        // Adversarial shape: > 64 bytes, every byte a continuation byte.
        // The bounded back-off (≤ 3) cannot find a boundary and the
        // window fails validation — the hex arm, not a walk to byte 0.
        let content = [0x80u8; 80];
        let body = one_file_body(true, true, vec![covered(0, 0, 80)]);
        let mut source = sealed(&[(0, &content)]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert_eq!(snippet.window, SnippetWindow::Hex(vec![0x80; 16]));
        assert!(snippet.truncated);
    }

    #[test]
    fn the_form_judgment_is_window_scoped_not_whole_plaintext() {
        // Invalid bytes *beyond* the window do not flip the form: the
        // window is what the snippet shows, and it is valid UTF-8.
        let mut content = vec![b'x'; 70];
        content[68] = 0xFF;
        let body = one_file_body(true, true, vec![covered(0, 0, 70)]);
        let mut source = sealed(&[(0, &content)]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert_eq!(snippet.window, SnippetWindow::Text("x".repeat(64)));
        assert!(snippet.truncated);
    }

    // ── the escape set (R3) — the display-integrity red arm ──

    #[test]
    fn the_closed_escape_set_renders_controls_and_bidi_escaped_exactly() {
        // One member of every class: BEL (C0), the short escapes, DEL,
        // NEL (C1), ALM, LRM, RLO, PDI — plus the quote and backslash.
        let content = "A\u{7}B\nC\tD\rE\"F\\G\u{7f}H\u{85}I\u{61c}J\u{200e}K\u{202e}L\u{2069}M";
        let body = one_file_body(true, true, vec![covered(0, 0, content.len() as u64)]);
        let mut source = sealed(&[(0, content.as_bytes())]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert_eq!(
            snippet.render(),
            "\"A\\u{7}B\\nC\\tD\\rE\\\"F\\\\G\\u{7f}H\\u{85}I\\u{61c}J\\u{200e}K\\u{202e}L\\u{2069}M\"",
            "C0/C1/DEL and the Trojan-Source bidi controls cannot repaint the consent screen"
        );
        // The escaped rendering is exactly one line.
        assert!(!snippet.render().contains('\n'));
    }

    #[test]
    fn ordinary_prose_passes_through_unescaped() {
        let content = "café Ω 世界 — plain prose.";
        let body = one_file_body(true, true, vec![covered(0, 0, content.len() as u64)]);
        let mut source = sealed(&[(0, content.as_bytes())]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert_eq!(snippet.render(), format!("\"{content}\""));
    }

    // ── the marker cannot be forged by content (R3) ──

    #[test]
    fn content_containing_the_marker_glyph_cannot_forge_truncation() {
        // Not truncated, content ends with a literal '…': the glyph sits
        // INSIDE the quotes and the rendering ends with the honest
        // closing quote.
        let content = "ends with…";
        let body = one_file_body(true, true, vec![covered(0, 0, content.len() as u64)]);
        let mut source = sealed(&[(0, content.as_bytes())]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let honest = preview.rows[0].snippet.as_ref().expect("snippet").render();
        assert_eq!(honest, "\"ends with…\"");
        assert!(honest.ends_with('"'), "no marker after the closing quote");

        // Truncated: the marker is OUTSIDE the closing quote — a
        // position content cannot reach once '"' is escaped.
        let long = "…".repeat(40); // 120 bytes; boundary back-off lands at 63
        let body = one_file_body(true, true, vec![covered(0, 0, long.len() as u64)]);
        let mut source = sealed(&[(0, long.as_bytes())]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let truncated = preview.rows[0].snippet.as_ref().expect("snippet").render();
        assert_eq!(truncated, format!("\"{}\"…", "…".repeat(21)));
        assert!(truncated.ends_with("\"…"), "marker only after the quote");
    }

    // ── the absent arm (R5) ──

    #[test]
    fn unavailable_rows_keep_their_coordinates() {
        let body = mirror_body(4, 4, 10);
        let preview = preview_with(&body, &ids(&[0, 1]), &mut NoLocalPlaintext);
        assert_eq!(preview.rows.len(), 3, "both units plus the mirror");
        for row in &preview.rows {
            assert!(row.snippet.is_none());
            assert_eq!(render_snippet(row.snippet.as_ref()), SNIPPET_UNAVAILABLE);
        }
        // The load-bearing fields are intact (position + total size —
        // the always-present pair, spec line 121).
        assert_eq!(preview.rows[1].range.start(), 4);
        assert_eq!(preview.rows[1].range.length(), 4);
        assert_eq!(preview.rows[1].size, 4);
        assert_eq!(preview.rows[1].path, "file-0");
    }

    #[test]
    fn a_source_length_disagreement_degrades_to_the_absent_arm() {
        // A plaintext that cannot be the sealed bytes (wrong length) is
        // treated as unavailable, never windowed.
        let body = one_file_body(true, true, vec![covered(0, 0, 10)]);
        let mut source = sealed(&[(0, b"only-6")]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        assert!(preview.rows[0].snippet.is_none());
    }

    // ── value vs rendering (R6) ──

    #[test]
    fn snippet_values_stay_raw_while_renderings_escape() {
        let content = "a\u{7}b…";
        let body = one_file_body(true, true, vec![covered(0, 0, content.len() as u64)]);
        let mut source = sealed(&[(0, content.as_bytes())]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        // The VALUE carries the raw window: the control char unescaped,
        // no quotes, no marker.
        assert_eq!(snippet.window, SnippetWindow::Text(content.to_owned()));
        // The RENDERING carries quotes and escapes.
        assert_eq!(snippet.render(), "\"a\\u{7}b…\"");
        assert_eq!(snippet.provenance, SnippetProvenance::SealedBytes);
    }

    #[test]
    fn provenance_is_a_carried_discriminant_not_a_rendering() {
        // Same window, both provenances: the rendering is identical (the
        // label copy is U27's); only the data discriminant differs.
        let canon = CanonMode::Text {
            canon_commit: mf::commit32(0x03),
            unicode_version: mf::UNICODE_VERSION.to_owned(),
        };
        let sealed_snip = cut_snippet(
            UnitKind::Normal,
            &canon,
            b"same bytes",
            SnippetProvenance::SealedBytes,
        );
        let current_snip = cut_snippet(
            UnitKind::Normal,
            &canon,
            b"same bytes",
            SnippetProvenance::CurrentFile,
        );
        assert_eq!(sealed_snip.render(), current_snip.render());
        assert_ne!(sealed_snip.provenance, current_snip.provenance);
        assert_eq!(SnippetProvenance::SealedBytes.name(), "sealed-bytes");
        assert_eq!(SnippetProvenance::CurrentFile.name(), "current-file");
    }

    // ── annotations: D28 promotion + D70 mirror-rides-along ──

    #[test]
    fn selecting_every_normal_unit_by_enumeration_is_a_full_reveal_and_the_mirror_rides() {
        let body = mirror_body(512, 512, 1030);
        let mut source = Recording::default();
        let preview = preview_with(&body, &ids(&[0, 1]), &mut source);

        // The mirror was never in the selection, yet it is a row —
        // auto-included, with its raw-domain coordinates (D70 §7.6).
        assert_eq!(
            preview.rows.iter().map(|r| r.unit_id).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        let mirror = &preview.rows[2];
        assert_eq!(mirror.kind, UnitKind::RawMirror);
        assert_eq!(mirror.range.start(), 0);
        assert_eq!(mirror.range.length(), 1030);
        assert_eq!(mirror.size, 1030);

        // The D28 promotion annotation, on every row of the file.
        assert!(preview.rows.iter().all(|r| r.file_fully_revealed));
        assert_eq!(
            preview.files,
            vec![FilePreview {
                file_id: 0,
                path: "file-0".to_owned(),
                fully_revealed: true,
                mirror_rides_along: true,
            }]
        );
        assert_eq!(
            preview.totals,
            PreviewTotals {
                units: 3,
                bytes: 512 + 512 + 1030,
                files_touched: 1,
                files_fully_revealed: 1,
                mirror_rides_along: true,
            }
        );
    }

    #[test]
    fn a_partial_selection_neither_promotes_nor_ships_the_mirror() {
        let body = mirror_body(512, 512, 1030);
        let preview = preview_with(&body, &ids(&[0]), &mut NoLocalPlaintext);
        assert_eq!(preview.rows.len(), 1);
        assert_eq!(preview.rows[0].unit_id, 0);
        assert!(!preview.rows[0].file_fully_revealed);
        assert_eq!(
            preview.files,
            vec![FilePreview {
                file_id: 0,
                path: "file-0".to_owned(),
                fully_revealed: false,
                mirror_rides_along: false,
            }]
        );
        assert_eq!(
            preview.totals,
            PreviewTotals {
                units: 1,
                bytes: 512,
                files_touched: 1,
                files_fully_revealed: 0,
                mirror_rides_along: false,
            }
        );
    }

    #[test]
    fn only_disclosed_units_are_ever_sourced() {
        // A partial selection must never decrypt the unselected unit or
        // the withheld mirror.
        let body = mirror_body(512, 512, 1030);
        let mut source = Recording::default();
        let _ = preview_with(&body, &ids(&[0]), &mut source);
        assert_eq!(source.asked, vec![0]);

        // And a full selection sources exactly the three disclosed rows.
        let mut source = Recording::default();
        let _ = preview_with(&body, &ids(&[0, 1]), &mut source);
        assert_eq!(source.asked, vec![0, 1, 2]);
    }

    #[test]
    fn multi_file_totals_count_files_bytes_and_riding_mirrors() {
        // Files: text-with-mirror (units 0,1 + mirror 2; 512+512, mirror
        // 1030), binary (unit 3; 4096), no-fine-tree text (unit 4; 700).
        let body = mf::multi_file_split_body();
        let preview = preview_with(&body, &ids(&[0, 1, 3]), &mut NoLocalPlaintext);

        assert_eq!(
            preview.rows.iter().map(|r| r.unit_id).collect::<Vec<_>>(),
            vec![0, 1, 2, 3],
            "file 0 fully revealed (mirror rides), file 1 fully revealed, file 2 untouched"
        );
        assert_eq!(preview.files.len(), 2, "the untouched file has no entry");
        assert_eq!(
            preview.totals,
            PreviewTotals {
                units: 4,
                bytes: 512 + 512 + 1030 + 4096,
                files_touched: 2,
                files_fully_revealed: 2,
                mirror_rides_along: true,
            }
        );
        // Paths come from the vault list, per file.
        assert_eq!(preview.rows[3].path, "file-1");
        assert_eq!(preview.rows[3].file_id, 1);
    }

    #[test]
    fn an_empty_selection_previews_nothing() {
        let body = mirror_body(4, 4, 10);
        let preview = preview_with(&body, &ids(&[]), &mut NoLocalPlaintext);
        assert!(preview.rows.is_empty());
        assert!(preview.files.is_empty());
        assert_eq!(preview.totals, PreviewTotals::default());
    }

    #[test]
    fn an_empty_binary_unit_renders_bare_hex() {
        // Unreachable for honest data (an empty file classifies as text)
        // — pinned for totality (D67 §3 R4).
        let body = one_file_body(false, false, vec![noncovered(0, UnitKind::Normal, 0)]);
        let mut source = sealed(&[(0, b"")]);
        let preview = preview_with(&body, &ids(&[0]), &mut source);
        let snippet = preview.rows[0].snippet.as_ref().expect("snippet present");
        assert_eq!(snippet.render(), "hex:");
        assert!(!snippet.truncated);
    }

    // ── seam errors ──

    #[test]
    fn unknown_and_mirror_ids_are_typed_errors() {
        let body = mirror_body(4, 4, 10);
        let paths = paths_for(&body);
        assert_eq!(
            disclosure_preview(&body, &paths, &ids(&[9]), &mut NoLocalPlaintext),
            Err(PreviewError::UnknownUnitId { unit_id: 9 })
        );
        assert_eq!(
            disclosure_preview(&body, &paths, &ids(&[0, 2]), &mut NoLocalPlaintext),
            Err(PreviewError::RawMirrorSelected { unit_id: 2 })
        );
    }

    #[test]
    fn a_path_count_mismatch_is_a_typed_error() {
        let body = mirror_body(4, 4, 10);
        assert_eq!(
            disclosure_preview(&body, &[], &ids(&[0]), &mut NoLocalPlaintext),
            Err(PreviewError::PathCountMismatch { paths: 0, files: 1 })
        );
    }

    #[test]
    fn all_normal_units_covers_every_file_and_never_a_mirror() {
        let body = mf::multi_file_split_body();
        assert_eq!(all_normal_units(&body), ids(&[0, 1, 3, 4]));
    }
}
