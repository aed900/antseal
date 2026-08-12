//! `reveal`'s CLI half (U28): where the proof bundle is written, what
//! happens when something is already there, and how the run reports itself.
//!
//! Everything here implements
//! `docs/decisions/D68-units-syntax-and-default-bundle-filename.md` §3
//! R5–R11. R16's engine ([`crate::pipeline::reveal`]) supplies the resolved
//! selection, the gathered ciphertexts, the R15 preview and — after consent
//! — the built `.sealproof` bytes; this module decides the path, refuses a
//! collision, writes exclusively, and renders the run. **Reveal never
//! prompts about the output path** (D68 §3 R7): the refusal replaces the
//! interactive "overwrite? y/n" convention entirely, exactly as D48 §5 did
//! for `restore`, and `reveal` keeps its one prompt for the decision that
//! carries the irreversible disclosure (U29's gate).
//!
//! # The order is the ruling (D68 §3 R8)
//!
//! ```text
//! resolve -o / default  →  check target absent  →  R16 prepare (gather,
//!   decrypt)  →  R15 preview  →  U29 consent gate  →  R13 build  →
//!   exclusive write
//! ```
//!
//! `MVP-SPEC.md` line 34 states the house's normative order — *"every cheap,
//! failable step **before** the one irreversible paid one"* — and reveal's
//! irreversible step is the disclosure itself (line 36: *"irreversibly
//! disclosed"*). So the path is resolved and checked **first**: before the
//! preview, before consent, and before a single ciphertext is fetched. Three
//! consequences, all deliberate — nobody is ever asked to consent to a
//! disclosure that then cannot be written; a refused path costs zero fetches
//! and zero money; and the failure arrives while the user is still thinking
//! about the command rather than after they have committed to it.
//!
//! # Never overwrite, and never by rename (D68 §3 R7, R9)
//!
//! An existing target — file, directory, symlink, anything
//! `symlink_metadata` reports — is a typed refusal naming the path and
//! pointing at `-o`; nothing is written and no byte of the existing file is
//! touched. There is no suffixing, no timestamping and no prompt.
//!
//! D48's two mechanisms are **deliberately departed from**, each with its
//! reason recorded in D68:
//!
//! - **byte-aware skip** (D48 §3) is structurally unavailable: restore's
//!   output is a function of immutable sealed content, while a bundle is a
//!   function of the *anchor set*, which spec line 35's every-invocation
//!   upgrade hook is designed to improve — so two reveals of one selection
//!   legitimately differ, and the second is strictly better evidence;
//! - **temp file + rename** (D48 §4) would *defeat* the refusal: a rename
//!   clobbers. The requirement here is exclusivity, so the file is created
//!   with `create_new(true)` (`O_EXCL`) at its final path. The pre-flight
//!   check above is advisory (TOCTOU); `create_new` is what makes "never
//!   overwrite" true rather than intended.
//!
//! **Recorded residual** (D68 §3 R9): a hard kill mid-write leaves a partial
//! `.sealproof` at the final path, which then refuses the next default-named
//! run until the user removes it or passes `-o`. That failure is safe and
//! self-announcing — a truncated bundle is a malformed bundle and `verify`
//! rejects it loudly — and it is preferred over any rename-based scheme that
//! could replace a good bundle.
//!
//! # The name carries the `work_id` and nothing else content-derived
//!
//! D68 §3 R6's test is not *"is it content-derived"* but *"does the name
//! disclose to a wider audience than the artifact it names?"* — a filename
//! travels as a mail-attachment name, a backup-index entry, a sync metadata
//! field and a screenshot. The `work_id` passes (every bundle embeds the
//! plaintext manifest, so anyone holding the file already has it, and D48
//! already puts it in a directory name); the **title** fails (free-form,
//! unbounded, unvalidated user text authoring a filesystem path) and the
//! **source paths** fail (unrevealed files are withheld as committed
//! placeholders — spec line 95 — so a name built from one would disclose
//! precisely what the bundle refuses to).
//!
//! # Secret hygiene (project rule 6)
//!
//! Nothing here holds `W`, a unit key or a salt: it takes already-built
//! bundle bytes — a public artifact by construction — plus ids, counts and
//! a path the user chose or this module derived from the `work_id`. The
//! report renders lengths and ids, never content.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use antseal_net::StorageBackend;

use crate::brand::VERIFIER_URL;
use crate::cli::RevealArgs;
use crate::error::CliError;
use crate::pipeline::restore::{hex32, resolve_work_id};
use crate::pipeline::reveal::{
    PreparedReveal, RevealEngine, RevealRequest, RevealSummary, UnitSelection,
};
use crate::vault::store::WorkStore;

/// The proof-bundle file extension, without the dot (`.sealproof`).
///
/// **Minted here** (D68 §3 R10): the repository spells this extension 210
/// times and held no constant for it, while `.sealvault` has had
/// [`EXPORT_FILE_EXTENSION`] since U12. One home means this module and any
/// future caller share it. Existing test literals are not required to
/// migrate by that ruling.
///
/// Advisory, like the export extension: a bundle is identified by its
/// magic and its versioned CBOR, never by its name — and an explicit `-o`
/// is taken **verbatim**, with no extension appended or rewritten (D68 §3
/// R5; silently rewriting a user's path is the class of surprise D48 §2
/// exists to prevent).
///
/// [`EXPORT_FILE_EXTENSION`]: crate::vault::export::EXPORT_FILE_EXTENSION
pub const BUNDLE_FILE_EXTENSION: &str = "sealproof";

/// Filename prefix of the default bundle path (D68 §3 R5; the stem is
/// maintainer-confirmed 2026-08-12, closing D68 §9 (iv)).
///
/// The house pattern is `antseal-` + the command name + `-` + the
/// discriminant — `antseal-restore-<work-id>/` (D48 §1) and
/// `antseal-vault-export-<timestamp>.sealvault` (U12) — so a user who has
/// seen one can predict the others and a directory listing groups every
/// antseal artifact under a single prefix.
pub const BUNDLE_FILE_PREFIX: &str = "antseal-reveal-";

/// The default output path for a work: `./antseal-reveal-<work-id>.sealproof`
/// in the invocation cwd, `<work-id>` in D29's printed form.
///
/// Bounded by construction — 15 + 64 + 10 = **89 bytes**, under `NAME_MAX`
/// on every supported platform — over a closed `[0-9a-f]` alphabet, and
/// work-scoped so the default never collides *across* works. Not a
/// subdirectory: `reveal` produces one file and `-o` is typed `FILE`, so a
/// directory default would contradict the flag's own type.
///
/// Identical in every mode: `--json` neither changes nor suppresses it (a
/// mode-dependent default would be exactly the human/machine divergence D51
/// works to remove), and the resolved path is always reported.
#[must_use]
pub fn default_bundle_path(work_id: &[u8; 32]) -> PathBuf {
    PathBuf::from(format!(
        "{BUNDLE_FILE_PREFIX}{}.{BUNDLE_FILE_EXTENSION}",
        hex32(work_id)
    ))
}

/// `-o <FILE>` when given, else [`default_bundle_path`].
///
/// An explicit path is taken **verbatim** — no extension coercion, no
/// re-rooting, no cwd rewriting (D68 §3 R5).
#[must_use]
pub fn resolve_bundle_path(output: Option<&Path>, work_id: &[u8; 32]) -> PathBuf {
    output.map_or_else(|| default_bundle_path(work_id), Path::to_path_buf)
}

/// D68 §3 R7/R8's pre-flight: refuse an occupied target **before** any
/// preview, any consent and any fetch.
///
/// `symlink_metadata` rather than `metadata`, deliberately: a symlink — even
/// a dangling one — occupies the path, and following it would ask about the
/// wrong file entirely.
///
/// # Errors
///
/// [`CliError::RefusedBundleOverwrite`] when anything exists at `path`;
/// [`CliError::Io`] when the path cannot be inspected at all (a path we
/// cannot look at is not one to write blind).
pub fn check_target_absent(path: &Path) -> Result<(), CliError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(CliError::RefusedBundleOverwrite {
            path: path.to_path_buf(),
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CliError::Io {
            context: format!("checking the proof-bundle output path {}", path.display()),
            source,
        }),
    }
}

/// What one `reveal` invocation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealReport {
    /// The work revealed from.
    pub work_id: [u8; 32],
    /// Where the bundle was written (`-o` or the default).
    pub bundle_path: PathBuf,
    /// The bundle's size on disk.
    pub bytes: u64,
    /// Files with at least one disclosed unit (the preview's total).
    pub files_touched: u64,
    /// R16's disclosure summary: exactly what the bundle discloses, derived
    /// from the same preview the user consented to.
    pub summary: RevealSummary,
}

impl RevealReport {
    /// The human report, as lines (the caller routes them to stdout or —
    /// under `--json` — to stderr, D51).
    ///
    /// The closing lines are U28's `Do`: the bundle path, and the canonical
    /// verifier page (spec line 139 — *"one canonical URL used in all docs
    /// and printed by the CLI in `reveal` output"*). The URL is
    /// [`VERIFIER_URL`] interpolated, never re-spelled: D62 §3 R8 permits
    /// exactly one Rust definition of that value.
    ///
    /// Possession language throughout, and no verdict-shaped sentence: this
    /// report says what was written and what it discloses, never what has
    /// been proven. It borrows nothing from
    /// [`antseal_core::verify::wording`] and coins no headline (U31).
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let units = self.summary.revealed_unit_ids.len();
        let whole = self.summary.files_fully_revealed.len();
        let mut out = vec![
            format!(
                "Wrote the proof bundle to {} ({} bytes).",
                self.bundle_path.display(),
                self.bytes
            ),
            format!(
                "  It discloses {units} unit(s) across {} file(s); {whole} of them {} revealed \
                 whole.",
                self.files_touched,
                if whole == 1 { "is" } else { "are" }
            ),
            format!(
                "  Ciphertexts used: {} from this vault's local copies, {} fetched from \
                 Autonomi.",
                self.summary.units_from_cache, self.summary.units_from_network
            ),
        ];
        out.push(
            if self.summary.receipt_included {
                "  The Arbitrum payment receipt is included: it names the wallet that paid, and \
                 links this work to every other seal that wallet paid for."
            } else {
                "  The Arbitrum payment receipt is not included."
            }
            .to_owned(),
        );
        out.push(format!(
            "Anyone you send it to can check it at {VERIFIER_URL} — drop the file on that page \
             for an offline verdict, or run `antseal verify {}`.",
            self.bundle_path.display()
        ));
        out
    }

    /// The `--json` result document (U3's envelope wraps it).
    ///
    /// **Tier C** under D65 §3 — reviewed by the committed fixture, not
    /// promised until U32 — carrying no tier-A member, so the
    /// alphabetization every `serde_json::Value` document undergoes here
    /// costs nothing. D65 §7's two rules that ride tier C anyway are
    /// honoured: every key is always present, and no key's JSON type varies
    /// run to run.
    ///
    /// `bytes` rides as a JSON number (restore's per-file `bytes`
    /// precedent): a bundle that could exceed 2⁵³ bytes cannot be built,
    /// held in memory or sent.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "work_id": hex32(&self.work_id),
            "bundle_path": self.bundle_path.display().to_string(),
            "bytes": self.bytes,
            "revealed_unit_ids": self.summary.revealed_unit_ids,
            "files_fully_revealed": self.summary.files_fully_revealed,
            "files_touched": self.files_touched,
            "receipt_included": self.summary.receipt_included,
            "units": {
                "from_cache": self.summary.units_from_cache,
                "from_network": self.summary.units_from_network,
            },
            // The one canonical URL, from the one constant (D62 §3 R8), so a
            // machine consumer printing the same closing line never has to
            // hard-code an address of its own.
            "verifier_url": VERIFIER_URL,
        })
    }
}

/// Resolve, check, gather, consent, build and write one reveal — the whole
/// `reveal` command minus argument parsing and the backend's construction.
///
/// # The consent seam (U29's, deliberately left open here)
///
/// `consent` is invoked with the [`PreparedReveal`] **after** the preview
/// exists and **before** anything bundle-shaped does — R16's two-phase
/// `prepare → build` split exists for exactly this, and collapsing it would
/// mean a bundle existed before the user agreed to it. U28 supplies the
/// seam and the plumbing; **U29 supplies the gate**: the preview rendering,
/// the receipt-exposure warning, `--yes`, and D51's machine-mode matrix
/// (`--json` ∨ non-TTY ∨ fd-0-consumed stdin never prompts; declined ≡
/// unobtainable; one consent-not-obtained class). A gate that refuses
/// returns its own [`CliError`] here and **nothing is written** — dropping
/// the prepared value discloses nothing and opens no whole-file commitment.
///
/// # What the handler above still owns (U29's, recorded so it is not
/// rediscovered)
///
/// The vault lock and the backend. This function **takes no U5 lock**, and
/// deliberately: it writes nothing into the vault — R16's `prepare` reads,
/// and the one write is the bundle at a path the user chose — which is the
/// same reason `run_restore` takes none. It also constructs no backend: the
/// storage-backend seam is U36's, shared with `seal` and `restore`.
///
/// # Errors
///
/// [`CliError::RefusedBundleOverwrite`] when the target is occupied (before
/// any fetch); whatever the gate returns; the mapped [`RevealError`]
/// classes (D69 §5); and [`CliError::Io`] when the write itself fails.
///
/// [`RevealError`]: crate::pipeline::reveal::RevealError
pub async fn run_reveal<B, G>(
    backend: &B,
    store: &WorkStore<'_>,
    args: &RevealArgs,
    consent: G,
) -> Result<RevealReport, CliError>
where
    B: StorageBackend,
    G: FnOnce(&PreparedReveal) -> Result<(), CliError>,
{
    // ── D68 §3 R8: the path first, and the collision with it ──
    let seal_id = resolve_work_id(store, &args.work_id)?;
    let work_id = store
        .load_meta(&seal_id)
        .map_err(CliError::from)?
        .work_id
        // Unreachable through this path: `resolve_work_id` matches on
        // `record.work_id == Some(..)`, so a work it returned has one. An
        // `expect` here would be a panic in library code (working principle
        // 2), and inventing a work id would name the wrong file.
        .ok_or_else(|| CliError::Internal {
            detail: "the resolved work records no work id, so no default bundle path exists"
                .to_owned(),
        })?;
    let target = resolve_bundle_path(args.output.as_deref(), &work_id);
    check_target_absent(&target)?;

    // ── R16: resolve the selection, gather, decrypt, preview ──
    let request = RevealRequest {
        selection: selection_of(args),
        include_receipt: args.include_receipt,
    };
    let prepared = RevealEngine::new(backend, store)
        .prepare(&seal_id, &request)
        .await?;
    let files_touched = prepared.preview().totals.files_touched;

    // ── U29's irreversible-disclosure gate sits exactly here ──
    consent(&prepared)?;

    // ── R13: build (self-verifying), then write exclusively ──
    let output = prepared.build()?;
    write_exclusive(&target, &output.sealproof)?;

    Ok(RevealReport {
        work_id,
        bundle_path: target,
        bytes: output.sealproof.len() as u64,
        files_touched,
        summary: output.summary,
    })
}

/// The typed selection behind `--all` / `--units` (D68 §3 R1–R2).
///
/// The clap layer guarantees exactly one is present and validates the
/// value's **lexis only**; every manifest-relative judgment — an unknown
/// id, a bare raw-mirror id, the D70 promotion — stays in R16's resolution,
/// where the ids, the kinds and the typed errors already live. An empty id
/// list cannot arrive from argv (clap rejects every empty spelling first,
/// D68 §1 g); constructed directly it is R16's `EmptySelection`.
fn selection_of(args: &RevealArgs) -> UnitSelection {
    if args.all {
        UnitSelection::All
    } else {
        UnitSelection::Ids(args.units.clone())
    }
}

/// D68 §3 R9's write discipline: exclusive creation at the final path,
/// written, flushed and closed; the partial file removed on any write
/// error.
///
/// `create_new(true)` is `O_EXCL` — the kernel-level "this file did not
/// exist" that makes the never-overwrite rule true even against a target
/// that appeared between the pre-flight check and this call. Not
/// temp-and-rename: a rename would clobber, which is the one outcome D68 §3
/// R7 forbids.
fn write_exclusive(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                CliError::RefusedBundleOverwrite {
                    path: path.to_path_buf(),
                }
            } else {
                CliError::Io {
                    context: format!("creating the proof bundle at {}", path.display()),
                    source,
                }
            }
        })?;
    if let Err(source) = file.write_all(bytes).and_then(|()| file.flush()) {
        // Close before removing, so no handle outlives the file it named.
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(CliError::Io {
            context: format!(
                "writing the proof bundle to {} (the partial file was removed)",
                path.display()
            ),
            source,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BUNDLE_FILE_EXTENSION, BUNDLE_FILE_PREFIX, RevealReport, check_target_absent,
        default_bundle_path, resolve_bundle_path, write_exclusive,
    };
    use crate::brand::VERIFIER_URL;
    use crate::error::ErrorClass;
    use crate::pipeline::reveal::RevealSummary;
    use std::path::{Path, PathBuf};

    /// A scratch directory that removes itself.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "antseal-u28-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).expect("mk scratch");
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn summary() -> RevealSummary {
        RevealSummary {
            revealed_unit_ids: vec![0, 1, 4],
            files_fully_revealed: vec![0],
            receipt_included: false,
            units_from_cache: 3,
            units_from_network: 0,
        }
    }

    /// D68 §3 R5's worked example, from a fixed `[u8; 32]` and through the
    /// constants rather than a literal extension (D68 §3 R11 pin 1).
    #[test]
    fn the_default_bundle_path_is_d68s_worked_example() {
        let work_id = [0xAB; 32];
        assert_eq!(
            default_bundle_path(&work_id),
            PathBuf::from(format!(
                "{BUNDLE_FILE_PREFIX}{}.{BUNDLE_FILE_EXTENSION}",
                "ab".repeat(32)
            ))
        );
        // The bound D68 computes: 15 + 64 + 10 = 89 bytes, closed alphabet.
        let name = default_bundle_path(&work_id)
            .file_name()
            .expect("named")
            .to_string_lossy()
            .into_owned();
        assert_eq!(name.len(), 89, "{name}");
        assert!(
            name.strip_prefix(BUNDLE_FILE_PREFIX)
                .and_then(|rest| rest.strip_suffix(&format!(".{BUNDLE_FILE_EXTENSION}")))
                .is_some_and(|hex| hex.len() == 64
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            "the variable part is 64 closed-alphabet hex characters: {name}"
        );
        // cwd-relative, never a directory, never absolute.
        assert!(default_bundle_path(&work_id).parent() == Some(Path::new("")));
    }

    /// `-o` is taken verbatim — no extension coercion, no re-rooting — and
    /// its absence is the default (D68 §3 R5).
    #[test]
    fn an_explicit_output_path_is_taken_verbatim() {
        let work_id = [0x11; 32];
        assert_eq!(
            resolve_bundle_path(Some(Path::new("pitch.txt")), &work_id),
            PathBuf::from("pitch.txt")
        );
        assert_eq!(
            resolve_bundle_path(Some(Path::new("/tmp/out/b")), &work_id),
            PathBuf::from("/tmp/out/b")
        );
        assert_eq!(
            resolve_bundle_path(None, &work_id),
            default_bundle_path(&work_id)
        );
    }

    /// Every occupied target is refused, and an absent one is not — the
    /// pre-flight half of D68 §3 R7.
    #[test]
    fn every_occupied_target_is_refused_and_an_absent_one_is_not() {
        let scratch = Scratch::new("occupied");
        assert!(check_target_absent(&scratch.join("absent.sealproof")).is_ok());

        let file = scratch.join("file.sealproof");
        std::fs::write(&file, b"anything").expect("write");
        let dir = scratch.join("dir.sealproof");
        std::fs::create_dir(&dir).expect("mkdir");
        for occupied in [&file, &dir] {
            let err = check_target_absent(occupied).expect_err("occupied");
            assert_eq!(err.class(), ErrorClass::RefusedOverwrite, "{err}");
            let message = err.to_string();
            assert!(
                message.contains(&occupied.display().to_string()) && message.contains("-o"),
                "the refusal names the path and the way out: {message}"
            );
        }
    }

    /// The exclusive write refuses an existing file at the kernel level and
    /// leaves its bytes untouched — the property `create_new` buys that a
    /// rename would destroy (D68 §3 R9).
    #[test]
    fn the_write_is_exclusive_and_never_replaces_existing_bytes() {
        let scratch = Scratch::new("exclusive");
        let target = scratch.join("bundle.sealproof");
        write_exclusive(&target, b"first bundle").expect("writes");
        assert_eq!(std::fs::read(&target).expect("read"), b"first bundle");

        let err = write_exclusive(&target, b"second bundle").expect_err("refused");
        assert_eq!(err.class(), ErrorClass::RefusedOverwrite, "{err}");
        assert_eq!(
            std::fs::read(&target).expect("read"),
            b"first bundle",
            "the existing bundle's bytes are untouched"
        );
    }

    /// A write into a directory that does not exist is the ordinary I/O
    /// class and leaves nothing behind — reveal creates no directories
    /// (unlike `restore`, whose `-o` is a directory by type).
    #[test]
    fn a_write_into_a_missing_directory_is_an_io_error_leaving_nothing() {
        let scratch = Scratch::new("nodir");
        let target = scratch.join("missing/bundle.sealproof");
        let err = write_exclusive(&target, b"bytes").expect_err("no such directory");
        assert_eq!(err.class(), ErrorClass::IoError, "{err}");
        assert!(!target.exists());
        assert!(!scratch.join("missing").exists());
    }

    /// The closing lines carry the path and the one canonical URL, from the
    /// constant (D62 §3 R8; U28's `Do`).
    #[test]
    fn the_closing_lines_name_the_bundle_and_the_verifier_page() {
        let report = RevealReport {
            work_id: [0xA1; 32],
            bundle_path: default_bundle_path(&[0xA1; 32]),
            bytes: 4096,
            files_touched: 2,
            summary: summary(),
        };
        let rendered = report.render();
        let closing = rendered.last().expect("a closing line").clone();
        assert!(closing.contains(VERIFIER_URL), "{closing}");
        assert!(
            rendered[0].contains(&report.bundle_path.display().to_string()),
            "{}",
            rendered[0]
        );
        // Possession language only: no verdict, no notary, no unqualified
        // priority claim (U31).
        let all = rendered.join("\n").to_lowercase();
        for forbidden in [
            "notary", "notarize", "notarise", "legally", "priority", "certif",
        ] {
            assert!(!all.contains(forbidden), "`{forbidden}` in:\n{all}");
        }
    }

    /// The receipt line states the exposure when the receipt rides, and
    /// says plainly that it does not otherwise (spec lines 36/110/185).
    #[test]
    fn the_receipt_line_states_the_exposure_only_when_it_rides() {
        let base = RevealReport {
            work_id: [0x22; 32],
            bundle_path: PathBuf::from("b.sealproof"),
            bytes: 10,
            files_touched: 1,
            summary: summary(),
        };
        let without = base.render().join("\n");
        assert!(without.contains("receipt is not included"), "{without}");
        assert!(!without.contains("wallet"), "{without}");

        let with = RevealReport {
            summary: RevealSummary {
                receipt_included: true,
                ..summary()
            },
            ..base
        }
        .render()
        .join("\n");
        assert!(with.contains("wallet that paid"), "{with}");
    }
}
