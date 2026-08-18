//! `seal`'s plan validation (U13): the checks that run before anything is
//! unlocked, quoted, consented to, anchored, paid or uploaded.
//!
//! *"Before anything is **read**"* was true of this module until D149 §2
//! R2 and is not any more. D24 §1's `--split` x `--no-fine-tree` refusal
//! has a condition — *is this file text?* — that no `stat`, extension or
//! fixed-size prefix can answer (`is_text` is strict UTF-8 validity over
//! the **whole** file, MVP-SPEC.md line 83), so the refusal reads the
//! files a `--no-fine-tree` glob matched under an active `--split`,
//! bounded and one-sided ([`file_is_text`]). That is the only read here,
//! it happens under that flag pair only, and it is on the path that
//! exists to say no.
//!
//! # Why this is a separate module from the pipeline
//!
//! [`Pipeline::seal`](crate::pipeline::Pipeline::seal) is written over
//! *bytes* — it performs no I/O of its own (D34). Everything between argv
//! and those bytes is here: which arguments name real, sealable files
//! (D46), which of them a `--no-fine-tree` pattern covers, how the D45
//! invocation identity is spelled, and the one flag combination that is
//! refused outright.
//!
//! Every function in this module is pure, `stat`-only, or — for the one
//! D24 §1 refusal — reads a file the user's own glob selected, to answer
//! that refusal's own condition. Nothing here opens a vault, collects a
//! passphrase, touches the network, or writes a byte — which is what lets
//! `--dry-run` run the identical code (D49) and what lets the whole D46
//! matrix be tested without a backend.
//!
//! # The order the checks run in, and why
//!
//! ```text
//! --no-anchor × arbitrum-one   (flag-only; no filesystem access at all)
//!   → D46 argument validation  (stat per argument; every problem collected)
//!   → the M1 anchor-stage gate (this build cannot anchor yet)
//!   → --no-fine-tree matching  (pure, over the validated list)
//!   → --split x --no-fine-tree (D24 §1; the only step that reads bytes,
//!                               and only files the glob matched)
//! ```
//!
//! The mainnet guard is first because it mirrors
//! [`Pipeline::seal`](crate::pipeline::Pipeline::seal)'s own first
//! statement: the CLI check and the library check are the same refusal in
//! the same position, and this module *constructs the library's error
//! value* rather than paraphrasing it, so the two layers cannot drift into
//! saying different things. It also needs no filesystem access, which
//! makes it the cheapest thing that can say no.
//!
//! D46 validation comes before the M1 anchor-stage gate deliberately: a
//! directory argument is wrong permanently, and the milestone gap is
//! temporary. Telling a user about the temporary obstacle first would make
//! them fix the network flag and *then* discover the real problem.
//!
//! # D46: files only, every offending argument named
//!
//! `docs/decisions/D46-seal-directory-arguments.md` fixes four rules,
//! checked here in one pass so "all argument validation completes before
//! consent" (D46 rule 4's stated purpose) is literally true:
//!
//! 1. a **directory** — after following the argument's own symlink
//!    (`stat`, not `lstat`: a symlink naming a *file* is the user's
//!    deliberate act and is accepted; a symlink to a directory is a
//!    directory);
//! 2. a **non-regular file** (FIFO, device, socket — reading one is
//!    blocking or non-deterministic, and no permanent paid artifact may
//!    depend on it);
//! 3. a **lexical duplicate** of another argument;
//! 4. missing or unreadable — the *ordinary I/O class* (D46 rule 4), not
//!    the D46 argument class.
//!
//! Rules 1–3 report together as one [`CliError::InvalidSealArgument`]
//! naming every offender. Rule 4 reports as [`CliError::Io`]. When both
//! kinds are present the D46 class wins and the missing paths are named
//! inside it — one message, everything the user has to fix.
//!
//! # Lexical absolutization keeps `..`
//!
//! [`absolutize`] cwd-joins and drops `.` and repeated separators, and
//! **deliberately does not pop `..`** — D45 §1's rule, and the only sound
//! one: `link/../x` where `link` is a symlink to another directory does
//! not name `./x`, so popping would declare two different files
//! duplicates and refuse a legitimate seal. The cost is that
//! `a/../a.txt` and `a.txt` are two identities rather than one; the
//! benefit is that no correct invocation is ever refused. Conservative in
//! the direction that only ever costs a duplicate-detection miss.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use antseal_core::content::{FileFlags, SplitMode as ContentSplitMode};
use antseal_net::NetworkId;

use crate::cli::{SealArgs, SplitMode};
use crate::error::CliError;
use crate::pipeline::SealError;
use crate::vault::store::SealShapingFlags;

/// One validated argument, ready to become a
/// [`SealFile`](crate::pipeline::SealFile) once its bytes are read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedFile {
    /// The path exactly as the user spelled it (committed to via
    /// `path_commit`, and what the D45 record calls "as given").
    pub as_given: String,
    /// The same path lexically absolutized — D45's resume match key.
    pub absolute: String,
    /// Size in bytes, from the same `stat` that validated the argument —
    /// which is also what lets [`refuse_split_on_no_fine_tree`] exempt an
    /// empty file for free, before any read.
    ///
    /// Displayed by the consent gate (U14). *"…before anything is read"*
    /// stood here until D149 §2 R2 and no longer holds of the process: a
    /// file matched by `--no-fine-tree` under an active `--split` has been
    /// read by then, bounded as R2 specifies. The `stat` this field comes
    /// from is still the only source of the **number**.
    pub size: u64,
    /// The per-file semantic flags G consumes.
    pub flags: FileFlags,
}

/// A validated seal invocation: what will be sealed, under which flags,
/// on which network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealPlan {
    /// The files, in argument order (position = `file_id`).
    pub files: Vec<PlannedFile>,
    /// The D45 seal-shaping flag set — the invocation identity's second
    /// half.
    pub shaping: SealShapingFlags,
    /// The effective network (flag > config > default, resolved by U4).
    pub network: NetworkId,
    /// `--dry-run` (D49).
    pub dry_run: bool,
    /// `--yes` (D51's declared consent channel).
    pub yes: bool,
}

impl SealPlan {
    /// Total input bytes — the "byte totals" the consent report shows.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.files
            .iter()
            .fold(0u64, |acc, f| acc.saturating_add(f.size))
    }

    /// The as-given paths of every file a `--no-fine-tree` pattern
    /// matched (U15's warning names exactly these).
    #[must_use]
    pub fn no_fine_tree_matches(&self) -> Vec<&str> {
        self.files
            .iter()
            .filter(|f| f.flags.no_fine_tree_matched())
            .map(|f| f.as_given.as_str())
            .collect()
    }

    /// The lexically absolutized path list — D45's match key, in argument
    /// order.
    #[must_use]
    pub fn absolute_paths(&self) -> Vec<String> {
        self.files.iter().map(|f| f.absolute.clone()).collect()
    }

    /// The as-given path list, in argument order.
    #[must_use]
    pub fn as_given_paths(&self) -> Vec<String> {
        self.files.iter().map(|f| f.as_given.clone()).collect()
    }
}

/// Build and validate the plan for a `seal` invocation.
///
/// `cwd` is injected rather than read from the process so the whole D46
/// matrix is drivable from a test with a fixture directory as the working
/// directory — and so the one place a *process-global* is consulted is a
/// place a reviewer can find (the same discipline `SealRequest` applies to
/// the clock).
///
/// # Errors
///
/// - [`CliError::InvalidSealArgument`] — the `--no-anchor` × `arbitrum-one`
///   refusal (constructed from [`SealError::NoAnchorOnMainnet`], so the CLI
///   and the library say the same words), any D46 rule 1–3 violation, or
///   D24 §1's `--split` × `--no-fine-tree` conflict — with every offending
///   argument named.
/// - [`CliError::Io`] — arguments that do not exist or cannot be `stat`ed,
///   when that is the *only* problem (D46 rule 4); or a `--no-fine-tree`
///   match that cannot be opened or read while D24 §1's condition is being
///   decided (D149 §2 R2).
/// - [`CliError::Usage`] — a `--no-fine-tree` pattern that matches no file
///   in the work.
pub fn build_plan(args: &SealArgs, network: NetworkId, cwd: &Path) -> Result<SealPlan, CliError> {
    // ── 1. The flag combination that never needs a filesystem ──
    //
    // Constructed, not paraphrased: `SealError`'s Display is the single
    // author of this refusal and `From<SealError>` is the single author
    // of its class, so the CLI-level guard and S13's library-level guard
    // are the same sentence with the same exit code by construction.
    if args.no_anchor && network == NetworkId::ArbitrumOne {
        return Err(SealError::NoAnchorOnMainnet.into());
    }

    // ── 2. D46, in one pass over every argument ──
    let files = validate_arguments(&args.paths, cwd)?;

    // ── 3. `--no-fine-tree` matching, over the validated list ──
    //
    // U22 removed the M1 anchor-stage gate that used to sit here and refuse
    // **every** seal without `--no-anchor`. The stage it stood in for is
    // wired now (`seal_run` injects A20's `SubmitAnchorGate`), and the
    // refusal a user can still meet — zero verified TSA tokens — is that
    // gate's own, made after consent and before `pay` with its own exit
    // code. Nothing anchor-shaped is decidable from argv alone any more,
    // except the `--no-anchor` × mainnet combination checked in step 1.
    let shaping = shaping_flags(args);
    let base = base_flags(args);
    let mut planned = Vec::with_capacity(files.len());
    let mut matched_any = false;
    for file in files {
        let excluded = shaping
            .no_fine_tree
            .iter()
            .any(|pattern| pattern_matches(pattern, &file.as_given, &file.absolute));
        matched_any |= excluded;
        planned.push(PlannedFile {
            flags: if excluded {
                base.with_no_fine_tree()
            } else {
                base
            },
            ..file
        });
    }
    // A pattern that matches nothing is a silent, permanent wrong answer:
    // the user asked for whole-file-only treatment, got a fine tree
    // anyway, paid for it, and finds out never. Refusing costs one re-run;
    // proceeding costs the artifact.
    if !shaping.no_fine_tree.is_empty() && !matched_any {
        return Err(CliError::Usage {
            message: format!(
                "--no-fine-tree {} matched none of the {} file(s) given: the pattern is \
                 matched against each path as you spelled it and against its final \
                 component, with `*` and `?` as the only metacharacters (`*` and `?` do not \
                 cross `/`). Nothing was quoted, anchored, paid, or uploaded",
                shaping.no_fine_tree.join(", "),
                planned.len()
            ),
        });
    }

    // ── 4. D24 §1: `--split` x `--no-fine-tree` on the same text file ──
    //
    // Last because it is the only check that opens a file: everything
    // decidable from argv or from the `stat` that already happened has
    // had its chance, so nothing is read for an invocation another rule
    // was going to refuse anyway.
    refuse_split_on_no_fine_tree(&planned, &shaping.no_fine_tree)?;

    Ok(SealPlan {
        files: planned,
        shaping,
        network,
        dry_run: args.dry_run,
        yes: args.yes,
    })
}

/// One D46 problem, kept typed until the whole pass is done so the report
/// can name every offender at once.
#[derive(Debug)]
enum Problem {
    /// Rules 1–3: the D46 argument class.
    Argument(String),
    /// Rule 4: the ordinary I/O class.
    Io {
        detail: String,
        source: std::io::Error,
    },
}

/// D46's single validation pass. Returns files with **no** flags applied
/// yet (matching happens once the whole list is known).
fn validate_arguments(paths: &[PathBuf], cwd: &Path) -> Result<Vec<PlannedFile>, CliError> {
    let mut problems: Vec<Problem> = Vec::new();
    let mut files: Vec<PlannedFile> = Vec::new();
    // absolutized path → the as-given spelling that claimed it first.
    let mut seen: BTreeMap<String, String> = BTreeMap::new();

    for path in paths {
        // v1 records are UTF-8 (U9's recorded limitation), and a path
        // that cannot be recorded cannot be resumed or restored — so it
        // is refused here, pre-consent, rather than after payment.
        let Some(as_given) = path.to_str() else {
            problems.push(Problem::Argument(format!(
                "{} is not valid UTF-8; antseal records input paths as UTF-8 text (v1)",
                path.display()
            )));
            continue;
        };
        let absolute_path = absolutize(cwd, path);
        let Some(absolute) = absolute_path.to_str().map(str::to_owned) else {
            problems.push(Problem::Argument(format!(
                "{as_given} does not absolutize to valid UTF-8; antseal records input paths \
                 as UTF-8 text (v1)"
            )));
            continue;
        };

        // Rule 3, before the stat: two spellings of one path is a
        // question about the argument list, not about the filesystem.
        if let Some(first) = seen.get(&absolute) {
            problems.push(Problem::Argument(if first == as_given {
                format!("{as_given} is given twice (each file is sealed and paid for once)")
            } else {
                format!(
                    "{as_given} and {first} are the same file after lexical normalization \
                     (each file is sealed and paid for once)"
                )
            }));
            continue;
        }

        // Rules 1, 2 and 4. `metadata` follows the argument's own
        // symlink, which is D46's stat-not-lstat rule verbatim.
        //
        // The **absolutized** path is what is `stat`ed, not the argument
        // as spelled: `cwd` is injected (so the D46 matrix is drivable
        // against a fixture directory), and resolving a relative argument
        // against the process's own cwd instead would quietly make the
        // parameter a lie. `cwd.join(relative)` names exactly the file
        // the OS would have opened, so production behaviour is unchanged.
        match std::fs::metadata(&absolute_path) {
            Err(source) => problems.push(Problem::Io {
                detail: as_given.to_owned(),
                source,
            }),
            Ok(meta) if meta.is_dir() => problems.push(Problem::Argument(format!(
                "{as_given} is a directory; antseal seals an explicit file list — expand it \
                 yourself, e.g. `antseal seal {as_given}/*.md` or \
                 `antseal seal $(find {as_given} -type f | sort)` (D46)"
            ))),
            Ok(meta) if !meta.is_file() => problems.push(Problem::Argument(format!(
                "{as_given} is not a regular file; a permanent, paid-for seal may not depend \
                 on a FIFO, socket or device, whose contents are not reproducible (D46)"
            ))),
            Ok(meta) => {
                seen.insert(absolute.clone(), as_given.to_owned());
                files.push(PlannedFile {
                    as_given: as_given.to_owned(),
                    absolute,
                    size: meta.len(),
                    flags: FileFlags::new(),
                });
            }
        }
    }

    report(problems)?;
    Ok(files)
}

/// Turn a finished problem list into the one error the user sees.
///
/// The D46 class wins whenever any rule 1–3 violation is present, and the
/// missing paths ride inside it: a user with both a directory argument and
/// a typo'd filename should see both in one message rather than fixing
/// one and re-running to discover the other.
fn report(problems: Vec<Problem>) -> Result<(), CliError> {
    if problems.is_empty() {
        return Ok(());
    }
    let has_argument_class = problems.iter().any(|p| matches!(p, Problem::Argument(_)));
    if has_argument_class {
        return Err(CliError::InvalidSealArgument {
            problems: problems
                .into_iter()
                .map(|p| match p {
                    Problem::Argument(detail) => detail,
                    Problem::Io { detail, source } => format!("{detail} cannot be read: {source}"),
                })
                .collect(),
        });
    }
    // Rule 4 alone: the ordinary I/O class. Every unreadable argument is
    // named in the context; the first one's `io::Error` is the source, so
    // `--verbose`-style tooling still sees a real errno.
    let mut names = Vec::with_capacity(problems.len());
    let mut source = None;
    for problem in problems {
        if let Problem::Io { detail, source: e } = problem {
            names.push(detail);
            source.get_or_insert(e);
        }
    }
    Err(CliError::Io {
        context: format!("reading seal argument(s) {}", names.join(", ")),
        source: source.unwrap_or_else(|| std::io::Error::other("unreadable seal argument")),
    })
}

/// D24 §1's refusal: a **text** file that `--split` selected for splitting
/// and that a `--no-fine-tree` glob also matched.
///
/// The two flags ask for incompatible *permanent* granularities.
/// `--no-fine-tree` makes a file whole-file-reveal-only forever (spec line
/// 85) and unit boundaries are frozen at seal time, so the sub-file units
/// `--split` asked for (line 84) could never be revealed. D24 layer 2
/// makes that contradiction unrepresentable in the model
/// ([`antseal_core::content::unit::SplitEligibleText`] is the witness only
/// a fine-tree-covered text descriptor can produce) — but *unrepresentable
/// is not rejected*: the model reconciles by falling back to one whole-file
/// unit, silently. Silence is the outcome D24's status line says was not
/// chosen, and this function is layer 1, the half that says so out loud.
///
/// # Why here and not one layer down
///
/// Every other candidate site — `run_seal`, `Pipeline::seal`'s own plan
/// validation — sits behind the vault lock, the passphrase prompt and the
/// network connect (`commands.rs`'s `seal_over_backend`). D24 rationale 1
/// is *"re-running a failed command costs seconds"*, and that is a claim
/// about this function and about nowhere else: raised any later, a
/// two-flag typo would cost a passphrase entry and a connect. D149 §1.4
/// measured the alternatives; §3.2 and §3.3 record why each loses.
///
/// # The term order is normative (D149 §2 R1)
///
/// `split()` and `no_fine_tree_matched()` are argv-cheap, `size` came from
/// the `stat` that already happened, and `force_text()` is argv again — so
/// [`file_is_text`]'s read is reached only once nothing cheaper can
/// answer. **`--force-text` costs no I/O, and an empty file costs no
/// I/O.** Reordering the terms is a behaviour change, not a tidy-up.
///
/// `--force-text` is a *positive*, not an exemption: it makes a file text
/// by argv (spec line 83), so it is the one flag that turns a genuinely
/// binary matched file into a refusal. That combination passes silently in
/// every build before this one (D149 §1.3 run M3).
///
/// Empty files are exempt because the opt-out cost them nothing:
/// `CanonDescriptor::describe_file` sets
/// `fine_tree_present = !opt_out.is_requested() && size > 0`, so a
/// raw-empty file is split-ineligible **with** the opt-out and without it.
/// This refusal exists to catch granularity the opt-out destroyed; on an
/// empty file it destroyed none, and refusing would be the over-reach D24
/// §1 already avoids for binary files.
///
/// # Errors
///
/// [`CliError::InvalidSealArgument`] — one problem per offending file,
/// every one named in a single message (D46's own *"every offending
/// argument named"* rule, reused here so a user with two conflicting files
/// fixes both in one re-run) — or
/// [`CliError::Io`] if a matched file cannot be read at all.
fn refuse_split_on_no_fine_tree(
    planned: &[PlannedFile],
    patterns: &[String],
) -> Result<(), CliError> {
    let mut problems: Vec<Problem> = Vec::new();
    for file in planned {
        if file.flags.split().is_some()
            && file.flags.no_fine_tree_matched()
            && file.size > 0
            && (file.flags.force_text() || file_is_text(&file.absolute, &file.as_given)?)
        {
            // The pattern(s) that actually matched **this** file,
            // recomputed with the very function that made the decision.
            // Printing the whole `--no-fine-tree` list would leave the
            // user to work out which entry caught which file, and a
            // paraphrase could disagree with the matcher.
            let patterns = patterns
                .iter()
                .filter(|pattern| pattern_matches(pattern, &file.as_given, &file.absolute))
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            let as_given = &file.as_given;
            // The "counts as text by antseal's rule" clause is load-bearing,
            // not decoration: a 10 KiB `tar` is valid UTF-8 end to end, so
            // `--no-fine-tree '*.tar'` refuses files the user calls binary
            // (D149 §1.5). State the rule rather than assert a
            // classification the user will dispute. The two workarounds are
            // D24 §1's own; there is deliberately no third.
            problems.push(Problem::Argument(format!(
                "{as_given} is selected for splitting by --split blank-lines and is also \
                 matched by --no-fine-tree {patterns}: --no-fine-tree makes it permanently \
                 whole-file-reveal only, so the sub-file units --split asks for could never \
                 be revealed from it, and unit boundaries are frozen forever at seal time. \
                 It counts as text by antseal's rule — valid UTF-8, or --force-text \
                 (MVP-SPEC.md line 83). Seal it as a separate work without --split, or drop \
                 one of the two flags (D24)"
            )));
        }
    }
    report(problems)
}

/// How much of a file [`file_is_text`] reads before it has to commit to
/// reading the rest. One buffer decides essentially every non-UTF-8 file
/// (D149 §1.5: a 128 MB ELF is settled at byte 40).
const TEXT_PROBE_BYTES: u64 = 8192;

/// Is this file text — [`antseal_core::canon::is_text`]'s answer, reached
/// as cheaply as that answer allows.
///
/// The only function in this module that opens a file. `as_given` is
/// carried purely so the I/O context names the path the user typed rather
/// than the absolutized one.
///
/// # Errors
///
/// [`CliError::Io`] if the file cannot be opened or read. It was `stat`ed
/// successfully moments ago (D46 rule 4), so this is a race or a
/// permissions gap, not the ordinary missing-file case.
fn file_is_text(absolute: &str, as_given: &str) -> Result<bool, CliError> {
    let io = |source| CliError::Io {
        context: format!("reading {as_given} to decide --split against --no-fine-tree (D24)"),
        source,
    };
    let file = std::fs::File::open(absolute).map_err(io)?;
    text_verdict(file).map_err(io)
}

/// [`file_is_text`]'s rule, over any reader — which is what lets a test
/// put a byte budget under it and watch the early exit happen (D149 §2
/// R10 T6) instead of trusting that it does.
///
/// # Bounded on one side only
///
/// The tempting cheap probe is *"read 8 KiB; valid UTF-8 means text"*, and
/// measured it is wrong in the direction that over-refuses (D149 §1.5).
/// What is sound is the negative: [`str::from_utf8`] distinguishes a
/// genuinely invalid sequence (`error_len() == Some(_)`) from one merely
/// cut off by the end of the buffer (`error_len() == None`), and a genuine
/// invalid byte inside the head settles the **whole** file, because
/// appending bytes can never repair it. So a *negative* may be taken from
/// the head and a *positive* may not: a 10 KiB `tar` — valid UTF-8 end to
/// end, NUL being a perfectly good scalar — correctly falls through to the
/// whole file.
///
/// # One text rule, not two
///
/// [`antseal_core::canon::is_text`] stays the **sole** author of "this
/// file is text". The head branch never returns `true` on its own; it only
/// short-circuits a `false` that `is_text` would have returned anyway. Do
/// not add an extension test, a NUL scan or a control-character ratio
/// here: spec line 83 and `canon::is_text`'s own doc state the rule has no
/// heuristic, and a second rule in the CLI would refuse files the model
/// would have split and pass files it would not.
///
/// # Why the tail comes off the same handle
///
/// D149 §2 R2 writes the fall-through as a fresh `std::fs::read` of the
/// path. Continuing the open handle is that rule with its two reads fused:
/// identical verdict on any file that is not being rewritten underneath
/// us, one `open` instead of two, the head bytes read once instead of
/// twice — and, on a file that *is* changing, a verdict taken from one
/// version rather than half from each. It is also what gives the R10 T6
/// budget a single reader to observe; with two opens the second read would
/// bypass any seam a test could hold.
fn text_verdict<R: std::io::Read>(mut source: R) -> std::io::Result<bool> {
    use std::io::Read as _;

    let mut bytes = Vec::new();
    (&mut source)
        .take(TEXT_PROBE_BYTES)
        .read_to_end(&mut bytes)?;
    if bytes.len() < TEXT_PROBE_BYTES as usize {
        // A short read out of a `Take` is EOF: this IS the whole file, so
        // `is_text` over it is the final answer and no tail is read.
        return Ok(antseal_core::canon::is_text(&bytes));
    }
    if let Err(e) = std::str::from_utf8(&bytes)
        && e.error_len().is_some()
    {
        return Ok(false);
    }
    source.read_to_end(&mut bytes)?;
    Ok(antseal_core::canon::is_text(&bytes))
}

/// Lexically absolutize: cwd-join, drop `.` and repeated separators,
/// **keep `..`** (module docs; D45 §1).
///
/// `Path::components` performs exactly that normalization — it elides
/// `CurDir` and collapses separators while yielding `ParentDir` verbatim —
/// so re-collecting the components *is* the rule rather than an
/// approximation of it.
#[must_use]
pub fn absolutize(cwd: &Path, path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    joined.components().collect()
}

/// The D45 seal-shaping flag set. Session flags (`--yes`, `--json`,
/// `--dry-run`, `--passphrase-fd`) are deliberately absent — they say
/// nothing about *what* is sealed, so they must not split one resumable
/// work into two identities.
#[must_use]
pub fn shaping_flags(args: &SealArgs) -> SealShapingFlags {
    SealShapingFlags {
        title: args.title.clone(),
        split_blank_lines: args.split == Some(SplitMode::BlankLines),
        force_text: args.force_text,
        // `SealArgs::no_fine_tree` is one optional occurrence (U1's
        // recorded reading of the canonical surface); the record's field
        // is a `Vec` so that accepting repeats later stays additive.
        no_fine_tree: args.no_fine_tree.iter().cloned().collect(),
        no_anchor: args.no_anchor,
        force_degraded: args.force_degraded,
    }
}

/// The flags every file starts from (`--no-fine-tree` is per-file and is
/// applied afterwards).
fn base_flags(args: &SealArgs) -> FileFlags {
    let mut flags = FileFlags::new();
    if args.force_text {
        flags = flags.with_force_text();
    }
    if args.split == Some(SplitMode::BlankLines) {
        flags = flags.with_split(ContentSplitMode::BlankLines);
    }
    flags
}

/// Does a `--no-fine-tree` pattern cover this file?
///
/// Tried in order against: the path **as given**, its final component,
/// and the lexically absolutized path. Matching the as-given spelling
/// first is what makes the plain no-metacharacter case behave as exact-
/// path matching — `--no-fine-tree notes.txt` covers `notes.txt` and
/// nothing else.
#[must_use]
pub fn pattern_matches(pattern: &str, as_given: &str, absolute: &str) -> bool {
    let basename = as_given.rsplit('/').next().unwrap_or(as_given);
    glob_matches(pattern, as_given)
        || glob_matches(pattern, basename)
        || glob_matches(pattern, absolute)
}

/// The frozen `--no-fine-tree` pattern language.
///
/// # Scope, and why it is this small
///
/// `*` matches any run of characters **within one path segment**; `?`
/// matches exactly one character, also not `/`; every other byte is a
/// literal. There are no character classes, no brace expansion, and no
/// `**`.
///
/// This is a **deliberate non-dependency**. A glob crate would be a
/// dependency-policy §1 event (a new edge, its own transitive graph, its
/// own churn) taken for one flag, and — worse — it would import a
/// *semantics* this project would then have frozen into permanent, paid
/// artifacts without ever having written it down: which file gets a fine
/// tree is recorded per file in the manifest and can never be revised for
/// a work already sealed. Thirty lines whose entire behaviour is stated
/// in this paragraph is the smaller frozen surface, which is D46 rule 2's
/// own argument applied to a second decision.
///
/// The previous lane's recommendation was exact-path matching. That is
/// the metacharacter-free case of this function and behaves identically;
/// the two metacharacters are added because `--no-fine-tree <GLOB>` is
/// what the frozen `--help` surface promises, and because a pattern that
/// silently matched nothing would produce exactly the permanent wrong
/// artifact this design is built to avoid — which [`build_plan`] closes
/// from the other side by refusing a zero-match pattern outright.
#[must_use]
pub fn glob_matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // `star`/`mark`: the position of the last `*` seen and how much of
    // the text it has been made to absorb — the standard linear-ish
    // backtracking wildcard match, with the segment guard added.
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti] || (p[pi] == '?' && t[ti] != '/')) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(star_at) = star
            && t[mark] != '/'
        {
            // Make the star absorb one more character — never a `/`,
            // which is what keeps a pattern inside one path segment.
            mark += 1;
            ti = mark;
            pi = star_at + 1;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(paths: &[&str]) -> SealArgs {
        SealArgs {
            paths: paths.iter().map(PathBuf::from).collect(),
            title: None,
            split: None,
            force_text: false,
            no_fine_tree: None,
            dry_run: false,
            yes: false,
            force_degraded: false,
            no_anchor: true,
        }
    }

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "antseal-plan-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::create_dir_all(&root).expect("mk dir");
            Self(root)
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("mk parent");
            }
            std::fs::write(&path, bytes).expect("write fixture");
            path
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ── the wildcard language ───────────────────────────────────────

    #[test]
    fn a_pattern_with_no_metacharacters_is_exact_path_matching() {
        assert!(glob_matches("notes.txt", "notes.txt"));
        assert!(!glob_matches("notes.txt", "notes.txt.bak"));
        assert!(!glob_matches("notes.txt", "my-notes.txt"));
        assert!(!glob_matches("notes.txt", "docs/notes.txt"));
    }

    #[test]
    fn star_and_question_stay_inside_one_path_segment() {
        assert!(glob_matches("*.bin", "blob.bin"));
        assert!(glob_matches("src/*.rs", "src/main.rs"));
        // The segment guard: `*` may not swallow a separator.
        assert!(!glob_matches("src/*.rs", "src/deep/main.rs"));
        assert!(!glob_matches("*.rs", "src/main.rs"));
        assert!(glob_matches("a?c", "abc"));
        assert!(!glob_matches("a?c", "a/c"));
        // Degenerate patterns terminate and answer.
        assert!(glob_matches("*", "anything"));
        assert!(glob_matches("", ""));
        assert!(!glob_matches("", "x"));
        assert!(glob_matches("**", "x"));
        assert!(glob_matches("a*b*c", "aXXbYYc"));
        assert!(!glob_matches("a*b*c", "aXXbYY"));
    }

    #[test]
    fn a_pattern_is_tried_against_the_spelling_the_basename_and_the_absolute_path() {
        // The as-given spelling.
        assert!(pattern_matches("docs/a.md", "docs/a.md", "/w/docs/a.md"));
        // The basename — which is how `*.bin` covers a nested file.
        assert!(pattern_matches(
            "*.bin",
            "assets/img.bin",
            "/w/assets/img.bin"
        ));
        // The absolutized spelling, for a user who pasted a full path.
        assert!(pattern_matches("/w/docs/a.md", "docs/a.md", "/w/docs/a.md"));
        assert!(!pattern_matches("*.md", "notes.txt", "/w/notes.txt"));
    }

    // ── D46 ─────────────────────────────────────────────────────────

    #[test]
    fn a_directory_argument_is_refused_and_the_message_carries_the_workaround() {
        let dir = Dir::new("d46-dir");
        dir.file("keep.txt", b"x");
        std::fs::create_dir_all(dir.0.join("sub")).expect("mk sub");
        let err = build_plan(&args(&["keep.txt", "sub"]), NetworkId::Devnet, &dir.0)
            .expect_err("a directory argument is refused");
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidSealArgument);
        let rendered = err.to_string();
        assert!(rendered.contains("sub is a directory"), "{rendered}");
        assert!(
            rendered.contains("find"),
            "the recipe is offered: {rendered}"
        );
    }

    #[test]
    fn a_symlink_to_a_directory_is_a_directory_and_a_symlink_to_a_file_is_accepted() {
        let dir = Dir::new("d46-link");
        dir.file("real.txt", b"hello");
        std::fs::create_dir_all(dir.0.join("realdir")).expect("mk realdir");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.0.join("real.txt"), dir.0.join("to-file"))
                .expect("symlink to file");
            std::os::unix::fs::symlink(dir.0.join("realdir"), dir.0.join("to-dir"))
                .expect("symlink to dir");

            // stat-not-lstat: the file link is the user's deliberate act.
            let plan = build_plan(&args(&["to-file"]), NetworkId::Devnet, &dir.0)
                .expect("a symlink naming a file is accepted");
            assert_eq!(plan.files[0].size, 5);

            let err = build_plan(&args(&["to-dir"]), NetworkId::Devnet, &dir.0)
                .expect_err("a symlink to a directory is a directory");
            assert!(err.to_string().contains("is a directory"), "{err}");
        }
    }

    /// D46 rule 2's non-regular-file class, exercised with the one
    /// non-regular file std can create without `unsafe` (the workspace
    /// denies `unsafe_code`, so `mkfifo` is not available to this test):
    /// a bound Unix-domain socket. A FIFO, a device and a socket all
    /// reach the same `!is_file()` arm, so the rule is covered.
    #[cfg(unix)]
    #[test]
    fn a_socket_is_refused_as_a_non_regular_file() {
        let dir = Dir::new("d46-sock");
        let Ok(listener) = std::os::unix::net::UnixListener::bind(dir.0.join("sock")) else {
            // Some sandboxes forbid AF_UNIX binds; the directory case
            // above still covers plan validation, so skip rather than
            // report a failure that is not ours.
            return;
        };
        let err = build_plan(&args(&["sock"]), NetworkId::Devnet, &dir.0)
            .expect_err("a socket is refused");
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidSealArgument);
        assert!(err.to_string().contains("is not a regular file"), "{err}");
        drop(listener);
    }

    #[test]
    fn lexical_duplicates_are_refused_in_both_spellings() {
        let dir = Dir::new("d46-dup");
        dir.file("a.txt", b"x");

        let err = build_plan(&args(&["a.txt", "a.txt"]), NetworkId::Devnet, &dir.0)
            .expect_err("the same spelling twice");
        assert!(err.to_string().contains("given twice"), "{err}");

        let err = build_plan(&args(&["a.txt", "./a.txt"]), NetworkId::Devnet, &dir.0)
            .expect_err("two spellings of one path");
        assert!(
            err.to_string()
                .contains("same file after lexical normalization"),
            "{err}"
        );

        // `..` is NOT popped (module docs), so this is two identities and
        // the seal is allowed — the conservative direction.
        dir.file("sub/a.txt", b"y");
        let plan = build_plan(&args(&["a.txt", "sub/../a.txt"]), NetworkId::Devnet, &dir.0)
            .expect("`..` is kept verbatim, so these are distinct identities");
        assert_eq!(plan.files.len(), 2);
    }

    #[test]
    fn a_missing_argument_alone_is_the_ordinary_io_class() {
        let dir = Dir::new("d46-missing");
        dir.file("a.txt", b"x");
        let err = build_plan(&args(&["a.txt", "gone.txt"]), NetworkId::Devnet, &dir.0)
            .expect_err("a missing file is refused");
        assert_eq!(err.class(), crate::error::ErrorClass::IoError);
        assert!(err.to_string().contains("gone.txt"), "{err}");
    }

    #[test]
    fn a_missing_argument_beside_a_d46_violation_reports_in_the_d46_class() {
        let dir = Dir::new("d46-both");
        std::fs::create_dir_all(dir.0.join("sub")).expect("mk sub");
        let err = build_plan(&args(&["sub", "gone.txt"]), NetworkId::Devnet, &dir.0)
            .expect_err("refused");
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidSealArgument);
        let rendered = err.to_string();
        assert!(rendered.contains("sub is a directory"), "{rendered}");
        assert!(rendered.contains("gone.txt cannot be read"), "{rendered}");
    }

    #[test]
    fn every_offender_is_named_not_just_the_first() {
        let dir = Dir::new("d46-all");
        std::fs::create_dir_all(dir.0.join("one")).expect("mk one");
        std::fs::create_dir_all(dir.0.join("two")).expect("mk two");
        let err =
            build_plan(&args(&["one", "two"]), NetworkId::Devnet, &dir.0).expect_err("refused");
        let rendered = err.to_string();
        assert!(rendered.contains("one is a directory"), "{rendered}");
        assert!(rendered.contains("two is a directory"), "{rendered}");
        assert!(rendered.starts_with("invalid seal arguments"), "{rendered}");
    }

    // ── the flag guards ─────────────────────────────────────────────

    #[test]
    fn no_anchor_on_mainnet_is_refused_before_any_filesystem_access() {
        let mut a = args(&["/definitely/does/not/exist/anywhere.txt"]);
        a.no_anchor = true;
        let err = build_plan(&a, NetworkId::ArbitrumOne, Path::new("/")).expect_err("refused");
        // The argument does not exist, and we never looked: the flag
        // guard is first, so the message is about the flag.
        let rendered = err.to_string();
        assert!(
            rendered.contains("--no-anchor cannot be used on arbitrum-one"),
            "{rendered}"
        );
        assert!(!rendered.contains("anywhere.txt"), "{rendered}");
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidSealArgument);
    }

    #[test]
    fn the_cli_refusal_is_the_library_refusal_verbatim() {
        // Both layers must say the same thing, or a user who hits one
        // and searches for the other finds nothing (S13 proves the
        // library path; this is the CLI half of that gate clause).
        let mut a = args(&["x.txt"]);
        a.no_anchor = true;
        let cli = build_plan(&a, NetworkId::ArbitrumOne, Path::new("/tmp")).expect_err("refused");
        let library: CliError = SealError::NoAnchorOnMainnet.into();
        assert_eq!(cli.to_string(), library.to_string());
        assert_eq!(cli.exit_code(), library.exit_code());
    }

    /// **U22's removal, asserted from the outside.** A plain `seal` — no
    /// `--no-anchor` — now *validates*. Before U22 this same call was the
    /// one refusal every anchored seal met, and the whole anchor stage was
    /// unreachable behind it.
    ///
    /// The plan is checked field by field rather than merely `is_ok()`: a
    /// validation that silently set `no_anchor` would also make this pass,
    /// and that would be the M1 behaviour under a different name — an
    /// unanchored seal sold as an anchored one, which is exactly what the
    /// M1 error refused to do.
    #[test]
    fn a_plain_seal_now_validates_and_stays_anchored() {
        let dir = Dir::new("u22-anchored");
        dir.file("a.txt", b"x");
        let mut a = args(&["a.txt"]);
        a.no_anchor = false;
        let plan = build_plan(&a, NetworkId::Devnet, &dir.0).expect("an anchored plan validates");
        assert!(
            !plan.shaping.no_anchor,
            "validation must not sell UNANCHORED"
        );
        assert!(!plan.shaping.force_degraded);
        assert_eq!(plan.as_given_paths(), vec!["a.txt"]);
    }

    /// The rehearsal is still a faithful prefix (D49): `--dry-run` neither
    /// gains a refusal the real seal lacks nor loses one it has.
    #[test]
    fn a_dry_run_of_an_anchored_seal_validates_identically() {
        let dir = Dir::new("u22-dry");
        dir.file("a.txt", b"x");
        let mut a = args(&["a.txt"]);
        a.no_anchor = false;
        let real = build_plan(&a, NetworkId::Devnet, &dir.0).expect("real plan");
        a.dry_run = true;
        let dry = build_plan(&a, NetworkId::Devnet, &dir.0).expect("dry plan");
        assert_eq!(dry.shaping, real.shaping);
        assert_eq!(dry.files, real.files);
        assert!(dry.dry_run && !real.dry_run);
    }

    #[test]
    fn d46_validation_still_precedes_everything_it_used_to() {
        // A directory argument is a permanent argument problem and is
        // refused on argv + `stat` alone, with no `--no-anchor` in sight.
        let dir = Dir::new("order");
        std::fs::create_dir_all(dir.0.join("sub")).expect("mk sub");
        let mut a = args(&["sub"]);
        a.no_anchor = false;
        let err = build_plan(&a, NetworkId::Devnet, &dir.0).expect_err("refused");
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidSealArgument);
    }

    // ── plan contents ───────────────────────────────────────────────

    /// **`--split` is deliberately absent here — do not put it back.**
    /// This work carries `--force-text` and a `--no-fine-tree` glob that
    /// matches `blob.bin`, and `--force-text` makes every file text by
    /// argv (spec line 83), so adding `--split` makes this invocation
    /// D24 §1's refusal rather than a plan (D149 §2 R5, R7). The split
    /// half of the old combined test lives one test down, over a work
    /// with no glob to conflict with; splitting the fixture is the only
    /// way to keep both halves asserted at all.
    #[test]
    fn the_plan_records_sizes_flags_and_both_path_spellings() {
        let dir = Dir::new("plan");
        dir.file("notes.txt", b"hello world");
        dir.file("blob.bin", &[0u8; 40]);
        let mut a = args(&["notes.txt", "blob.bin"]);
        a.title = Some("thesis".to_owned());
        a.force_text = true;
        a.no_fine_tree = Some("*.bin".to_owned());

        let plan = build_plan(&a, NetworkId::Devnet, &dir.0).expect("plan builds");
        assert_eq!(plan.total_bytes(), 51);
        assert_eq!(plan.as_given_paths(), vec!["notes.txt", "blob.bin"]);
        assert_eq!(
            plan.absolute_paths(),
            vec![
                dir.0.join("notes.txt").display().to_string(),
                dir.0.join("blob.bin").display().to_string()
            ]
        );
        assert_eq!(plan.no_fine_tree_matches(), vec!["blob.bin"]);
        assert!(plan.files[0].flags.force_text());
        assert!(!plan.files[0].flags.no_fine_tree_matched());
        assert!(plan.files[1].flags.no_fine_tree_matched());
        assert_eq!(
            plan.shaping,
            SealShapingFlags {
                title: Some("thesis".to_owned()),
                split_blank_lines: false,
                force_text: true,
                no_fine_tree: vec!["*.bin".to_owned()],
                no_anchor: true,
                force_degraded: false,
            }
        );
    }

    /// The coverage R7 lifted out of the test above: `--split` reaching
    /// the D45 shaping record **and** reaching every file's `FileFlags`,
    /// over a work with no `--no-fine-tree` glob to conflict with.
    #[test]
    fn split_reaches_the_shaping_record_and_every_file_when_no_glob_conflicts() {
        let dir = Dir::new("plan-split");
        dir.file("notes.txt", b"para one\n\npara two\n");
        dir.file("more.txt", b"alpha\n\nbeta\n");
        let mut a = args(&["notes.txt", "more.txt"]);
        a.title = Some("thesis".to_owned());
        a.split = Some(SplitMode::BlankLines);

        let plan = build_plan(&a, NetworkId::Devnet, &dir.0).expect("plan builds");
        assert!(plan.shaping.split_blank_lines);
        assert!(plan.shaping.no_fine_tree.is_empty());
        for file in &plan.files {
            assert_eq!(
                file.flags.split(),
                Some(ContentSplitMode::BlankLines),
                "--split is applied to every file, not just the first: {}",
                file.as_given
            );
            assert!(!file.flags.no_fine_tree_matched());
            assert!(!file.flags.force_text());
        }
    }

    #[test]
    fn a_no_fine_tree_pattern_that_matches_nothing_is_refused() {
        let dir = Dir::new("nomatch");
        dir.file("a.txt", b"x");
        let mut a = args(&["a.txt"]);
        a.no_fine_tree = Some("*.bin".to_owned());
        let err = build_plan(&a, NetworkId::Devnet, &dir.0).expect_err("refused");
        assert_eq!(err.class(), crate::error::ErrorClass::Usage);
        assert!(err.to_string().contains("matched none"), "{err}");
    }

    // ── D24 §1: --split x --no-fine-tree (D149) ────────────────────
    //
    // Every row of D149 §2 R10's table lives here except T7, which needs a
    // spawned binary and a vault-less HOME to say anything at all and is in
    // `tests/seal_plan_conflict.rs`.

    /// A reader that remembers how much came out of it.
    ///
    /// The verdict alone cannot tell whether the probe *stopped*: a file
    /// whose first byte is `0xFF` is not text however much of it is read.
    /// Only the byte count can, which is why this exists.
    struct Counting<'a> {
        bytes: &'a [u8],
        read: usize,
    }

    impl std::io::Read for Counting<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = std::cmp::min(buf.len(), self.bytes.len() - self.read);
            buf[..n].copy_from_slice(&self.bytes[self.read..self.read + n]);
            self.read += n;
            Ok(n)
        }
    }

    /// T1. The refusal itself: the file, both flags, and both workarounds.
    #[test]
    fn split_over_a_matched_text_file_is_refused_naming_both_flags() {
        let dir = Dir::new("d24-text");
        dir.file("notes.txt", b"para one\n\npara two\n");
        let mut a = args(&["notes.txt"]);
        a.split = Some(SplitMode::BlankLines);
        a.no_fine_tree = Some("notes.txt".to_owned());

        let err = build_plan(&a, NetworkId::Devnet, &dir.0).expect_err("refused (D24 §1)");
        assert_eq!(err.class(), crate::error::ErrorClass::InvalidSealArgument);
        // 27, reused rather than minted: the sibling two-flag
        // contradiction in this same function already means exactly this
        // (D149 §2 R3).
        assert_eq!(err.exit_code(), 27);
        let rendered = err.to_string();
        // The file-name SLOT, not merely the string: the pattern half of
        // this very message is also `notes.txt`, so `contains("notes.txt")`
        // would survive the file name going missing.
        assert!(
            rendered.contains("notes.txt is selected for splitting"),
            "{rendered}"
        );
        assert!(rendered.contains("--split blank-lines"), "{rendered}");
        assert!(rendered.contains("--no-fine-tree notes.txt"), "{rendered}");
        // Mandatory, not decoration: a `tar` is text by this rule, so the
        // user's own word for the file will often disagree (D149 §1.5).
        assert!(
            rendered.contains("It counts as text by antseal's rule"),
            "{rendered}"
        );
        // D24 §1's own two workarounds, both of them.
        assert!(
            rendered.contains("Seal it as a separate work without --split"),
            "{rendered}"
        );
        assert!(rendered.contains("drop one of the two flags"), "{rendered}");
    }

    /// T2. The negative control that keeps the fix from over-reaching:
    /// `--split blank-lines --no-fine-tree '*.jpg'` is the *intended*
    /// usage — split my prose, skip the fine tree on my photographs — and
    /// D24 §1 exempts binary matches outright (G6).
    ///
    /// The fixture is `0xFF` bytes under a name that is not `.bin`, on
    /// purpose: NUL padding and ASCII headers are valid UTF-8, so a `.bin`
    /// name proves nothing about text-ness (D149 §1.5).
    #[test]
    fn a_genuinely_binary_match_under_split_is_not_an_error() {
        let dir = Dir::new("d24-binary");
        dir.file("notes.txt", b"para one\n\npara two\n");
        dir.file("opaque.dat", &[0xFFu8; 40]);
        let mut a = args(&["notes.txt", "opaque.dat"]);
        a.split = Some(SplitMode::BlankLines);
        a.no_fine_tree = Some("*.dat".to_owned());

        let plan = match build_plan(&a, NetworkId::Devnet, &dir.0) {
            Ok(plan) => plan,
            Err(e) => panic!("a binary match is not an error under --split (D24 §1, G6): {e}"),
        };
        assert_eq!(plan.no_fine_tree_matches(), vec!["opaque.dat"]);
        // Both requests survive onto the file; the model reconciles them
        // structurally (D24 layer 2), which is what `show_command.rs`'s
        // fixture asserts one layer down.
        assert_eq!(
            plan.files[1].flags.split(),
            Some(ContentSplitMode::BlankLines)
        );
        assert!(plan.files[1].flags.no_fine_tree_matched());
    }

    /// T3. `--force-text` is the exception to T2, and it is the case that
    /// passes silently in every build before this one (D149 §1.3 run M3):
    /// the flag makes the file text by argv, so the contradiction is real
    /// even though the bytes are not UTF-8.
    #[test]
    fn force_text_makes_a_binary_match_a_refusal() {
        let dir = Dir::new("d24-forced");
        dir.file("notes.txt", b"para one\n\npara two\n");
        dir.file("opaque.dat", &[0xFFu8; 40]);
        let mut a = args(&["notes.txt", "opaque.dat"]);
        a.split = Some(SplitMode::BlankLines);
        a.force_text = true;
        a.no_fine_tree = Some("*.dat".to_owned());

        let err = build_plan(&a, NetworkId::Devnet, &dir.0).expect_err("refused (D24 §1)");
        assert_eq!(err.exit_code(), 27);
        let rendered = err.to_string();
        // Not `contains("--force-text")`: the message names that flag in
        // its text-rule clause whatever the input, so that assertion could
        // not fail. The file-name slot can.
        assert!(
            rendered.contains("opaque.dat is selected for splitting"),
            "{rendered}"
        );
        assert!(rendered.contains("--no-fine-tree *.dat"), "{rendered}");
    }

    /// T4. A raw-empty file has no fine tree at any opt-out setting —
    /// `fine_tree_present = !opt_out.is_requested() && size > 0` — so the
    /// opt-out destroyed no granularity and there is nothing to refuse.
    #[test]
    fn an_empty_matched_file_is_not_an_error() {
        let dir = Dir::new("d24-empty");
        dir.file("empty.txt", b"");
        let mut a = args(&["empty.txt"]);
        a.split = Some(SplitMode::BlankLines);
        a.no_fine_tree = Some("empty.txt".to_owned());

        match build_plan(&a, NetworkId::Devnet, &dir.0) {
            Ok(plan) => assert_eq!(plan.total_bytes(), 0),
            Err(e) => panic!("an empty match destroys no granularity (D149 §2 R1): {e}"),
        }
    }

    /// T5. The sharpest row in the set. Valid UTF-8 through the whole
    /// probe, `0xFF` immediately after: the naive *"8 KiB of valid UTF-8
    /// means text"* rule calls this text and refuses the seal. A small
    /// binary fixture (T2) cannot catch that, because it never reaches the
    /// boundary at all.
    #[test]
    fn a_head_that_is_valid_utf8_does_not_decide_the_file() {
        let dir = Dir::new("d24-boundary");
        let mut bytes = vec![b'a'; TEXT_PROBE_BYTES as usize];
        bytes.push(0xFF);
        dir.file("notes.txt", b"para one\n\npara two\n");
        dir.file("edge.dat", &bytes);
        let mut a = args(&["notes.txt", "edge.dat"]);
        a.split = Some(SplitMode::BlankLines);
        a.no_fine_tree = Some("*.dat".to_owned());

        if let Err(e) = build_plan(&a, NetworkId::Devnet, &dir.0) {
            panic!(
                "a valid-UTF-8 head decides nothing; the file is binary and exempt \
                 (D149 §2 R2): {e}"
            );
        }
    }

    /// T6. The other side of R2's one-sidedness: a *decisive* invalid
    /// sequence in the head settles the whole file, so the read takes **at
    /// most one probe buffer** and never goes on to the tail. It does not
    /// truncate at the offending byte — the buffer is already in hand — and
    /// the assertion below is written as that bound rather than as an exact
    /// offset, because the bound is the property. `Ok` alone would pass with
    /// the early exit removed; the byte count is what makes this assertion
    /// able to fail.
    #[test]
    fn a_decisive_invalid_byte_in_the_head_stops_the_read() {
        let mut bytes = Vec::with_capacity((1 << 20) + 1);
        bytes.push(0xFFu8);
        bytes.resize((1 << 20) + 1, b'a');

        let mut counting = Counting {
            bytes: &bytes,
            read: 0,
        };
        let verdict = text_verdict(&mut counting).expect("an in-memory reader cannot fail");
        assert!(!verdict, "a leading 0xFF is not valid UTF-8");
        assert!(
            counting.read <= TEXT_PROBE_BYTES as usize,
            "a decisive invalid sequence in the head must bound the read to at most one \
             probe buffer ({} bytes): {} of {} bytes taken (D149 §2 R2)",
            TEXT_PROBE_BYTES,
            counting.read,
            bytes.len()
        );

        // And the same file through the production path: exempt, and the
        // plan builds.
        let dir = Dir::new("d24-earlyexit");
        dir.file("notes.txt", b"para one\n\npara two\n");
        dir.file("big.dat", &bytes);
        let mut a = args(&["notes.txt", "big.dat"]);
        a.split = Some(SplitMode::BlankLines);
        a.no_fine_tree = Some("*.dat".to_owned());
        if let Err(e) = build_plan(&a, NetworkId::Devnet, &dir.0) {
            panic!("a leading 0xFF is binary and exempt: {e}");
        }
    }

    /// T8. D46's *"every offending argument named"* applies to this
    /// refusal too: a user with two conflicting files fixes both in one
    /// re-run rather than discovering the second after fixing the first.
    #[test]
    fn every_conflicting_file_is_named_not_just_the_first() {
        let dir = Dir::new("d24-many");
        dir.file("one.txt", b"para one\n\npara two\n");
        dir.file("two.txt", b"alpha\n\nbeta\n");
        let mut a = args(&["one.txt", "two.txt"]);
        a.split = Some(SplitMode::BlankLines);
        a.no_fine_tree = Some("*.txt".to_owned());

        let err = build_plan(&a, NetworkId::Devnet, &dir.0).expect_err("refused (D24 §1)");
        let rendered = err.to_string();
        assert!(rendered.contains("one.txt is selected"), "{rendered}");
        assert!(rendered.contains("two.txt is selected"), "{rendered}");
        assert!(rendered.starts_with("invalid seal arguments"), "{rendered}");
    }

    #[test]
    fn session_flags_are_not_part_of_the_shaping_identity() {
        let dir = Dir::new("identity");
        dir.file("a.txt", b"x");
        let quiet = build_plan(&args(&["a.txt"]), NetworkId::Devnet, &dir.0).expect("plan");
        let mut noisy = args(&["a.txt"]);
        noisy.yes = true;
        noisy.dry_run = true;
        let noisy = build_plan(&noisy, NetworkId::Devnet, &dir.0).expect("plan");
        assert_eq!(
            quiet.shaping, noisy.shaping,
            "--yes/--dry-run must not split one resumable work into two identities (D45 §1)"
        );
    }

    #[test]
    fn absolutize_joins_cleans_and_keeps_parent_components() {
        let cwd = Path::new("/work/dir");
        assert_eq!(
            absolutize(cwd, Path::new("a.txt")),
            Path::new("/work/dir/a.txt")
        );
        assert_eq!(
            absolutize(cwd, Path::new("./a.txt")),
            Path::new("/work/dir/a.txt")
        );
        assert_eq!(
            absolutize(cwd, Path::new("./sub//./a.txt")),
            Path::new("/work/dir/sub/a.txt")
        );
        assert_eq!(
            absolutize(cwd, Path::new("/abs/a.txt")),
            Path::new("/abs/a.txt")
        );
        // `..` survives — the soundness rule in the module docs.
        assert_eq!(
            absolutize(cwd, Path::new("sub/../a.txt")),
            Path::new("/work/dir/sub/../a.txt")
        );
    }
}
