//! The irreversible-disclosure consent gate (U29) — the last thing that
//! happens before a `.sealproof` exists.
//!
//! # What the user is shown, and why each part is there
//!
//! `MVP-SPEC.md` line 36 fixes the contents: *"prints exactly which units
//! (file, byte-range, size, snippet) will be **irreversibly disclosed** and
//! requires confirmation (`--yes` for scripts)"*. Those four fields are the
//! row this module renders, in that order, with the file in its own header.
//! The snippet is the only one of the four that binds consent to *content*
//! rather than to coordinates (D67 §2.1): `--units 3,5` is typed from
//! memory or from an earlier `show`, and a `4`-for-`5` slip discloses the
//! **wrong unit, irreversibly**. The snippet is the last surface on which
//! that mistake is visible while it is still reversible.
//!
//! Two annotations ride beside the spec's four, and both are consequences a
//! user cannot see from the ids they typed:
//!
//! - **the D28 promotion** — selecting a file's remaining unit makes it a
//!   *full* reveal, which opens that file's whole-file commitments
//!   (`file_salt`, and `s_root` where a fine tree exists — spec line 95);
//! - **the D70 ride-along** — a fully revealed file's raw mirror is
//!   included automatically, disclosing the file's exact original bytes
//!   (BOM/CRLF/NFD and all — spec line 92).
//!
//! Neither is inferable from a `--units` list, and both are permanent, so
//! the screen states them rather than leaving them to be discovered in a
//! bundle someone else is already reading.
//!
//! # The rendering is D67's, not this module's
//!
//! Every snippet reaches a line through [`crate::preview::render_snippet`]
//! — the single implementation of D67 §3 R3/R4/R5 — and every
//! sealer-authored string (paths) through
//! [`crate::preview::escape_for_terminal`], D67 §3 R3's closed escape set.
//! That is load-bearing on *this* surface above all others: escaping the C0
//! controls and the CVE-2021-42574 bidi set is what stops a crafted file
//! repainting the very screen that is asking for irreversible-disclosure
//! consent, and escaping LF is what stops a path or a snippet forging an
//! extra unit row beneath itself.
//!
//! # This is not a verdict surface
//!
//! The copy here states what *will be disclosed*; it never states what has
//! been *proven*. Verdict wording is [`antseal_core::verify::wording`]'s
//! (R18), the redaction view's is R19's, and neither is borrowed or
//! paraphrased here — a consent screen that spoke in verdict sentences
//! would be claiming, at the moment of disclosure, something only a
//! verifier can say. Possession language throughout (spec line 28): never
//! "notary", never unqualified "priority", no legal claim of any kind.
//!
//! # Machine mode is an input (D51, inherited unchanged)
//!
//! The gate never probes TTY-ness. `machine_mode` arrives from
//! [`crate::machine::machine_mode_for`], the single detection point, and
//! `reveal`'s consent prompt is registered in the D51 prompt-class registry
//! with `--yes` as its declared channel ([`crate::machine::spec`]). The
//! matrix is `seal`'s, unchanged: `--json` ∨ non-TTY stdin ∨ stdin consumed
//! by `--passphrase-fd 0` never prompts; `--yes` consents in advance;
//! **declined ≡ unobtainable** — one [`CliError::ConsentNotObtained`] class
//! for a human "no" and for a machine-mode absence of `--yes`, because
//! scripts branch on *did not consent*, not on why.
//!
//! And D51 invariant 1 rides here too: **the preview always renders**.
//! `--yes` skips the question, never the screen — on stdout in plain mode
//! and on stderr under `--json`, so an automated disclosure leaves the same
//! audit trail an interactive one does.
//!
//! # Where this sits in the order
//!
//! [`crate::reveal_out::run_reveal`] resolves the output path and refuses a
//! collision **before** this gate is ever asked (D68 §3 R8), and R16's
//! two-phase `prepare → build` split means nothing bundle-shaped exists
//! while the user is deciding. A declining gate returns its error and the
//! [`PreparedReveal`] is dropped: no file is created, no whole-file
//! commitment is opened, nothing leaves the machine.
//!
//! # Secret hygiene (project rule 6)
//!
//! Nothing here holds `W`, a unit key or a salt. It renders ids, counts,
//! offsets, paths and the ≤64-byte snippet windows of the units the user is
//! about to disclose deliberately — the plaintext R15's Accept explicitly
//! carves out — and nothing else.

use std::cell::RefCell;
use std::collections::BTreeSet;

use crate::error::{CliError, ConsentOutcome};
use crate::pipeline::reveal::PreparedReveal;
use crate::preview::{
    DisclosurePreview, FilePreview, PreviewRow, escape_for_terminal, render_snippet,
};
use crate::seal_consent::{ConsentPrompt, ask_on_tty};

/// Indent of a file row (the house's two spaces, as in
/// [`crate::redaction_out`] and `status::WorkStatus::render`).
const FILE_INDENT: &str = "  ";

/// Indent of a unit row beneath its file.
const UNIT_INDENT: &str = "      ";

/// Indent of a per-file note: deeper than the file header, shallower than
/// a unit row, because these notes are consequences of the **file's**
/// classification rather than facts about any one unit.
const NOTE_INDENT: &str = "    ";

/// The headline, carrying MVP-SPEC.md line 36's own words.
///
/// One author for one sentence: the renderer interpolates this constant and
/// the tests assert against it *and* against the literal phrase
/// **"irreversibly disclosed"**, so a well-meant rewording fails rather
/// than quietly softening the only sentence that says the disclosure cannot
/// be taken back.
pub const DISCLOSURE_HEADLINE: &str =
    "These units will be irreversibly disclosed to everyone who is ever shown this bundle:";

/// The closing sentence: what "irreversible" means in practice.
///
/// Deliberately about *distribution*, not about proof — a bundle is a file,
/// and a file that has left this machine cannot be recalled from the people
/// who copied it.
pub const DISCLOSURE_FINALITY_NOTE: &str = "Once this bundle leaves your machine you cannot unsend it, restrict who reads it, or \
     narrow what it discloses. There is no revocation.";

/// The `--include-receipt` warning (spec line 110; Risks, line 185).
///
/// Rendered **only** when the receipt actually rides in the bundle, which
/// [`crate::pipeline::reveal::RevealSummary::receipt_included`] settles at
/// prepare time — so the screen cannot warn about an exposure that is not
/// happening, nor stay silent about one that is.
pub const RECEIPT_EXPOSURE_WARNING: &str = "WARNING: --include-receipt puts the Arbitrum payment receipt in this bundle. It names the \
     wallet that paid for this seal, and it links this work to every other seal that wallet \
     ever paid for — to everyone who is shown the bundle, permanently. Leave it out unless a \
     recipient specifically needs it.";

/// The question, asked only when a terminal is there to answer it.
///
/// Ends in `[y/N] ` because the default on an irreversible step is never
/// yes: EOF, an empty line and anything unrecognised all mean no
/// ([`ask_on_tty`]'s contract).
pub const DISCLOSURE_QUESTION: &str = "Proceed with this irreversible disclosure? [y/N] ";

/// The real prompt: `/dev/tty`, never stdin and never stdout.
///
/// The **device** handling is [`ask_on_tty`]'s, shared with U14's
/// permanence gate: one implementation of "open the terminal, ask, and
/// treat EOF, a blank line and anything unrecognised as **no**", so the two
/// consent-class prompts in the product cannot drift on the one rule that
/// matters. Only the question is this module's.
///
/// Reached only when [`crate::machine::machine_mode_for`] has already said
/// *interactive*: D51 forbids `/dev/tty` as a **detection** mechanism, and
/// using it as the read/write device once stdin-isatty has spoken is the
/// discipline U7's passphrase prompt and U14's gate both follow.
pub struct TtyDisclosurePrompt;

impl ConsentPrompt for TtyDisclosurePrompt {
    fn ask(&mut self) -> Result<bool, CliError> {
        ask_on_tty(DISCLOSURE_QUESTION)
    }
}

/// Everything the irreversible-disclosure screen shows, as values.
///
/// Borrows the preview rather than cloning it: the rows carry the snippet
/// windows of about-to-be-disclosed plaintext, and one copy of those is
/// enough.
#[derive(Debug, Clone, Copy)]
pub struct DisclosureReport<'a> {
    /// R15's preview, exactly as R16 computed it from the resolved
    /// selection — so what the user reads is what the builder will build.
    pub preview: &'a DisclosurePreview,
    /// Whether the Arbitrum receipt will ride (settled at prepare time).
    pub receipt_included: bool,
}

impl<'a> DisclosureReport<'a> {
    /// The report for a prepared reveal.
    #[must_use]
    pub fn of(prepared: &'a PreparedReveal) -> Self {
        Self {
            preview: prepared.preview(),
            receipt_included: prepared.summary().receipt_included,
        }
    }

    /// The human screen, as lines. Rendered identically in every mode —
    /// only the *stream* changes (stdout in plain mode, stderr under
    /// `--json`, per D51 invariant 1).
    ///
    /// The **file list** drives the loop, not the row list: a touched file
    /// whose rows are all missing still gets a header, so a disclosure
    /// cannot lose a file from its own screen silently. Rows carry
    /// `file_id`, so this holds whatever order they arrive in.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let mut out = vec![DISCLOSURE_HEADLINE.to_owned()];

        for file in &self.preview.files {
            out.push(format!("{FILE_INDENT}{}", file_line(file)));
            for row in self
                .preview
                .rows
                .iter()
                .filter(|row| row.file_id == file.file_id)
            {
                out.push(format!("{UNIT_INDENT}{}", unit_line(row)));
            }
            if file.fully_revealed {
                out.push(format!("{NOTE_INDENT}{FULL_REVEAL_NOTE}"));
            }
            if file.mirror_rides_along {
                out.push(format!("{NOTE_INDENT}{MIRROR_RIDES_ALONG_NOTE}"));
            }
        }

        // Totality over the rows, not just over the files. R15 lists every
        // touched file, so a row whose `file_id` names none of them is
        // unreachable for a preview it computed — and a consent screen that
        // can silently drop a unit it is about to disclose is not one to
        // ship on the strength of that. `show`'s renderer states the
        // mirror-image rule (a file with no rows still gets a header);
        // this is the other direction.
        let listed: BTreeSet<u64> = self.preview.files.iter().map(|f| f.file_id).collect();
        let mut orphans = self
            .preview
            .rows
            .iter()
            .filter(|row| !listed.contains(&row.file_id))
            .peekable();
        if orphans.peek().is_some() {
            out.push(format!("{FILE_INDENT}{UNNAMED_FILE_HEADER}"));
            for row in orphans {
                out.push(format!("{UNIT_INDENT}{}", unit_line(row)));
            }
        }

        out.push(format!("{FILE_INDENT}{}", self.totals_line()));
        out.push(format!("{FILE_INDENT}{DISCLOSURE_FINALITY_NOTE}"));
        if self.receipt_included {
            out.push(format!("{FILE_INDENT}{RECEIPT_EXPOSURE_WARNING}"));
        }
        out
    }

    /// The summary line: R15's own totals, restated and never recomputed —
    /// a screen that counted its own rows could disagree with the builder
    /// about what is being disclosed, which is the one disagreement this
    /// surface must not have.
    fn totals_line(&self) -> String {
        let totals = &self.preview.totals;
        format!(
            "Disclosing {} unit(s), {} byte(s), across {} file(s); {} of those file(s) \
             revealed whole.",
            totals.units, totals.bytes, totals.files_touched, totals.files_fully_revealed,
        )
    }
}

/// What a full reveal opens beyond its own bytes (spec line 95; D28).
const FULL_REVEAL_NOTE: &str = "this also discloses the file's whole-file commitments (its file salt, and its byte-range \
     tree seed where one exists), which a partial reveal withholds";

/// The header for rows whose file the preview did not name — the
/// totality arm, unreachable for a preview R15 computed.
const UNNAMED_FILE_HEADER: &str = "also disclosed, from a file this preview could not name:";

/// Why a mirror row is present at all (spec line 92; D70).
const MIRROR_RIDES_ALONG_NOTE: &str = "its raw mirror is included with it: the file's exact original bytes, byte-order marks, \
     line endings and all";

/// One file's header line.
///
/// The path goes through D67 §3 R3's **closed** escape set rather than
/// through `{:?}`: `escape_debug` tracks Unicode data across toolchains,
/// which is the exact rot D67 refused for a snapshot-frozen rendering.
/// Escaping LF is the load-bearing half — it makes the header exactly one
/// line, so a path carrying `"\n      unit 9   normal …"` cannot forge a
/// unit row beneath it. The quotes are the delimiter, and with `\"` in the
/// set nothing inside can close them early.
fn file_line(file: &FilePreview) -> String {
    format!(
        "file #{} \"{}\" — {}",
        file.file_id,
        escape_for_terminal(&file.path),
        if file.fully_revealed {
            "revealed whole"
        } else {
            "partly revealed"
        }
    )
}

/// One unit's row: the spec's `byte-range, size, snippet` (line 36), with
/// the id and the kind that name it.
///
/// **Deliberately `show`'s columns, minus one.** `show`'s unit row is
/// `unit N   kind   S byte(s) at offset O of TOTAL   snippet`, and a user
/// picks `--units` off exactly that screen, so this one keeps its shape and
/// its order — `size` + `offset` *is* the byte-range, in the unit's
/// committed domain (canonical-byte offsets for a text file's normal units,
/// raw-byte offsets for binary files and raw mirrors — spec line 83).
///
/// The domain **total** is absent because R15's preview does not carry a
/// per-file size and this renderer computes nothing of its own. That is not
/// a gap in spec line 121's *"every reveal displays position + total
/// size"*: D67 §1 (b) rules that line governs what a **verifier** shows a
/// third party about what surrounds a disclosure, while this screen's job
/// is the inverse — confirming to the **sealer** what is inside the
/// selection before it becomes permanent. R19's redaction view is line
/// 121's surface and prints the total on every block.
fn unit_line(row: &PreviewRow) -> String {
    format!(
        "unit {}   {}   {} byte(s) at offset {}   {}",
        row.unit_id,
        row.kind.registry_value_name(),
        row.size,
        row.range.start(),
        render_snippet(row.snippet.as_ref()),
    )
}

/// The invocation-scoped disclosure gate: the seam
/// [`crate::reveal_out::run_reveal`] takes.
pub struct DisclosureConsent<'a, P: ConsentPrompt> {
    /// `--yes`: consent given in advance.
    yes: bool,
    /// D51 machine mode, from the single detection point.
    machine_mode: bool,
    /// Where human copy goes: `true` = stderr (under `--json`).
    to_stderr: bool,
    prompt: RefCell<&'a mut P>,
    /// Every screen this gate rendered — what a test reads to assert the
    /// preview was shown even when nothing was asked (D51 invariant 1).
    rendered: RefCell<Vec<Vec<String>>>,
}

impl<'a, P: ConsentPrompt> DisclosureConsent<'a, P> {
    /// Assemble the gate from the invocation's own context.
    #[must_use]
    pub fn new(yes: bool, machine_mode: bool, to_stderr: bool, prompt: &'a mut P) -> Self {
        Self {
            yes,
            machine_mode,
            to_stderr,
            prompt: RefCell::new(prompt),
            rendered: RefCell::new(Vec::new()),
        }
    }

    /// Which stream this gate's copy goes to — `true` = stderr, which is
    /// what `--json` selects so stdout can carry exactly one envelope
    /// (D51 invariant 1/2).
    #[must_use]
    pub const fn to_stderr(&self) -> bool {
        self.to_stderr
    }

    /// Every screen rendered so far, in order.
    #[must_use]
    pub fn rendered(&self) -> Vec<Vec<String>> {
        self.rendered.borrow().clone()
    }

    /// Render the screen for a prepared reveal, then obtain consent under
    /// the D51 matrix — the seam
    /// [`crate::reveal_out::run_reveal`] is handed.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::decide`] returns.
    pub fn confirm(&self, prepared: &PreparedReveal) -> Result<(), CliError> {
        self.decide(&DisclosureReport::of(prepared))
    }

    /// The gate over an already-assembled screen.
    ///
    /// Split from [`Self::confirm`] because a [`PreparedReveal`] can only
    /// come from R16's engine over a real vault: this is the arm the
    /// rendering and matrix rows drive directly, and `confirm` is the
    /// two-line adapter above it.
    ///
    /// # Errors
    ///
    /// [`CliError::ConsentNotObtained`] — `Declined` for an interactive
    /// "no", `MachineModeWithoutYes` for machine mode with no `--yes`. One
    /// class, two messages (D51 invariant 3). A channel failure while
    /// asking is the prompt's own [`CliError`].
    pub fn decide(&self, report: &DisclosureReport<'_>) -> Result<(), CliError> {
        let lines = report.render();
        self.emit(&lines);
        self.rendered.borrow_mut().push(lines);

        // `--yes` first: it is the declared channel, and D51's matrix has
        // it win in every row it appears in, TTY or not.
        if self.yes {
            return Ok(());
        }
        if self.machine_mode {
            return Err(CliError::ConsentNotObtained {
                reason: ConsentOutcome::MachineModeWithoutYes,
            });
        }
        if self.prompt.borrow_mut().ask()? {
            Ok(())
        } else {
            Err(CliError::ConsentNotObtained {
                reason: ConsentOutcome::Declined,
            })
        }
    }

    /// This gate as the closure [`crate::reveal_out::run_reveal`] takes.
    pub fn gate(&self) -> impl FnOnce(&PreparedReveal) -> Result<(), CliError> + '_ {
        move |prepared| self.confirm(prepared)
    }

    fn emit(&self, lines: &[String]) {
        for line in lines {
            if self.to_stderr {
                eprintln!("{line}");
            } else {
                println!("{line}");
            }
        }
    }
}

#[cfg(test)]
#[path = "reveal_consent/tests.rs"]
mod tests;
