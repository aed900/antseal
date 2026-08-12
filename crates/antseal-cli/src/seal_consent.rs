//! The permanence-consent gate (U14) — the last thing that happens before
//! money can move.
//!
//! # What the user is shown, and why each part is there
//!
//! MVP-SPEC.md line 34 fixes the contents: the **file list**, **byte
//! totals**, the ***true, complete* quote** (every blob, the encrypted
//! manifest included), the **ANT and ETH balances displayed beside it**,
//! and the warning [`PERMANENCE_WARNING`] — then an interactive confirm,
//! with `--yes` for scripts.
//!
//! "True and complete" is not a promise this module makes; it is one it
//! *receives*. The quote handed to [`SealConsent::confirm`] is the object
//! the pipeline just fetched over the full blob set and the exact object
//! `pay()` will receive (D36's pay-argument identity rule), and S8's
//! completeness contract is what makes it complete. This module's job is
//! to show it without editorialising and to refuse to guess.
//!
//! # The gate takes data, never a backend (D89 Decision 3)
//!
//! [`SealConsent`] holds a [`BalanceReport`] read once by the handler
//! before the pipeline starts, so rendering is a pure function of values
//! and its snapshot costs nothing. The shortfall rule is
//! [`antseal_net::preflight`] — **called**, never restated: putting a
//! second implementation of "which shortfall fires first" behind the
//! consent screen is exactly how a user ends up being told they need ETH
//! when they need ANT.
//!
//! # `ConsentRequest` is untouched (a deliberate non-change)
//!
//! U14's ground survey predicted this gate would have to extend lane ι's
//! [`ConsentRequest`](crate::pipeline::ConsentRequest) with the file list,
//! byte totals and balances. It does not, and the reason is worth
//! recording: those three are **per-invocation** facts, while
//! `ConsentRequest` carries the **per-call** ones (the fresh quote, the
//! blob count, the prior record, whether this is a resume, whether the
//! proofs expired). A `ConsentHook` implementation is free to hold its own
//! invocation context — that is what the trait seam is *for* — so the
//! whole feature lands with zero edits inside `pipeline/`, the pipeline
//! stays balance-unaware, and lane ι's contract is preserved byte for
//! byte.
//!
//! # Machine mode is an input (D51)
//!
//! The gate never probes TTY-ness. `machine_mode` arrives from
//! [`crate::machine::machine_mode_for`], the single detection point, and
//! in machine mode without `--yes` the answer is
//! [`ConsentOutcome::MachineModeWithoutYes`] — the same class as a human
//! saying no, because "declined" and "unobtainable" are one outcome:
//! consent was not obtained and nothing was paid.

use std::io::Write as _;

use antseal_net::{BalanceReport, CostQuote, PreflightReport, preflight};

use crate::error::{CliError, ConsentOutcome};
use crate::pipeline::{ConsentDecision, ConsentHook, ConsentRequest};
use crate::seal_plan::SealPlan;
use crate::vault::store::{ConsentChannel, ConsentRecord};

/// The spec-normative permanence warning, verbatim from MVP-SPEC.md line
/// 34.
///
/// One author for one sentence: the renderer interpolates this constant
/// and the tests assert against it *and* against its literal text, so a
/// well-meant rewording fails rather than quietly softening the only
/// sentence that stands between a user and a permanent public upload.
pub const PERMANENCE_WARNING: &str = "upload is permanent, public, and irreversible";

/// Everything the consent screen shows, as values.
#[derive(Debug, Clone)]
pub struct ConsentReport {
    /// `(path as given, size in bytes)` in argument order.
    pub files: Vec<(String, u64)>,
    /// Sum of the input sizes.
    pub total_input_bytes: u64,
    /// The fresh, complete quote.
    pub quote: CostQuote,
    /// Blobs the quote covers (units + raw mirrors + encrypted manifest).
    pub blob_count: usize,
    /// Both balances, read once this invocation.
    pub balances: BalanceReport,
    /// The prior journaled consent (D36 rule 4) — display only.
    pub prior: Option<ConsentRecord>,
    /// The resume plan lines, when this invocation resumes a work: D45's
    /// **one merged render**, never two prompts.
    pub resume_plan: Vec<String>,
    /// U15's seal-time warnings (title visibility, `--no-fine-tree`
    /// permanence, fine-tree cost), from
    /// [`crate::seal_warnings::warnings_for`]. Carried here rather than
    /// printed by a second emitter so the rehearsal screen, the real
    /// screen and the `--json` document cannot disagree about them.
    pub warnings: Vec<String>,
    /// D37: the previous payment is stranded and granting authorizes an
    /// additional spend.
    pub proofs_expired: bool,
    /// `--dry-run`: the figure is indicative (D49) and nothing will be
    /// asked or paid.
    pub dry_run: bool,
}

impl ConsentReport {
    /// The shortfall check, over this report's own quote and balances.
    ///
    /// # Errors
    ///
    /// [`CliError::InsufficientAntToken`] / [`CliError::InsufficientEthGas`]
    /// — distinct all the way to the exit code, because the user remedies
    /// them differently (acquire ANT vs bridge ETH).
    pub fn preflight(&self) -> Result<PreflightReport, CliError> {
        preflight(&self.balances, &self.quote)
            .map_err(|e| crate::pipeline::SealError::Storage(e).into())
    }

    /// The human report, as lines. Rendered identically in every mode —
    /// only the *stream* changes (stdout in plain mode, stderr under
    /// `--json`, per D51 invariant 2).
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let mut out = Vec::new();
        out.extend(self.resume_plan.iter().cloned());

        out.push(format!(
            "Sealing {} file(s), {} byte(s):",
            self.files.len(),
            self.total_input_bytes
        ));
        for (path, size) in &self.files {
            out.push(format!("    {path}  ({size} bytes)"));
        }

        // U15's three warning moments, above the quote (MVP-SPEC.md line
        // 85 asks for the fine-tree estimate "before the quote", and the
        // other two are permanent consequences a user must weigh before
        // reading a price). One render, one author — see
        // `crate::seal_warnings`.
        out.extend(self.warnings.iter().cloned());

        let indicative = if self.dry_run { " (indicative)" } else { "" };
        out.push(format!(
            "  Upload:      {} blob(s) — every encrypted unit plus the encrypted manifest",
            self.blob_count
        ));
        out.push(format!(
            "  Cost{indicative}: {} atto-ANT storage, plus about {} wei of gas",
            self.quote.total_ant_atto, self.quote.gas_estimate_wei
        ));
        out.push(format!("  Wallet:      {}", self.balances.wallet));
        out.push(format!(
            "               {} atto-ANT{}",
            self.balances.ant_atto,
            shortfall(self.balances.ant_atto, self.quote.total_ant_atto)
        ));
        out.push(format!(
            "               {} wei{}",
            self.balances.gas_wei,
            shortfall(self.balances.gas_wei, self.quote.gas_estimate_wei)
        ));

        // D36 rule 4: the prior consented totals, with a visible drift
        // flag when they differ — in EITHER direction, and display only.
        // A cheaper quote is as much a surprise as a dearer one, and
        // neither is ever a reason to skip the gate.
        if let Some(prior) = &self.prior {
            out.push(format!(
                "  Previously consented ({}): {} atto-ANT{}",
                utc(prior.consent_time_unix_secs),
                prior.total_ant_atto,
                drift(prior.total_ant_atto, self.quote.total_ant_atto)
            ));
        }

        if self.proofs_expired {
            out.push(
                "  WARNING: this seal was already paid for, but its payment proofs have \
                 expired and the network will no longer accept them. That payment is \
                 stranded and cannot be recovered. Consenting here authorizes a SECOND, \
                 ADDITIONAL payment."
                    .to_owned(),
            );
        }

        out.push(format!("  WARNING: {PERMANENCE_WARNING}."));
        out.push(
            "  Anyone who later holds this vault or its passphrase can decrypt these \
             ciphertexts, and nothing on the network can be deleted or rotated."
                .to_owned(),
        );
        out
    }

    /// The machine document for the `--json` fixtures (U16's dry-run
    /// result embeds it; a real seal reports its outcome instead).
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "files": self.files.iter().map(|(path, size)| serde_json::json!({
                "path": path,
                "bytes": size,
            })).collect::<Vec<_>>(),
            "total_input_bytes": self.total_input_bytes,
            "blob_count": self.blob_count,
            // Decimal strings: atto-ANT is 18 decimals and real values
            // exceed the 2^53 most JSON consumers survive (U19's call).
            "storage_cost_atto": self.quote.total_ant_atto.to_string(),
            "gas_estimate_wei": self.quote.gas_estimate_wei.to_string(),
            "indicative": self.dry_run,
            "wallet": self.balances.wallet.to_string(),
            "balance_ant_atto": self.balances.ant_atto.to_string(),
            "balance_gas_wei": self.balances.gas_wei.to_string(),
            "prior_consent": self.prior.map(|p| serde_json::json!({
                "total_ant_atto": p.total_ant_atto.to_string(),
                "gas_estimate_wei": p.gas_estimate_wei.to_string(),
                "consent_time": p.consent_time_unix_secs,
                "changed": p.total_ant_atto != self.quote.total_ant_atto,
            })),
            "resume": !self.resume_plan.is_empty(),
            "proofs_expired": self.proofs_expired,
            "permanence_warning": PERMANENCE_WARNING,
            // U15's warnings as data: a script that gates on "did this
            // seal disclose a title / lose reveal granularity?" reads
            // this array rather than grepping the human copy.
            "warnings": self.warnings,
        })
    }
}

/// Unix seconds as `YYYY-MM-DD HH:MM:SS UTC` — the house calendar
/// (`commands::civil_utc`), so the consent screen, `list` and export
/// filenames all read from one implementation.
fn utc(unix_secs: u64) -> String {
    let (y, mo, d, h, mi, s) = crate::commands::civil_utc(unix_secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

fn shortfall(available: u128, required: u128) -> String {
    if available >= required {
        String::new()
    } else {
        format!("  ** SHORT by {} **", required - available)
    }
}

fn drift(prior: u128, now: u128) -> String {
    match now.cmp(&prior) {
        std::cmp::Ordering::Equal => String::new(),
        std::cmp::Ordering::Greater => format!("  [CHANGED: +{}]", now - prior),
        std::cmp::Ordering::Less => format!("  [CHANGED: -{}]", prior - now),
    }
}

/// How the answer is obtained once the report has been shown. Injected so
/// the whole gate is drivable without a terminal.
pub trait ConsentPrompt {
    /// Ask, and return whether the user affirmed.
    ///
    /// # Errors
    ///
    /// [`CliError`] when the *channel* fails (a terminal read error) —
    /// never for a plain "no", which is `Ok(false)`.
    fn ask(&mut self) -> Result<bool, CliError>;
}

/// The permanence gate's question (U14), asked verbatim.
pub const PERMANENCE_QUESTION: &str = "Proceed with this permanent upload? [y/N] ";

/// Ask one yes/no consent question on `/dev/tty` — never stdin, never
/// stdout.
///
/// **One implementation, every consent-class prompt (U29).** The device
/// handling and the answer rule are the same wherever the product asks for
/// consent, and the answer rule is the part that must never drift:
/// affirmative is opt-in and explicit, so EOF, an empty line and anything
/// unrecognised all mean **no**. The default on an irreversible step is
/// never yes. Only the question differs — U14 asks
/// [`PERMANENCE_QUESTION`], U29's disclosure gate asks
/// [`DISCLOSURE_QUESTION`] — so the question is the parameter and the
/// mechanism is not.
///
/// Reached only when [`crate::machine::machine_mode_for`] has already said
/// *interactive*: D51 forbids `/dev/tty` as a **detection** mechanism, and
/// using it as the read/write device once stdin-isatty has spoken is the
/// discipline U7's passphrase prompt follows too.
///
/// # Errors
///
/// [`CliError::Io`] when the *channel* fails — never for a plain "no",
/// which is `Ok(false)`.
///
/// [`DISCLOSURE_QUESTION`]: crate::reveal_consent::DISCLOSURE_QUESTION
pub fn ask_on_tty(question: &str) -> Result<bool, CliError> {
    use std::io::BufRead as _;

    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|source| CliError::Io {
            context: "opening /dev/tty to ask for consent".to_owned(),
            source,
        })?;
    write!(tty, "{question}").map_err(|source| CliError::Io {
        context: "writing the consent prompt".to_owned(),
        source,
    })?;
    tty.flush().map_err(|source| CliError::Io {
        context: "writing the consent prompt".to_owned(),
        source,
    })?;

    let mut answer = String::new();
    std::io::BufReader::new(tty)
        .read_line(&mut answer)
        .map_err(|source| CliError::Io {
            context: "reading the consent answer".to_owned(),
            source,
        })?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
}

/// The permanence gate's real prompt: [`ask_on_tty`] with U14's question.
pub struct TtyConsentPrompt;

impl ConsentPrompt for TtyConsentPrompt {
    fn ask(&mut self) -> Result<bool, CliError> {
        ask_on_tty(PERMANENCE_QUESTION)
    }
}

/// The invocation-scoped consent gate: U14's [`ConsentHook`].
pub struct SealConsent<'a, P: ConsentPrompt> {
    files: Vec<(String, u64)>,
    total_input_bytes: u64,
    balances: BalanceReport,
    resume_plan: Vec<String>,
    /// U15's warnings for this invocation, computed once from the plan.
    warnings: Vec<String>,
    yes: bool,
    machine_mode: bool,
    /// Where human copy goes: `true` = stderr (under `--json`).
    to_stderr: bool,
    /// Injected, so the journaled consent time is deterministic under
    /// test (the same discipline `SealRequest::claimed_time_unix_secs`
    /// follows — one findable place a clock is trusted).
    now_unix_secs: u64,
    prompt: std::cell::RefCell<&'a mut P>,
    /// Every report this gate rendered — the merged-render assertion
    /// ("one gate pass, not two prompts") reads this.
    pub rendered: std::cell::RefCell<Vec<ConsentReport>>,
}

impl<'a, P: ConsentPrompt> SealConsent<'a, P> {
    /// Assemble the gate from the invocation's own context.
    ///
    /// The whole [`SealPlan`] is taken rather than just its file list so
    /// that the displayed files and U15's warnings have **one** source: a
    /// gate handed a file list and a separately-computed warning set could
    /// be given two that disagree, and the warning that goes missing that
    /// way is the one about a permanent consequence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan: &SealPlan,
        balances: BalanceReport,
        resume_plan: Vec<String>,
        yes: bool,
        machine_mode: bool,
        to_stderr: bool,
        now_unix_secs: u64,
        prompt: &'a mut P,
    ) -> Self {
        Self {
            files: plan
                .files
                .iter()
                .map(|f| (f.as_given.clone(), f.size))
                .collect(),
            total_input_bytes: plan.total_bytes(),
            balances,
            resume_plan,
            warnings: crate::seal_warnings::warnings_for(plan),
            yes,
            machine_mode,
            to_stderr,
            now_unix_secs,
            prompt: std::cell::RefCell::new(prompt),
            rendered: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// The report this gate would show for a given request — the same
    /// object [`ConsentHook::confirm`] renders, exposed so `--dry-run`
    /// (U16) prints the identical screen without a consent pass.
    #[must_use]
    pub fn report_for(&self, request: &ConsentRequest<'_>) -> ConsentReport {
        ConsentReport {
            files: self.files.clone(),
            total_input_bytes: self.total_input_bytes,
            quote: request.quote.clone(),
            blob_count: request.blob_count,
            balances: self.balances,
            prior: request.prior,
            // The plan renders whenever this **invocation** is a resume —
            // which this gate knows, because D45 detection is what built
            // `resume_plan` — and deliberately NOT off
            // `ConsentRequest::resume`.
            //
            // That field is `proofs_expired || anchor.is_none()`, so it
            // is **false** for the commonest resume of all: a work killed
            // before the anchor gate still has anchoring to do, so
            // `anchor` is `Some` and the flag reads as a fresh seal.
            // Gating on it would have suppressed the resume plan in
            // exactly the case a user is most likely to meet, and D45's
            // "one merged render" would have quietly become no render.
            // A non-empty plan means D45 matched; nothing else can make
            // it non-empty.
            resume_plan: self.resume_plan.clone(),
            warnings: self.warnings.clone(),
            proofs_expired: request.proofs_expired,
            dry_run: false,
        }
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

impl<P: ConsentPrompt> ConsentHook for SealConsent<'_, P> {
    fn confirm(&self, request: &ConsentRequest<'_>) -> Result<ConsentDecision, CliError> {
        let report = self.report_for(request);
        // Shown before anything can refuse, including the shortfall: the
        // typed error carries required-vs-available for scripts, and the
        // report is what explains it to a person — the file list and the
        // complete quote in one place. Both audiences, one render.
        self.emit(&report.render());
        self.rendered.borrow_mut().push(report.clone());

        report.preflight()?;

        // D51: machine mode never prompts. `--yes` is the declared
        // channel; without it the answer is "not obtained", which is the
        // same outcome class as a human saying no.
        if self.yes {
            return Ok(ConsentDecision::Granted {
                channel: ConsentChannel::YesFlag,
                at_unix_secs: self.now_unix_secs,
            });
        }
        if self.machine_mode {
            return Ok(ConsentDecision::Declined(
                ConsentOutcome::MachineModeWithoutYes,
            ));
        }
        if self.prompt.borrow_mut().ask()? {
            Ok(ConsentDecision::Granted {
                channel: ConsentChannel::Interactive,
                at_unix_secs: self.now_unix_secs,
            })
        } else {
            Ok(ConsentDecision::Declined(ConsentOutcome::Declined))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antseal_core::crypto::secrets::SealId;
    use antseal_net::network::EvmAddress20;

    /// NON-SECRET fixture wallet address (project rule 6): a repeated
    /// byte pattern, obviously not a real account.
    const FIXTURE_WALLET: [u8; 20] = [0x5A; 20];

    struct Scripted(Vec<bool>);
    impl ConsentPrompt for Scripted {
        fn ask(&mut self) -> Result<bool, CliError> {
            Ok(self.0.pop().unwrap_or(false))
        }
    }
    struct NeverAsked;
    impl ConsentPrompt for NeverAsked {
        fn ask(&mut self) -> Result<bool, CliError> {
            panic!("the gate prompted in a mode that must never prompt (D51)");
        }
    }

    /// Two small, untitled, fine-tree-bearing files: the plan that earns
    /// **no** U15 warnings, so these snapshots keep asserting exactly the
    /// U14 contents they were written for.
    fn plan() -> SealPlan {
        use crate::seal_plan::PlannedFile;
        use crate::vault::store::SealShapingFlags;

        SealPlan {
            files: vec![
                PlannedFile {
                    as_given: "notes.txt".to_owned(),
                    absolute: "/w/notes.txt".to_owned(),
                    size: 11,
                    flags: antseal_core::content::FileFlags::new(),
                },
                PlannedFile {
                    as_given: "blob.bin".to_owned(),
                    absolute: "/w/blob.bin".to_owned(),
                    size: 40,
                    flags: antseal_core::content::FileFlags::new(),
                },
            ],
            shaping: SealShapingFlags {
                no_anchor: true,
                ..SealShapingFlags::default()
            },
            network: antseal_net::NetworkId::Devnet,
            dry_run: false,
            yes: false,
        }
    }

    fn quote(ant: u128, gas: u128) -> CostQuote {
        CostQuote {
            blobs: Vec::new(),
            total_ant_atto: ant,
            gas_estimate_wei: gas,
        }
    }

    fn balances(ant: u128, gas: u128) -> BalanceReport {
        BalanceReport {
            wallet: EvmAddress20::from_bytes(FIXTURE_WALLET),
            ant_atto: ant,
            gas_wei: gas,
        }
    }

    fn request<'a>(quote: &'a CostQuote, prior: Option<ConsentRecord>) -> ConsentRequest<'a> {
        ConsentRequest {
            seal_id: SealId::from_bytes([0xC1; 16]),
            quote,
            blob_count: 3,
            prior,
            resume: prior.is_some(),
            proofs_expired: false,
        }
    }

    /// U15: the three warnings reach the pre-consent screen **through the
    /// gate**, and they render above the price.
    ///
    /// The gate computes them from the plan in its constructor, so there
    /// is no way to build a `SealConsent` for a titled or opted-out seal
    /// that fails to carry them — which is the property, not the fact that
    /// one particular call site remembered.
    #[test]
    fn the_gate_carries_u15s_warnings_and_renders_them_above_the_quote() {
        use crate::seal_plan::PlannedFile;
        use crate::seal_warnings::{FINE_TREE_ESTIMATE_THRESHOLD_BYTES, warnings_for};
        use antseal_core::content::FileFlags;

        let mut plan = plan();
        plan.shaping.title = Some("Q3 layoffs".to_owned());
        plan.shaping.no_fine_tree = vec!["*.bin".to_owned()];
        plan.files[1].flags = FileFlags::new().with_no_fine_tree();
        plan.files.push(PlannedFile {
            as_given: "scan.tiff".to_owned(),
            absolute: "/w/scan.tiff".to_owned(),
            size: FINE_TREE_ESTIMATE_THRESHOLD_BYTES,
            flags: FileFlags::new(),
        });

        let q = quote(4_200, 21_000);
        let mut p = NeverAsked;
        let gate = SealConsent::new(
            &plan,
            balances(9_000, 1_000_000),
            Vec::new(),
            true,
            false,
            false,
            1_800_000_000,
            &mut p,
        );
        let report = gate.report_for(&request(&q, None));

        // One author: the gate's warnings ARE `warnings_for`'s output.
        assert_eq!(report.warnings, warnings_for(&plan));
        assert_eq!(report.warnings.len(), 3, "{:#?}", report.warnings);

        let lines = report.render();
        let index = |needle: &str| {
            lines
                .iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle} missing from {lines:#?}"))
        };
        // Every warning is above the cost line and above the permanence
        // sentence: the user weighs the permanent consequences before
        // reading a price, and the fine-tree estimate arrives "before the
        // quote" (MVP-SPEC.md line 85) in reading order.
        let cost = index("Cost");
        for needle in ["PLAINTEXT", "--no-fine-tree matched", "Note: building"] {
            assert!(index(needle) < cost, "{needle} must precede the quote");
        }
        assert!(cost < index(PERMANENCE_WARNING));
        // …and the machine document carries them as data.
        assert_eq!(report.json()["warnings"].as_array().map(Vec::len), Some(3));
    }

    /// The complement, and the reason the snapshots above stayed valid: a
    /// plain seal of small untitled files earns no warnings, so the gate
    /// adds no lines at all.
    #[test]
    fn a_plain_seal_renders_no_u15_warnings() {
        let q = quote(1, 1);
        let mut p = NeverAsked;
        let gate = SealConsent::new(
            &plan(),
            balances(9, 9),
            Vec::new(),
            true,
            false,
            false,
            1,
            &mut p,
        );
        let report = gate.report_for(&request(&q, None));
        assert!(report.warnings.is_empty());
        let text = report.render().join("\n");
        assert!(!text.contains("PLAINTEXT"), "{text}");
        assert!(!text.contains("--no-fine-tree"), "{text}");
        assert!(!text.contains("Note: building"), "{text}");
    }

    #[test]
    fn the_report_carries_the_spec_wording_the_file_list_the_totals_and_both_balances() {
        let q = quote(4_200, 21_000);
        let mut p = NeverAsked;
        let gate = SealConsent::new(
            &plan(),
            balances(9_000, 1_000_000),
            Vec::new(),
            true,
            false,
            false,
            1_800_000_000,
            &mut p,
        );
        let text = gate.report_for(&request(&q, None)).render().join("\n");

        // The spec's sentence, verbatim — asserted against the constant
        // AND against the literal, so neither can drift alone.
        assert!(text.contains(PERMANENCE_WARNING), "{text}");
        assert!(
            text.contains("upload is permanent, public, and irreversible"),
            "{text}"
        );
        // File list + byte totals.
        assert!(text.contains("Sealing 2 file(s), 51 byte(s)"), "{text}");
        assert!(text.contains("notes.txt  (11 bytes)"), "{text}");
        assert!(text.contains("blob.bin  (40 bytes)"), "{text}");
        // The complete quote, named as covering the manifest too.
        assert!(text.contains("3 blob(s)"), "{text}");
        assert!(text.contains("encrypted manifest"), "{text}");
        assert!(text.contains("4200 atto-ANT storage"), "{text}");
        assert!(text.contains("21000 wei of gas"), "{text}");
        // BOTH balances, beside it.
        assert!(text.contains("9000 atto-ANT"), "{text}");
        assert!(text.contains("1000000 wei"), "{text}");
        assert!(text.contains(&balances(0, 0).wallet.to_string()), "{text}");
        // A funded wallet shows no shortfall marker.
        assert!(!text.contains("SHORT"), "{text}");
    }

    #[test]
    fn the_resume_render_shows_prior_totals_with_a_drift_flag_in_both_directions() {
        let mut p = NeverAsked;
        let gate = SealConsent::new(
            &plan(),
            balances(9_000, 1_000_000),
            vec!["  Resuming interrupted seal c1c1".to_owned()],
            true,
            false,
            false,
            1_800_000_000,
            &mut p,
        );
        let prior = |ant: u128| ConsentRecord {
            total_ant_atto: ant,
            gas_estimate_wei: 21_000,
            consent_time_unix_secs: 1_798_761_800,
            channel: ConsentChannel::Interactive,
        };

        let dearer = quote(4_200, 21_000);
        let text = gate
            .report_for(&request(&dearer, Some(prior(4_000))))
            .render()
            .join("\n");
        assert!(text.contains("Previously consented"), "{text}");
        assert!(text.contains("[CHANGED: +200]"), "{text}");
        // D45's ONE merged render: the resume plan and the consent screen
        // are the same pass, never two prompts.
        assert!(text.contains("Resuming interrupted seal"), "{text}");

        let cheaper = quote(3_800, 21_000);
        let text = gate
            .report_for(&request(&cheaper, Some(prior(4_000))))
            .render()
            .join("\n");
        assert!(text.contains("[CHANGED: -200]"), "{text}");

        // Unchanged: the prior line still shows, with no drift flag.
        let same = quote(4_000, 21_000);
        let text = gate
            .report_for(&request(&same, Some(prior(4_000))))
            .render()
            .join("\n");
        assert!(text.contains("Previously consented"), "{text}");
        assert!(!text.contains("CHANGED"), "{text}");

        // Absent record → render without the prior line, never an error.
        let text = gate.report_for(&request(&same, None)).render().join("\n");
        assert!(!text.contains("Previously consented"), "{text}");
    }

    /// **The regression this gate exists to not have.**
    ///
    /// `ConsentRequest::resume` is `proofs_expired || anchor.is_none()`,
    /// so it is **false** for a work killed before the anchor gate — the
    /// commonest resume there is. The plan must render anyway, because
    /// D45 detection (not the pipeline's flag) is what knows this
    /// invocation is a resume.
    #[test]
    fn the_resume_plan_renders_even_when_the_requests_resume_flag_is_false() {
        let q = quote(10, 1);
        let mut p = NeverAsked;
        let gate = SealConsent::new(
            &plan(),
            balances(9_000, 9_000),
            vec!["  Resuming interrupted seal beef".to_owned()],
            true,
            false,
            false,
            1,
            &mut p,
        );
        let mut req = request(&q, None);
        // Exactly what `consent_anchor_pay` passes for a `Staged` resume:
        // there is still anchoring to do, so `anchor` is `Some` and this
        // reads as a fresh seal.
        req.resume = false;
        req.proofs_expired = false;
        let text = gate.report_for(&req).render().join("\n");
        assert!(
            text.contains("Resuming interrupted seal beef"),
            "the resume plan vanished on the commonest resume case: {text}"
        );
        // And the merged render really is one screen, not two: the plan
        // and the permanence warning are in the same output.
        assert!(text.contains(PERMANENCE_WARNING), "{text}");
        assert!(gate.report_for(&req).json()["resume"] == true);
    }

    #[test]
    fn a_shortfall_is_visible_in_the_report_and_typed_in_the_error() {
        let q = quote(4_200, 21_000);

        // ANT first (S8's fixed order), even when both are short.
        let mut p = NeverAsked;
        let gate = SealConsent::new(
            &plan(),
            balances(1_000, 5),
            Vec::new(),
            true,
            false,
            false,
            1,
            &mut p,
        );
        let report = gate.report_for(&request(&q, None));
        let text = report.render().join("\n");
        assert!(text.contains("** SHORT by 3200 **"), "{text}");
        let err = report.preflight().expect_err("short");
        assert_eq!(err.class(), crate::error::ErrorClass::InsufficientAntToken);
        assert_eq!(err.exit_code(), 20);

        // Gas alone.
        let mut p = NeverAsked;
        let gate = SealConsent::new(
            &plan(),
            balances(9_000, 5),
            Vec::new(),
            true,
            false,
            false,
            1,
            &mut p,
        );
        let report = gate.report_for(&request(&q, None));
        assert!(report.render().join("\n").contains("** SHORT by 20995 **"));
        let err = report.preflight().expect_err("short");
        assert_eq!(err.class(), crate::error::ErrorClass::InsufficientEthGas);
        assert_eq!(err.exit_code(), 21);
    }

    #[test]
    fn machine_mode_without_yes_declines_and_never_prompts() {
        let q = quote(1, 1);
        let mut p = NeverAsked;
        let gate = SealConsent::new(
            &plan(),
            balances(9_000, 9_000),
            Vec::new(),
            false,
            true,
            true,
            1,
            &mut p,
        );
        assert_eq!(
            gate.confirm(&request(&q, None))
                .expect("no channel failure"),
            ConsentDecision::Declined(ConsentOutcome::MachineModeWithoutYes)
        );
        // The report still rendered — a script's log says what it refused.
        assert_eq!(gate.rendered.borrow().len(), 1);
    }

    #[test]
    fn yes_grants_through_the_yes_channel_and_still_prints_the_report() {
        let q = quote(1, 1);
        let mut p = NeverAsked;
        let gate = SealConsent::new(
            &plan(),
            balances(9_000, 9_000),
            Vec::new(),
            true,
            true,
            true,
            1_800_000_000,
            &mut p,
        );
        assert_eq!(
            gate.confirm(&request(&q, None)).expect("granted"),
            ConsentDecision::Granted {
                channel: ConsentChannel::YesFlag,
                at_unix_secs: 1_800_000_000,
            }
        );
        assert!(
            gate.rendered.borrow()[0]
                .render()
                .join("\n")
                .contains(PERMANENCE_WARNING),
            "--yes consents in advance; the report still prints"
        );
    }

    #[test]
    fn an_interactive_no_declines_and_an_interactive_yes_grants() {
        let q = quote(1, 1);

        let mut p = Scripted(vec![false]);
        let gate = SealConsent::new(
            &plan(),
            balances(9, 9),
            Vec::new(),
            false,
            false,
            false,
            7,
            &mut p,
        );
        assert_eq!(
            gate.confirm(&request(&q, None)).expect("asked"),
            ConsentDecision::Declined(ConsentOutcome::Declined)
        );

        let mut p = Scripted(vec![true]);
        let gate = SealConsent::new(
            &plan(),
            balances(9, 9),
            Vec::new(),
            false,
            false,
            false,
            7,
            &mut p,
        );
        assert_eq!(
            gate.confirm(&request(&q, None)).expect("asked"),
            ConsentDecision::Granted {
                channel: ConsentChannel::Interactive,
                at_unix_secs: 7,
            }
        );
    }

    #[test]
    fn the_proofs_expired_render_says_the_earlier_payment_is_stranded() {
        let q = quote(1, 1);
        let mut p = NeverAsked;
        let gate = SealConsent::new(
            &plan(),
            balances(9, 9),
            vec!["  Resuming".to_owned()],
            true,
            false,
            false,
            1,
            &mut p,
        );
        let mut req = request(&q, None);
        req.resume = true;
        req.proofs_expired = true;
        let text = gate.report_for(&req).render().join("\n");
        assert!(text.contains("stranded"), "{text}");
        assert!(text.contains("SECOND, ADDITIONAL payment"), "{text}");
    }

    #[test]
    fn the_json_document_uses_decimal_strings_for_chain_amounts() {
        let q = quote(u128::from(u64::MAX) + 1, 21_000);
        let mut p = NeverAsked;
        let gate = SealConsent::new(
            &plan(),
            balances(u128::MAX, 1),
            Vec::new(),
            true,
            false,
            false,
            1,
            &mut p,
        );
        let json = gate.report_for(&request(&q, None)).json();
        assert_eq!(json["storage_cost_atto"], "18446744073709551616");
        assert_eq!(
            json["balance_ant_atto"],
            "340282366920938463463374607431768211455"
        );
        assert_eq!(json["permanence_warning"], PERMANENCE_WARNING);
        assert_eq!(json["total_input_bytes"], 51);
    }
}
