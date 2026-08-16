//! U29 acceptance suite: the irreversible-disclosure consent gate, over a
//! real seal and through `reveal`'s own path.
//!
//! Every row here seals the fixture work through the S12 pipeline into a
//! real vault and then drives
//! [`antseal_cli::reveal_out::run_reveal`] with the **real** gate
//! ([`antseal_cli::reveal_consent::DisclosureConsent`]) rather than a test
//! double — so what is asserted is what a user would see and what a
//! declining user would be left with: nothing.
//!
//! The fixture is built to reach D67's arms in one work: a text file
//! carrying a **raw mirror** (BOM + CRLF + NFD → hex, truncated), a
//! **binary** file (hex, whole), a text file long enough to **truncate with
//! a code-point back-off**, and a **`--split blank-lines`** file whose three
//! units make a partial selection and a promoted one both expressible.
//!
//! The committed snapshot at `tests/snapshots/reveal-consent.txt` is this
//! row's M3 freeze vehicle for that rendering (D67 §3 R7): regenerate it
//! deliberately with `ANTSEAL_BLESS=1` and justify the diff.
//!
//! NON-SECRET: every fixture byte string is documented here.

mod common;

use std::path::{Path, PathBuf};

use antseal_cli::cli::RevealArgs;
use antseal_cli::error::{CliError, ConsentOutcome, ErrorClass};
use antseal_cli::pipeline::{
    NoBarriers, Pipeline, SealFile, SealRequest, SealResult, VaultJournal, hex32,
};
use antseal_cli::preview::{
    DisclosurePreview, FilePreview, PreviewRow, PreviewTotals, Snippet, SnippetProvenance,
    SnippetWindow,
};
use antseal_cli::reveal_consent::{
    DISCLOSURE_HEADLINE, DisclosureConsent, DisclosureReport, RECEIPT_EXPOSURE_WARNING,
};
use antseal_cli::reveal_out::run_reveal;
use antseal_cli::seal_consent::ConsentPrompt;
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::content::{FileFlags, SplitMode};
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_core::manifest::{ByteRange, UnitKind};
use antseal_net::NetworkId;
use antseal_net::test_util::{MockBackend, block_on};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use common::{IsolatedVault, RecordingGate, ScriptedConsent};

// ─────────────────────────────────────────────────────────────────────
// Fixture content
// ─────────────────────────────────────────────────────────────────────

/// Raw bytes differ from canonical three ways (BOM, CRLF, NFD `e`+U+0301),
/// so this file carries a **raw mirror**: canonical 25 bytes, raw 32.
const CRLF_BOM_NFD: &[u8] = "\u{FEFF}caf\u{65}\u{301} notes\r\n\r\nsecond para\r\n".as_bytes();

/// Binary: raw-domain offsets, no mirror, hex snippet shorter than the cap.
const BINARY: &[u8] = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0x7F, 0x80, 0x00, 0x42];

/// Canonical-already text tiled into three units by `--split blank-lines`.
const SPLIT_TEXT: &[u8] = b"alpha one\n\nbeta two\n\ngamma three\n";

/// Text whose 64-byte text window lands **inside** a code point, so the cut
/// backs off (D67 §3 R3): exactly 63 ASCII bytes, then `é` at bytes 63–64.
fn long_text() -> Vec<u8> {
    let mut text = String::from("A paragraph long enough that the preview must cut it");
    while text.len() < 63 {
        text.push('.');
    }
    text.push('\u{e9}');
    text.push_str(" and there is more after the cut.\n");
    text.into_bytes()
}

const NAMES: [&str; 4] = ["notes.txt", "data/blob.bin", "long.txt", "split.txt"];

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "antseal-u29-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(path.join("data")).expect("mk scratch");
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

/// Write the fixture files and seal them; returns the printed work id.
fn seal_fixture(mock: &MockBackend, vault: &UnlockedVault, scratch: &Scratch) -> String {
    let long = long_text();
    let content: [&[u8]; 4] = [CRLF_BOM_NFD, BINARY, &long, SPLIT_TEXT];
    let absolutes: Vec<PathBuf> = NAMES.iter().map(|n| scratch.join(n)).collect();
    for (path, bytes) in absolutes.iter().zip(content) {
        std::fs::write(path, bytes).expect("plant the fixture file");
    }
    let absolute_strings: Vec<String> = absolutes
        .iter()
        .map(|p| p.to_str().expect("utf-8 path").to_owned())
        .collect();
    let flags = [
        FileFlags::new(),
        FileFlags::new(),
        FileFlags::new(),
        FileFlags::new().with_split(SplitMode::BlankLines),
    ];
    let files: Vec<SealFile<'_>> = (0..NAMES.len())
        .map(|i| SealFile {
            path_as_given: NAMES[i],
            path_absolute: &absolute_strings[i],
            bytes: content[i],
            flags: flags[i],
        })
        .collect();

    let mut journal_rng = ChaCha20Rng::from_seed([0x29; 32]);
    let journal = VaultJournal::new(WorkStore::new(vault), &mut journal_rng);
    let gate = RecordingGate::new();
    let consent = ScriptedConsent::always_yes();
    let pipeline = Pipeline::new(mock, &gate, &journal, &consent, &NoBarriers);
    let request = SealRequest {
        files: &files,
        title: "u29 fixture".to_owned(),
        claimed_time_unix_secs: 1_800_000_000,
        app_version: "antseal-test/1".to_owned(),
        network: NetworkId::Devnet,
        no_anchor: false,
        degraded: false,
        dry_run: false,
        sig_policy: SigPolicy::hybrid(),
        shaping: SealShapingFlags {
            title: Some("u29 fixture".to_owned()),
            ..SealShapingFlags::default()
        },
    };
    match block_on(pipeline.seal(&request, &mut ChaCha20Rng::from_seed([0x2A; 32])))
        .expect("the fixture seals")
    {
        SealResult::Sealed(outcome) => hex32(&outcome.work_id),
        SealResult::DryRun(_) => unreachable!("not a dry run"),
    }
}

fn all_args(work_id: &str, output: &Path) -> RevealArgs {
    RevealArgs {
        work_id: work_id.to_owned(),
        all: true,
        units: Vec::new(),
        output: Some(output.to_path_buf()),
        include_receipt: false,
        yes: false,
    }
}

fn unit_args(work_id: &str, units: &[u64], output: &Path) -> RevealArgs {
    RevealArgs {
        units: units.to_vec(),
        all: false,
        ..all_args(work_id, output)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Prompt doubles
// ─────────────────────────────────────────────────────────────────────

struct NeverAsked;
impl ConsentPrompt for NeverAsked {
    fn ask(&mut self) -> Result<bool, CliError> {
        panic!("the disclosure gate prompted in a mode that must never prompt (D51)");
    }
}

struct Scripted {
    answer: bool,
    asks: usize,
}
impl ConsentPrompt for Scripted {
    fn ask(&mut self) -> Result<bool, CliError> {
        self.asks += 1;
        Ok(self.answer)
    }
}

/// Run one reveal through the real gate, returning the screen it rendered
/// and whatever `run_reveal` returned.
fn reveal_through_the_gate(
    mock: &MockBackend,
    vault: &UnlockedVault,
    args: &RevealArgs,
    yes: bool,
    machine_mode: bool,
    answer: bool,
) -> (Vec<Vec<String>>, Result<(), CliError>) {
    let store = WorkStore::new(vault);
    let mut prompt = Scripted { answer, asks: 0 };
    let gate = DisclosureConsent::new(yes, machine_mode, true, &mut prompt);
    let outcome = block_on(run_reveal(mock, &store, args, gate.gate())).map(|_| ());
    (gate.rendered(), outcome)
}

/// The screen a granting run renders (and the bundle it writes, discarded).
fn screen(mock: &MockBackend, vault: &UnlockedVault, args: &RevealArgs) -> Vec<String> {
    let (rendered, outcome) = reveal_through_the_gate(mock, vault, args, false, false, true);
    outcome.expect("the reveal completes");
    assert_eq!(rendered.len(), 1, "one screen, one gate pass");
    rendered.into_iter().next().expect("one screen")
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 1: the preview, snapshot-frozen
// ─────────────────────────────────────────────────────────────────────

/// **U29 accept**: the M3 freeze of D67's rendering on this surface.
#[test]
fn the_consent_screen_matches_the_committed_snapshot() {
    let scratch = Scratch::new("snapshot");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u29-snapshot");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, &scratch);

    let mut out = String::from(
        "antseal — `reveal <work-id>` (U29), the screen shown before any bundle exists\n\n",
    );

    // Every file is promoted (`--all` selects every normal unit), the one
    // file that has a mirror rides it, and `long.txt`'s row is D67 §3 R3's
    // code-point back-off: the window stops at byte 63 because byte 64 is
    // the second half of `é`, so the accent never reaches the screen.
    out.push_str("════ --all: every unit, every file promoted, the one mirror riding ════\n");
    out.push_str(
        &screen(
            &mock,
            &unlocked,
            &all_args(&work_id, &scratch.join("a.sealproof")),
        )
        .join("\n"),
    );

    out.push_str("\n\n════ --units 5: one unit of one file, nothing promoted ════\n");
    out.push_str(
        &screen(
            &mock,
            &unlocked,
            &unit_args(&work_id, &[5], &scratch.join("b.sealproof")),
        )
        .join("\n"),
    );

    out.push_str("\n\n════ --units 4,5,6: the D28 promotion, on a file with no mirror ════\n");
    out.push_str(
        &screen(
            &mock,
            &unlocked,
            &unit_args(&work_id, &[4, 5, 6], &scratch.join("c.sealproof")),
        )
        .join("\n"),
    );

    out.push_str("\n\n════ --units 0 --include-receipt: the wallet-exposure warning ════\n");
    let mut with_receipt = unit_args(&work_id, &[0], &scratch.join("d.sealproof"));
    with_receipt.include_receipt = true;
    out.push_str(&screen(&mock, &unlocked, &with_receipt).join("\n"));

    out.push_str(
        "\n\n════ the arms a seal cannot produce: the absent snippet, the empty unit, and a \
         crafted path ════\n",
    );
    out.push_str(
        &DisclosureReport {
            preview: &defensive_preview(),
            receipt_included: false,
        }
        .render()
        .join("\n"),
    );
    out.push('\n');

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/reveal-consent.txt");
    if std::env::var_os("ANTSEAL_BLESS").is_some() {
        std::fs::write(&path, &out).expect("bless");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing committed consent snapshot at {}: {e} (generate with ANTSEAL_BLESS=1)",
            path.display()
        )
    });
    assert!(
        committed == out,
        "the `reveal` consent screen drifted from {} — regenerate with ANTSEAL_BLESS=1 and \
         justify the diff\n--- rendered ---\n{out}",
        path.display()
    );
}

/// The defensive arms: a row whose snippet is absent (D67 §3 R5), an empty
/// unit (`""`, no marker), and a path carrying an LF, a C0 control and a
/// bidi override — none of which a seal of honest data produces, and all of
/// which this screen must render safely.
fn defensive_preview() -> DisclosurePreview {
    let hostile = "ok.txt\u{202E}\u{0007}\n      unit 99   normal   1 byte(s) at offset 0";
    let rows = vec![
        PreviewRow {
            unit_id: 0,
            file_id: 0,
            path: hostile.to_owned(),
            kind: UnitKind::Normal,
            range: ByteRange::new(0, 7),
            size: 7,
            file_fully_revealed: false,
            snippet: None,
        },
        PreviewRow {
            unit_id: 1,
            file_id: 0,
            path: hostile.to_owned(),
            kind: UnitKind::Normal,
            range: ByteRange::new(7, 0),
            size: 0,
            file_fully_revealed: false,
            snippet: Some(Snippet {
                window: SnippetWindow::Text(String::new()),
                truncated: false,
                provenance: SnippetProvenance::SealedBytes,
            }),
        },
    ];
    DisclosurePreview {
        totals: PreviewTotals {
            units: rows.len() as u64,
            bytes: rows.iter().map(|r| u128::from(r.size)).sum(),
            files_touched: 1,
            files_fully_revealed: 0,
            mirror_rides_along: false,
        },
        rows,
        files: vec![FilePreview {
            file_id: 0,
            path: hostile.to_owned(),
            fully_revealed: false,
            mirror_rides_along: false,
        }],
    }
}

/// The snapshot is only a freeze if the words it froze are the right ones:
/// the spec's phrase is present, and every disclosed unit has its own row.
#[test]
fn the_screen_names_every_disclosed_unit_and_says_irreversibly_disclosed() {
    let scratch = Scratch::new("rows");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u29-rows");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, &scratch);

    let lines = screen(
        &mock,
        &unlocked,
        &all_args(&work_id, &scratch.join("rows.sealproof")),
    );
    assert_eq!(lines[0], DISCLOSURE_HEADLINE);
    assert!(lines[0].contains("irreversibly disclosed"), "{}", lines[0]);

    let joined = lines.join("\n");
    for unit_id in 0..=6u64 {
        assert!(
            joined.contains(&format!("unit {unit_id}   ")),
            "unit {unit_id} has no row:\n{joined}"
        );
    }
    // The mirror is marked as such, and the D28/D70 consequences are stated.
    assert!(joined.contains("unit 1   raw-mirror"), "{joined}");
    assert!(joined.contains("whole-file commitments"), "{joined}");
    assert!(joined.contains("raw mirror is included"), "{joined}");
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 1b: declining writes no bundle file
// ─────────────────────────────────────────────────────────────────────

/// **U29 accept**: a declining gate leaves nothing behind — no bundle, and
/// not even a partial one.
#[test]
fn declining_writes_no_bundle_file() {
    let scratch = Scratch::new("decline");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u29-decline");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, &scratch);

    let target = scratch.join("refused.sealproof");
    let (rendered, outcome) = reveal_through_the_gate(
        &mock,
        &unlocked,
        &all_args(&work_id, &target),
        false,
        false,
        false,
    );
    let err = outcome.expect_err("a declined disclosure is not a success");
    assert_eq!(err.class(), ErrorClass::ConsentNotObtained, "{err}");
    assert!(matches!(
        err,
        CliError::ConsentNotObtained {
            reason: ConsentOutcome::Declined
        }
    ));
    assert_eq!(
        rendered.len(),
        1,
        "the screen was shown before the question"
    );
    assert!(
        !target.exists(),
        "a declined reveal writes nothing: {} exists",
        target.display()
    );
    assert_eq!(
        std::fs::read_dir(&scratch.0)
            .expect("scratch")
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "sealproof"))
            .count(),
        0,
        "no .sealproof of any name was written"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 3: --yes and the non-TTY abort
// ─────────────────────────────────────────────────────────────────────

/// **U29 accept**: `--yes` writes the bundle without asking anything, in
/// plain mode and in machine mode alike — and the screen still renders
/// (D51 invariant 1).
#[test]
fn yes_proceeds_without_prompting_and_still_renders_the_screen() {
    let scratch = Scratch::new("yes");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u29-yes");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, &scratch);
    let store = WorkStore::new(&unlocked);

    for (tag, machine_mode) in [("plain", false), ("machine", true)] {
        let target = scratch.join(&format!("{tag}.sealproof"));
        let mut args = all_args(&work_id, &target);
        args.yes = true;
        let mut prompt = NeverAsked;
        let gate = DisclosureConsent::new(true, machine_mode, machine_mode, &mut prompt);
        block_on(run_reveal(&mock, &store, &args, gate.gate())).expect("--yes consents");
        assert!(target.exists(), "{tag}: the bundle is written");
        assert_eq!(gate.rendered().len(), 1, "{tag}: the screen still rendered");
    }
}

/// **U29 accept**: machine mode without `--yes` aborts rather than hanging,
/// in the one consent-not-obtained class, and writes nothing.
#[test]
fn machine_mode_without_yes_aborts_and_writes_nothing() {
    let scratch = Scratch::new("machine");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u29-machine");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, &scratch);
    let store = WorkStore::new(&unlocked);

    let target = scratch.join("machine.sealproof");
    let mut prompt = NeverAsked;
    let gate = DisclosureConsent::new(false, true, true, &mut prompt);
    let err = block_on(run_reveal(
        &mock,
        &store,
        &all_args(&work_id, &target),
        gate.gate(),
    ))
    .expect_err("machine mode cannot obtain consent");
    assert_eq!(err.class(), ErrorClass::ConsentNotObtained, "{err}");
    assert!(matches!(
        err,
        CliError::ConsentNotObtained {
            reason: ConsentOutcome::MachineModeWithoutYes
        }
    ));
    assert!(err.to_string().contains("--yes"), "{err}");
    assert!(!target.exists());
    assert_eq!(gate.rendered().len(), 1, "the screen rendered anyway");
}

/// **U29 accept**: under `--json` the screen goes to **stderr**, so stdout
/// keeps carrying exactly one envelope (D51 invariants 1 and 2).
///
/// **What this asserts, exactly.** The routing *decision* — the gate holds
/// stderr when `--json` is on and stdout when it is not. It does not
/// observe the bytes arriving on a file descriptor: the emitter is
/// `eprintln!`/`println!`, the same mechanism `SealConsent::emit` uses, and
/// nothing in this crate can read its own process streams back without an
/// unstable API or a `libc` dependency (and no new dependencies, U29). The
/// end-to-end statement of stdout purity under `--json` is
/// `machine_mode.rs`'s harness, which drives the **real binary** for every
/// command and asserts exactly one document on stdout — `reveal` included.
#[test]
fn the_screen_goes_to_stderr_under_json() {
    let mut prompt = NeverAsked;
    // `to_stderr` is `globals.json` at the handler (`commands.rs`), which is
    // the same expression `seal`'s gate takes.
    assert!(DisclosureConsent::new(true, true, true, &mut prompt).to_stderr());
    let mut prompt = NeverAsked;
    assert!(!DisclosureConsent::new(true, false, false, &mut prompt).to_stderr());
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 2: the receipt warning
// ─────────────────────────────────────────────────────────────────────

/// **U29 accept**: the wallet-exposure warning rides with the receipt and
/// **only** with it — asserted in both directions over the same work.
#[test]
fn the_receipt_warning_rides_with_the_receipt_and_only_with_it() {
    let scratch = Scratch::new("receipt");
    let mock = MockBackend::new();
    let vault = IsolatedVault::create("u29-receipt");
    let unlocked = vault.unlock();
    let work_id = seal_fixture(&mock, &unlocked, &scratch);

    let without = screen(
        &mock,
        &unlocked,
        &all_args(&work_id, &scratch.join("without.sealproof")),
    )
    .join("\n");
    assert!(!without.contains(RECEIPT_EXPOSURE_WARNING), "{without}");
    assert!(
        !without.to_lowercase().contains("wallet"),
        "no wallet is named when no receipt rides:\n{without}"
    );

    let mut args = all_args(&work_id, &scratch.join("with.sealproof"));
    args.include_receipt = true;
    let with = screen(&mock, &unlocked, &args).join("\n");
    assert!(with.contains(RECEIPT_EXPOSURE_WARNING), "{with}");
    assert!(with.contains("wallet that paid"), "{with}");
    assert!(
        with.contains("every other seal that wallet ever paid for"),
        "{with}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// U71: the gate has a production caller, and nothing else does
// ─────────────────────────────────────────────────────────────────────

/// **U71**: `run_reveal`'s consent seam has exactly **one** production
/// caller, and that caller supplies the real [`DisclosureConsent`].
///
/// # Why every other test in this file fails to discharge this row
///
/// They assert that the gate *behaves*: it renders the screen, it honours
/// `--yes`, it aborts in machine mode, a decline writes no bundle. Nineteen
/// of them, all green, and every one of them would stay green if the
/// production path never called the gate at all — which is exactly the state
/// the U29 lane self-reported. `run_reveal` takes `consent: G` where
/// `G: FnOnce(&PreparedReveal) -> Result<(), CliError>`: an arbitrary
/// closure, with no type, trait bound or construction rule tying it to
/// `DisclosureConsent`. Spec line 36 makes the confirmation **constitutive**
/// of the command, so a call whose consent argument is `|_| Ok(())` is not a
/// degraded `reveal` — it is a *different command*, one that writes a
/// `.sealproof` full of irreversibly disclosed plaintext without asking, and
/// it compiles, passes every row above, and reads as ordinary.
///
/// (This paragraph deliberately does **not** spell the call form. The scan
/// below matches text, so a rustdoc sentence that wrote it would be counted
/// as a call — which is how this very doc first reddened the check, and is
/// worth leaving recorded rather than rediscovering.)
///
/// The suite proves the gate **works**. This proves it is **called**. The
/// two are not the same claim and no amount of the first produces the
/// second.
///
/// # The shape, and why it is (b) rather than (a)
///
/// U71 offered two: (a) close the seam so the production entry cannot accept
/// an arbitrary closure, or (b) pin the call site with a red-capable source
/// assertion in the shape of D128 §3 R2's
/// `without_storage_linkage_has_exactly_two_callers`. (b) is taken, on
/// measurement rather than preference, and the measurement is worth stating
/// because (a) is the shape U71 says to prefer.
///
/// (a) is **possible** — it is not blocked, and this is not a claim that it
/// is. Every scripted gate in the tree could be rebuilt from a real
/// `DisclosureConsent` over a scripted `ConsentPrompt`, which is what the
/// rows in *this* file already do. What it costs, measured today: `run_reveal`
/// takes `consent: G` at **eleven** call sites (1 production + 3 here + 7 in
/// `tests/reveal_output.rs` + 3 in `tests/reveal_vault_local.rs`), so a
/// narrowed parameter is a public-signature change plus ten harness rewrites,
/// and U71 is an S row about reachability. The escape hatch a narrowed
/// parameter would want cannot be `#[cfg(test)]` — `tests/` are separate
/// crates and never see it — so it would have to be a `pub` constructor
/// (which re-opens the seam it just closed) or a new cargo feature on this
/// package (a feature-graph change, a far larger blast radius than the
/// defect).
///
/// And (a) would **cost** something the suites currently have: U28's rows
/// assert D68 §3 R11's ordering by inspecting the `PreparedReveal` *at the
/// moment the gate is asked* — that the gate sees a preview and nothing
/// bundle-shaped — which is a property of being handed a closure. Shape (b)
/// holds the reachability property, keeps that observation, and costs one
/// test.
///
/// # What is asserted
///
/// 1. Exactly one file under any crate's `src/` calls `run_reveal`, it is
///    `commands.rs`, and it calls it **once**. A second production caller —
///    the way a permissive closure would arrive — reddens on the count, per
///    file, so a second call *inside* an already-listed file reddens too.
/// 2. That call's own argument list contains `DisclosureConsent::gate`'s
///    invocation, matched by walking the parentheses rather than a fixed
///    window, so reformatting cannot silently disarm it. Replacing the real
///    gate with `|_| Ok(())` at the existing site therefore reddens even
///    though the count did not move.
/// 3. `DisclosureConsent` is constructed exactly once in production, so the
///    gate cannot be built, left unused, and the closure passed by hand.
///
/// The call form is assembled with `concat!` so this scan's own source does
/// not contain the token it hunts for: a scanner that matches itself is one
/// nobody trusts on sight (D128 §3 R2's own precaution, adopted).
#[test]
fn the_reveal_consent_gate_has_exactly_one_production_caller() {
    use std::collections::BTreeMap;

    /// `(path, calls, warrant)` — the closed list of callers.
    const CALLERS: [(&str, usize, &str); 4] = [
        (
            "crates/antseal-cli/src/commands.rs",
            1,
            "the ONE production caller: `reveal`'s handler, wired at U72",
        ),
        (
            "crates/antseal-cli/tests/reveal_consent.rs",
            3,
            "U29's suite — drives the REAL gate (declining, granting, machine mode)",
        ),
        (
            "crates/antseal-cli/tests/reveal_output.rs",
            7,
            "U28's suite — scripted test doubles that COUNT whether the gate was asked",
        ),
        (
            "crates/antseal-cli/tests/reveal_vault_local.rs",
            3,
            "U72's suite — cache-served, cache-missing, and the collision-first order",
        ),
    ];
    /// The call form (see the rustdoc: built so this file does not contain
    /// it literally).
    const CALL: &str = concat!("run_reveal", "(");
    /// The production caller's warrant, as a token in its argument list.
    const GATE: &str = concat!("gate", ".", "gate", "()");
    /// The gate's construction.
    const BUILD: &str = concat!("DisclosureConsent", "::new", "(");
    /// The definition, exempt: `pub async fn run_reveal<B, G>(` does not
    /// contain the call form, but the file is named so a reader can see the
    /// exemption is deliberate rather than accidental.
    const DEFINITION: &str = "crates/antseal-cli/src/reveal_out.rs";

    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("cannot read an entry under {}: {e}", dir.display()))
                .path();
            let skip = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "target" || n == ".git");
            if skip {
                continue;
            }
            if path.is_dir() {
                collect(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// Production source: under a crate's `src/`, and **not** one of the
    /// `#[cfg(test)]` sibling modules that live there
    /// (`src/reveal_consent/tests.rs` is eight scripted gates, and counting
    /// them as production would make this check unpassable rather than
    /// strict).
    fn is_production_source(relative: &str) -> bool {
        relative.contains("/src/")
            && !relative.ends_with("/tests.rs")
            && !relative.contains("/src/tests/")
    }

    /// The text inside the parentheses of the call starting at `start`.
    fn argument_list(text: &str, start: usize) -> String {
        let bytes: Vec<char> = text[start..].chars().collect();
        let mut depth = 0usize;
        let mut out = String::new();
        for character in bytes {
            match character {
                '(' => {
                    depth += 1;
                    if depth == 1 {
                        continue;
                    }
                }
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return out;
                    }
                }
                _ => {}
            }
            if depth >= 1 {
                out.push(character);
            }
        }
        out
    }

    // The production filter must admit the one real site and reject the
    // `#[cfg(test)]` sibling, or it proves nothing.
    assert!(is_production_source("crates/antseal-cli/src/commands.rs"));
    assert!(!is_production_source(
        "crates/antseal-cli/src/reveal_consent/tests.rs"
    ));
    assert!(!is_production_source(
        "crates/antseal-cli/tests/reveal_consent.rs"
    ));

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels under the workspace root")
        .to_path_buf();
    let mut files = Vec::new();
    collect(&root, &mut files);
    assert!(
        files.len() > 300,
        "the walker found only {} files — it is not reaching the tree",
        files.len()
    );

    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    let mut builds: BTreeMap<String, usize> = BTreeMap::new();
    let mut saw_definition = false;
    let mut production_arguments: Vec<(String, String)> = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
        let relative = file
            .strip_prefix(&root)
            .expect("every scanned file is under the root")
            .to_string_lossy()
            .replace('\\', "/");
        if relative == DEFINITION {
            saw_definition = true;
        }
        let count = text.matches(CALL).count();
        if count > 0 {
            found.insert(relative.clone(), count);
        }
        let built = text.matches(BUILD).count();
        if built > 0 {
            builds.insert(relative.clone(), built);
        }
        if is_production_source(&relative) {
            for (offset, _) in text.match_indices(CALL) {
                production_arguments.push((relative.clone(), argument_list(&text, offset)));
            }
        }
    }
    assert!(
        saw_definition,
        "the scan did not reach `run_reveal`'s own definition file — walker broken?"
    );

    // 1. No file outside the closed list calls the seam, and every listed
    //    one calls it exactly as often as its warrant says.
    let listed: std::collections::BTreeSet<&str> =
        CALLERS.iter().map(|(path, _, _)| *path).collect();
    let strays: Vec<&String> = found
        .keys()
        .filter(|path| !listed.contains(path.as_str()))
        .collect();
    assert!(
        strays.is_empty(),
        "an unlisted caller of `{CALL}` appeared: {strays:?}. `reveal`'s consent gate is \
         constitutive of the command (spec line 36) — a caller that supplies a permissive \
         closure is a DIFFERENT command that writes irreversibly disclosed plaintext without \
         asking. Add the site here with its warrant, or do not add the site (U71)."
    );
    for (path, calls, why) in CALLERS {
        let seen = found.get(path).copied().unwrap_or(0);
        assert_eq!(
            seen, calls,
            "`{path}` calls `{CALL}` {seen} time(s), not {calls}. It is on U71's closed list \
             as: {why}. A count that moved is a consent seam nobody ruled, or a listed site \
             that stopped calling."
        );
    }

    // 2. Exactly one production call, and it passes the REAL gate.
    assert_eq!(
        production_arguments.len(),
        1,
        "expected exactly one `{CALL}` under a `src/`; found {:?}",
        production_arguments
            .iter()
            .map(|(path, _)| path)
            .collect::<Vec<_>>()
    );
    let (path, arguments) = &production_arguments[0];
    assert_eq!(path, "crates/antseal-cli/src/commands.rs", "{path}");
    assert!(
        arguments.contains(GATE),
        "the one production call to `{CALL}` in `{path}` does not pass `{GATE}`. Its consent \
         argument is an arbitrary closure, so `|_| Ok(())` compiles here and produces a reveal \
         that never asks — which spec line 36 makes a different command, not a degraded one \
         (U71).\n  argument list: {arguments}"
    );

    // 3. The gate is constructed exactly once in production, so it cannot be
    //    built and then bypassed.
    let production_builds: usize = builds
        .iter()
        .filter(|(path, _)| is_production_source(path))
        .map(|(_, count)| *count)
        .sum();
    assert_eq!(
        production_builds, 1,
        "`{BUILD}` appears {production_builds} time(s) under a `src/`, not once: {builds:?}"
    );
}
