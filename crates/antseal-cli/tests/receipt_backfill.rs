//! **U67 acceptance suite**: D33's block-number backfill, and the fact that
//! something in the product now calls it.
//!
//! The ruling is `docs/decisions/D33-block-number-locus.md` (Decision 2 — the
//! idempotent, non-gating enrichment retry) and the surface it repairs is
//! R16's `reveal --include-receipt`. Everything here runs in the **default**
//! build; the `ant-backend` feature owns exactly one constructor
//! (`antseal_cli::backend::payment_rpc`) and no policy, which is why this
//! suite can exist at all rather than living on one developer's machine.
//!
//! The suite is split the way U24's is, and forced the same way:
//!
//! - **in-process** for what the backfill *does to a bundle*, because that
//!   claim is about the reveal engine's output and is cheapest and clearest
//!   over `MockBackend`;
//! - **against the real binary** for *where the pass runs and what it costs
//!   its host*, because "`status`'s exit code and output are unaffected" is a
//!   claim about the shipped dispatch path and is unfalsifiable from a
//!   library call;
//! - **as a source scan** for *that a production caller exists at all*, which
//!   is the property the row exists for and which no amount of passing suite
//!   can produce (the defect U67 names was a fully-working, fully-tested,
//!   completely unreachable function).
//!
//! # No test here can reach a real endpoint (Q16)
//!
//! Nothing in this file opens a payment RPC to anything but a loopback stub.
//! The in-process rows drive a scripted [`BlockNumberSource`]; the spawned
//! U67 rows reach `backend::payment_rpc` and are refused by it in **both**
//! builds — the default one has no backend at all, and the `ant-backend` one
//! cannot resolve the fixture work's `devnet` endpoints because
//! [`spawn_status`] removes `ANTSEAL_DEVNET_ENV` (see [`GATED_ARM`]). The one
//! row that lets the constructor succeed is D173 §2 R14's, and it is
//! loopback-only by construction: the export it hands the binary names a
//! payment RPC that is a loopback stub and one bootstrap peer that is a
//! loopback UDP socket the test holds, and it counts what reaches each. Every
//! spawn goes through `spawn::antseal()`, which arms Q16's environment gate
//! (D99 R4.1) and the storage gate's (D173 §2 R11) — the latter admits that
//! loopback peer and would refuse any other.
//!
//! NON-SECRET: every byte string, seal id and passphrase here is a documented
//! fixture (project rule 6).

mod common;
#[path = "common/spawn.rs"]
mod spawn;

use std::io::Write as _;
use std::path::{Path, PathBuf};

use antseal_cli::pipeline::receipt_backfill::{
    BackfillSkip, BlockNumberSource, backfill_recorded_receipt, unfilled_block_numbers,
};
use antseal_cli::pipeline::receipt_sink::recorded_receipt;
use antseal_cli::pipeline::{
    NoBarriers, Pipeline, PreparedReveal, RevealEngine, RevealError, RevealRequest, SealFile,
    SealRequest, SealResult, UnitSelection, VaultJournal,
};
use antseal_cli::vault::session::UnlockedVault;
use antseal_cli::vault::store::{SealShapingFlags, WorkStore};
use antseal_core::bundle::BundleV1;
use antseal_core::content::FileFlags;
use antseal_core::crypto::secrets::SealId;
use antseal_core::crypto::sig_policy::SigPolicy;
use antseal_net::test_util::{MockBackend, block_on};
use antseal_net::{JournalReceipt, NetworkId, PaymentReceipt, TxStatus};
use common::{IsolatedVault, RecordingGate, ScriptedConsent};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// NON-SECRET fixture text; one file, one unit, no split — everything this
/// suite asserts is about the receipt record, not about unit shapes.
const NOTES: &[u8] = b"one sealed line\n";

// ─────────────────────────────────────────────────────────────────────
// Fixture
// ─────────────────────────────────────────────────────────────────────

/// A real sealed work in its own vault, through the real S12 pipeline over
/// `MockBackend` — so the receipt this suite mutilates is one the production
/// payment path actually produced, block numbers and all.
struct Sealed {
    vault: IsolatedVault,
    seal_id: SealId,
    work_id: [u8; 32],
}

fn seal_one(tag: &str, seed: u8) -> Sealed {
    let vault_dir = IsolatedVault::create(tag);
    let seal_id;
    let work_id;
    {
        let vault = vault_dir.unlock();
        let mock = MockBackend::new();
        let files = vec![SealFile {
            path_as_given: "notes.txt",
            path_absolute: "/w/notes.txt",
            bytes: NOTES,
            flags: FileFlags::new(),
        }];
        let request = SealRequest {
            files: &files,
            title: "u67 fixture".to_owned(),
            claimed_time_unix_secs: 1_800_000_000,
            app_version: "antseal-test/1".to_owned(),
            network: NetworkId::Devnet,
            no_anchor: false,
            degraded: false,
            dry_run: false,
            sig_policy: SigPolicy::hybrid(),
            shaping: SealShapingFlags::default(),
        };
        let mut journal_rng = ChaCha20Rng::from_seed([seed ^ 0xA5; 32]);
        let journal = VaultJournal::new(WorkStore::new(&vault), &mut journal_rng);
        let gate = RecordingGate::new();
        let consent = ScriptedConsent::always_yes();
        let pipeline = Pipeline::new(&mock, &gate, &journal, &consent, &NoBarriers);
        let outcome =
            match block_on(pipeline.seal(&request, &mut ChaCha20Rng::from_seed([seed; 32])))
                .expect("the fixture seals")
            {
                SealResult::Sealed(outcome) => outcome,
                SealResult::DryRun(_) => unreachable!("not a dry run"),
            };
        seal_id = outcome.seal_id;
        work_id = outcome.work_id;
    }
    Sealed {
        vault: vault_dir,
        seal_id,
        work_id,
    }
}

impl Sealed {
    fn read_receipt(&self, vault: &UnlockedVault) -> PaymentReceipt {
        recorded_receipt(&WorkStore::new(vault), &self.seal_id)
            .expect("reads")
            .expect("the pipeline journaled one")
    }

    fn write_receipt(&self, vault: &UnlockedVault, receipt: &PaymentReceipt) {
        let bytes = serde_json::to_vec(&JournalReceipt::seal(receipt.clone())).expect("encode");
        WorkStore::new(vault)
            .put_receipt(
                &self.seal_id,
                &bytes,
                &mut ChaCha20Rng::from_seed([0x67; 32]),
            )
            .expect("write");
    }

    /// Strip every block number, reproducing the state U67 exists for: the
    /// payment landed, the receipt read did not.
    fn unenrich(&self, vault: &UnlockedVault) -> Vec<u64> {
        let recorded = self.read_receipt(vault);
        let original: Vec<u64> = recorded
            .txs
            .iter()
            .filter_map(|tx| tx.block_number)
            .collect();
        assert!(
            !original.is_empty(),
            "the fixture's own payment recorded no block number, so this suite would be \
             asserting nothing"
        );
        let mut stripped = recorded;
        for tx in &mut stripped.txs {
            tx.block_number = None;
            tx.status = TxStatus::Submitted;
        }
        self.write_receipt(vault, &stripped);
        original
    }

    fn receipt_path(&self) -> PathBuf {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(32);
        for byte in self.seal_id.as_bytes() {
            let _ = write!(hex, "{byte:02x}");
        }
        self.vault.layout.works_dir().join(hex).join("receipt")
    }
}

/// A scripted stand-in for the payment RPC: fills every empty slot, counts
/// its calls. NON-SECRET, deterministic.
struct MockRpc {
    base: u64,
    calls: std::cell::Cell<usize>,
}

impl MockRpc {
    fn new(base: u64) -> Self {
        Self {
            base,
            calls: std::cell::Cell::new(0),
        }
    }
}

impl BlockNumberSource for MockRpc {
    fn backfill(&self, receipt: &mut PaymentReceipt) -> Result<usize, String> {
        self.calls.set(self.calls.get() + 1);
        let mut filled = 0;
        for (index, tx) in receipt.txs.iter_mut().enumerate() {
            if tx.block_number.is_none() {
                tx.block_number = Some(self.base + index as u64);
                tx.status = TxStatus::Confirmed;
                filled += 1;
            }
        }
        Ok(filled)
    }
}

fn prepare_with_receipt(
    backend: &MockBackend,
    vault: &UnlockedVault,
    seal_id: &SealId,
) -> Result<PreparedReveal, RevealError> {
    let store = WorkStore::new(vault);
    let engine = RevealEngine::new(backend, &store);
    block_on(engine.prepare(
        seal_id,
        &RevealRequest {
            selection: UnitSelection::All,
            include_receipt: true,
        },
    ))
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 1 — the two halves, together
// ─────────────────────────────────────────────────────────────────────

/// **U67 Accept row 1.** A completed work whose `TxRecord`s all carry
/// `block_number: None` reaches a filled slot after the pass runs against a
/// mock RPC, **and `--include-receipt` then succeeds on the same vault**.
///
/// The two are asserted together because either alone leaves the defect
/// standing: a filled slot nobody can spend is the state D33 was already in
/// (the function worked; nothing called it), and a green `--include-receipt`
/// on a healthy work says nothing about a damaged one.
///
/// The refusal is asserted **first**, on the same vault, in the same test.
/// Without it this row would be a bundle test that happened to pass — the
/// `expect_err` is what proves the fixture is actually in the broken state
/// the backfill is credited with repairing.
#[test]
fn a_backfilled_work_can_finally_embed_its_receipt() {
    let fixture = seal_one("u67-embed", 0x67);
    let vault = fixture.vault.unlock();
    let mock = MockBackend::new();

    // (a) The state U67 names: every slot empty, and R16 refuses — correctly,
    //     because registry §7.10 key 1 is required and undefinable here.
    let original = fixture.unenrich(&vault);
    assert_eq!(
        unfilled_block_numbers(&fixture.read_receipt(&vault)),
        fixture.read_receipt(&vault).txs.len()
    );
    let refusal = prepare_with_receipt(&mock, &vault, &fixture.seal_id)
        .expect_err("an unenriched receipt cannot be embedded");
    assert!(
        matches!(refusal, RevealError::ReceiptBlockNumberUnknown),
        "{refusal:?}"
    );

    // (b) The pass, over a mock RPC.
    let rpc = MockRpc::new(4_242);
    let pass = backfill_recorded_receipt(
        &vault,
        &fixture.seal_id,
        &rpc,
        &mut ChaCha20Rng::from_seed([0x68; 32]),
    );
    assert!(pass.written, "the pass wrote nothing: {pass:?}");
    assert_eq!(
        rpc.calls.get(),
        1,
        "the mock RPC was not asked exactly once"
    );
    assert_eq!(
        unfilled_block_numbers(&fixture.read_receipt(&vault)),
        0,
        "the pass reported a write but the journaled receipt still has empty slots"
    );

    // (c) The same vault, the same flag, and now it succeeds — carrying the
    //     backfilled minimum, which is the value registry §7.10 key 1 is.
    let prepared =
        prepare_with_receipt(&mock, &vault, &fixture.seal_id).expect("the enriched receipt embeds");
    let output = prepared.build().expect("builds");
    assert!(output.summary.receipt_included);
    let bundle = BundleV1::decode(&output.sealproof).expect("decodes");
    let embedded = bundle.receipt().expect("receipt embedded");
    assert_eq!(
        embedded.block_number(),
        4_242,
        "the embedded key 1 is the minimum over the backfilled numbers"
    );
    // The tx hashes are the pipeline's own, unchanged by enrichment: the
    // backfill fills a slot, it does not rewrite the capture.
    assert_eq!(
        embedded.tx_hashes().len(),
        fixture.read_receipt(&vault).txs.len()
    );
    assert_eq!(
        original.len(),
        embedded.tx_hashes().len(),
        "the fixture had one recorded block number per transaction before it was stripped"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 3 — the production caller, pinned
// ─────────────────────────────────────────────────────────────────────

/// **U67 Accept row 3.** The backfill has a production caller, and a scan
/// says where. Delete it and this reddens.
///
/// # Why a passing suite cannot discharge this row
///
/// It is the whole defect. `backfill_block_numbers` was implemented,
/// documented as idempotent, covered by a devnet test, and **called by
/// nothing in the product** — so every green test in the tree was green
/// against a `--include-receipt` that could never be repaired. An assertion
/// that the pass *works* is exactly the assertion that was already true. This
/// asserts that it is *reached*, which is a different claim and the only one
/// the row is about.
///
/// # The trap this scan is written around
///
/// `the_reveal_consent_gate_has_exactly_one_production_caller` in
/// `tests/reveal_consent.rs` records it the hard way: the scan matches text,
/// so a rustdoc paragraph that spells a call form literally is counted as a
/// production call. This doc therefore names functions **without** their
/// parentheses, and every hunted form is assembled with `concat!` so this
/// file does not contain the tokens it looks for.
///
/// # What is asserted
///
/// 1. The entry point has exactly one caller under any crate's `src/`, it is
///    `crates/antseal-cli/src/commands.rs`, and the call sits inside the
///    `status` handler — so moving it to a command that never renders a
///    receipt is a red, not a silent relocation.
/// 2. The pass it delegates to has exactly one production caller too — the
///    entry point itself — so nobody can reach the pass while bypassing the
///    empty-slot check and the source construction.
/// 3. `backfill_block_numbers`, the `antseal-net` function this row is
///    named after, is reachable from production: it is named in its own
///    definition file and in exactly one CLI file, the construction seam.
///    A tree in which it is named only by `antseal-net` and a devnet test is
///    the tree U67 found.
#[test]
fn the_block_number_backfill_has_exactly_one_production_caller() {
    use std::collections::BTreeMap;

    /// The production entry `status` calls (assembled, see the rustdoc).
    const ENTRY: &str = concat!("enrich_recorded", "_receipt", "(");
    /// The pass the entry delegates to.
    const PASS: &str = concat!("backfill_recorded", "_receipt", "(");
    /// `antseal-net`'s own function — the one U67 is named after.
    const NET: &str = concat!("backfill_block", "_numbers", "(");
    /// The handler the entry must sit in.
    const HOST: &str = concat!("fn status", "(");

    /// `(path, occurrences, warrant)` for [`ENTRY`] — a closed list over the
    /// whole tree, definition included, so the exemption below is visible
    /// rather than accidental.
    const ENTRY_SITES: [(&str, usize, &str); 3] = [
        (
            "crates/antseal-cli/src/commands.rs",
            1,
            "THE production caller: `status`'s handler (U67 — the host)",
        ),
        (
            "crates/antseal-cli/src/pipeline/receipt_backfill.rs",
            1,
            "the definition itself — exempt from the caller count, and named here so the \
             exemption is deliberate rather than accidental",
        ),
        (
            "crates/antseal-cli/tests/receipt_backfill.rs",
            0,
            "this suite never names the entry: its rows drive the PASS directly, and the \
             entry's arms are read off the real binary's trace. Listed at zero so the day \
             somebody adds one it is a decision rather than a drift",
        ),
    ];
    /// The definition's file, exempt from the production-caller count.
    const DEFINITION: &str = "crates/antseal-cli/src/pipeline/receipt_backfill.rs";
    /// `(path, occurrences, warrant)` for [`NET`] — re-counted to D173 §2
    /// R14's shape on 2026-10-14, with each change named rather than loosened.
    const NET_SITES: [(&str, usize, &str); 4] = [
        (
            "crates/antseal-net/src/ant_backend.rs",
            2,
            "the definition on the receipt reader (`pub async fn`, D33 Decision 1's locus \
             since D173 §2 R14) plus the payer's delegating method of the same name, which \
             D173 §2 R14 keeps as a delegation to the one shared body. Was 1 while the payer \
             carried the only definition; nothing in the tree calls the payer's as of this \
             re-count",
        ),
        (
            "crates/antseal-cli/src/backend.rs",
            1,
            "U67's gated bridge: the one call the payment-RPC source makes, on the receipt \
             reader. Was 3 — a delegating method on `SealBackend`, its body, and the call \
             through it — until D173 §2 R14 moved `status` off the payer; the wrapper went \
             with it, so nothing `status` holds can pay or open a storage session",
        ),
        (
            "crates/antseal-net/tests/devnet_backend.rs",
            2,
            "the devnet rows that proved the function correct while nothing called it — the \
             two lines U67 measured as its ONLY callers on 2026-08-11, now on the receipt \
             reader",
        ),
        (
            "crates/antseal-net/tests/storage_gate.rs",
            1,
            "D173 §2 R14's own row: the receipt reader backfills over a loopback JSON-RPC stub \
             while its bootstrap set holds a peer the armed storage gate would refuse — so the \
             read provably consults no storage gate",
        ),
    ];

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

    /// Production source: under a crate's `src/`, and not a `#[cfg(test)]`
    /// sibling module living there.
    fn is_production_source(relative: &str) -> bool {
        relative.contains("/src/")
            && !relative.ends_with("/tests.rs")
            && !relative.contains("/src/tests/")
    }

    /// The part of a file before its first `#[cfg(test)]` — the same cut
    /// `seal_session::production_files_naming` makes, adopted verbatim so
    /// this scan and the three S36/D99 scans agree on what "production"
    /// means. Without it an inline test module counts as a caller, and the
    /// fix would be to weaken the assertion rather than the scan.
    fn production_text(text: &str) -> &str {
        match text.find("#[cfg(test)]") {
            Some(at) => &text[..at],
            None => text,
        }
    }

    // The filter must admit this row's real site and reject both kinds of
    // test source, or it proves nothing.
    assert!(is_production_source("crates/antseal-cli/src/commands.rs"));
    assert!(!is_production_source(
        "crates/antseal-cli/src/reveal_consent/tests.rs"
    ));
    assert!(!is_production_source(
        "crates/antseal-cli/tests/receipt_backfill.rs"
    ));
    assert_eq!(
        production_text("a\n#[cfg(test)]\nmod tests { b }"),
        "a\n",
        "the `#[cfg(test)]` cut does not cut"
    );

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

    // Whole-file counts (the closed lists) and production-only counts (the
    // caller assertions), kept apart so an inline test module is documented
    // rather than mistaken for a caller.
    let mut entry_sites: BTreeMap<String, usize> = BTreeMap::new();
    let mut pass_sites: BTreeMap<String, usize> = BTreeMap::new();
    let mut net_sites: BTreeMap<String, usize> = BTreeMap::new();
    let mut entry_production: BTreeMap<String, usize> = BTreeMap::new();
    let mut pass_production: BTreeMap<String, usize> = BTreeMap::new();
    let mut net_production: BTreeMap<String, usize> = BTreeMap::new();
    let mut entry_in_status = false;
    let mut saw_commands = false;
    for file in &files {
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
        let relative = file
            .strip_prefix(&root)
            .expect("every scanned file is under the root")
            .to_string_lossy()
            .replace('\\', "/");
        for (form, sink) in [
            (ENTRY, &mut entry_sites),
            (PASS, &mut pass_sites),
            (NET, &mut net_sites),
        ] {
            let count = text.matches(form).count();
            if count > 0 {
                sink.insert(relative.clone(), count);
            }
        }
        if is_production_source(&relative) {
            let production = production_text(&text);
            for (form, sink) in [
                (ENTRY, &mut entry_production),
                (PASS, &mut pass_production),
                (NET, &mut net_production),
            ] {
                let count = production.matches(form).count();
                if count > 0 {
                    sink.insert(relative.clone(), count);
                }
            }
        }
        if relative == "crates/antseal-cli/src/commands.rs" {
            saw_commands = true;
            // The call must live inside `status`'s own handler body: from
            // its signature to the next item at the same indentation.
            let start = text
                .find(HOST)
                .expect("`commands.rs` defines a `status` handler");
            let body = &text[start..];
            let end = body[1..]
                .find("\npub(crate) fn ")
                .map_or(body.len(), |offset| offset + 1);
            entry_in_status = body[..end].contains(ENTRY);
        }
    }
    assert!(saw_commands, "the walker never reached `commands.rs`");

    // 1. The entry's closed caller list.
    let listed: std::collections::BTreeSet<&str> =
        ENTRY_SITES.iter().map(|(path, _, _)| *path).collect();
    let strays: Vec<&String> = entry_sites
        .keys()
        .filter(|path| !listed.contains(path.as_str()))
        .collect();
    assert!(
        strays.is_empty(),
        "an unlisted caller of the backfill entry appeared: {strays:?}. U67 hosts the pass in \
         ONE command on a measured argument (see the entry's own docs); a second host is a \
         decision, not an edit. Add the site here with its warrant, or do not add the site."
    );
    for (path, calls, why) in ENTRY_SITES {
        let seen = entry_sites.get(path).copied().unwrap_or(0);
        assert_eq!(
            seen, calls,
            "`{path}` names the backfill entry {seen} time(s), not {calls}. It is on U67's \
             closed list as: {why}. A count that fell to zero is the defect back: \
             `backfill_block_numbers` reachable only from a test, and `--include-receipt` \
             permanently refused for any work whose enrichment failed once."
        );
    }
    let production_entry_calls: usize = entry_production
        .iter()
        .filter(|(path, _)| path.as_str() != DEFINITION)
        .map(|(_, count)| *count)
        .sum();
    assert_eq!(
        production_entry_calls, 1,
        "expected exactly one production call to the backfill entry; found {entry_production:?}"
    );
    assert!(
        entry_production.contains_key(DEFINITION),
        "the walker never reached the entry's own definition — it is not scanning what it \
         thinks, so the exemption above is hiding nothing rather than hiding the definition"
    );
    assert!(
        entry_in_status,
        "the one production call is no longer inside `commands.rs`'s `status` handler. \
         `status` is the host on a measured argument — it is the only command that renders a \
         block number, so the repair sits beside the display of the thing repaired, and it \
         runs before the gather so one invocation both closes the gap and shows it closed."
    );

    // 2. The pass is reachable only through the entry.
    let production_pass: Vec<(&String, &usize)> = pass_production.iter().collect();
    assert_eq!(
        production_pass.len(),
        1,
        "the pass must be called from exactly one production file — its own entry, which is \
         what performs the empty-slot check and constructs the source. Found \
         {production_pass:?}"
    );
    assert_eq!(
        production_pass[0].0, DEFINITION,
        "the pass's one production caller moved out of its own module"
    );
    assert_eq!(
        *production_pass[0].1, 1,
        "the entry's module calls the pass more than once"
    );
    assert!(
        pass_sites
            .get(DEFINITION)
            .is_some_and(|whole_file| *whole_file > *production_pass[0].1),
        "the `#[cfg(test)]` cut removed nothing from the entry's own module, so this scan is \
         not actually distinguishing the inline test harness from a production caller"
    );

    // 3. `antseal-net`'s function is named from production, not only tests.
    for (path, calls, why) in NET_SITES {
        let seen = net_sites.get(path).copied().unwrap_or(0);
        assert_eq!(
            seen, calls,
            "`{path}` names `backfill_block` + `_numbers` {seen} time(s), not {calls} ({why})"
        );
    }
    let net_production_cli: usize = net_production
        .iter()
        .filter(|(path, _)| path.contains("antseal-cli"))
        .map(|(_, count)| *count)
        .sum();
    assert!(
        net_production_cli > 0,
        "no `antseal-cli` production source names `antseal-net`'s backfill. That is exactly \
         the state U67 measured on 2026-08-11: implemented, documented, and reachable only \
         from `crates/antseal-net/tests/devnet_backend.rs`. Found: {net_sites:?}"
    );

    // 4. The bridge takes a public chain from the pinned constants and never
    //    routes it through `select_network` (D174 §2 R6). Code lines only,
    //    production text only: the one caller left in `backend.rs` is the
    //    read-only commands' resolver, and the chain-half seam is defined
    //    once and called once, by the bridge.
    /// The resolver a public id must NOT go through here (assembled).
    const SELECT: &str = concat!("select_", "network(");
    /// The bridge's chain-half seam (assembled).
    const SEAM: &str = concat!("receipt_network", "_with(");
    let backend = files
        .iter()
        .find(|file| {
            file.strip_prefix(&root).is_ok_and(|rel| {
                rel.to_string_lossy().replace('\\', "/") == "crates/antseal-cli/src/backend.rs"
            })
        })
        .expect("the walker reached `backend.rs`");
    let backend_text = std::fs::read_to_string(backend).expect("read backend.rs");
    let code_line_hits = |form: &str| -> usize {
        production_text(&backend_text)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .map(|line| line.matches(form).count())
            .sum()
    };
    assert_eq!(
        code_line_hits(SELECT),
        1,
        "`backend.rs` calls the network selector on {} code line(s), not 1. Its one caller is \
         `read_only_network` (restore / verify --live). `payment_rpc` must not route a public \
         id through it: for `arbitrum-sepolia` the selector reads `ANTSEAL_DEVNET_ENV`, so a \
         public receipt's backfill would depend on a developer's export being present and \
         valid (D174 §2 R6)",
        code_line_hits(SELECT)
    );
    assert_eq!(
        code_line_hits(SEAM),
        2,
        "the chain-half seam must be defined once and called once by `payment_rpc` in \
         `backend.rs`; found {} code line(s) — a seam nothing calls is a seam whose tests \
         prove nothing about the bridge",
        code_line_hits(SEAM)
    );
}

// ─────────────────────────────────────────────────────────────────────
// Accept row 2 — non-gating, at the host command
// ─────────────────────────────────────────────────────────────────────

struct Spawned {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Spawn the real binary against `vault_root`, passphrase on stdin.
///
/// `ANTSEAL_DEVNET_ENV` is **removed**, not merely unused. Under
/// `--features ant-backend` the gated source constructor reads it to resolve
/// a `devnet` work's endpoints, so a developer who happens to have a devnet
/// exported would send these runs down a different arm than CI does — and
/// [`GATED_ARM`] below reads exactly that arm off the trace.
fn spawn_status(vault_root: &Path, args: &[&str], log: Option<&str>) -> Spawned {
    let mut command = spawn::antseal();
    command
        .args(args)
        .env("ANTSEAL_DIR", vault_root)
        .env_remove("RUST_LOG")
        .env_remove("ANTSEAL_DEVNET_ENV")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(filter) = log {
        command.env("RUST_LOG", filter);
    }
    let mut child = command.spawn().expect("spawn antseal");
    let _ = child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(common::FIXTURE_PASSPHRASE);
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait for antseal");
    Spawned {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The `RUST_LOG` filter that makes the pass's summary line and the source
/// constructor's arm visible, and nothing else.
const BACKFILL_LOG: &str =
    "antseal_cli::pipeline::receipt_backfill=debug,antseal_cli::backend=debug";

/// The sentence the **source constructor** emits in *this* build, read off
/// the spawned binary — which is built with this test's own feature set.
///
/// # Why this is here and not folded into the pass's trace
///
/// U67's host is ungated and CI-witnessed; the thing that opens a payment RPC
/// is not. `crate::backend::payment_rpc` is the whole `#[cfg(feature =
/// "ant-backend")]` surface this row added, and Q153 keeps `heavy-features`
/// local-only, so **without this assertion the gated constructor would be
/// compile-witnessed and nothing more** — it would never be observed
/// *running*, in any build, anywhere.
///
/// With it, the two builds witness two different real things through the same
/// spawned command:
///
/// - the default build proves the no-backend arm is reached and returns
///   `None` silently;
/// - an `ant-backend` build proves the **gated** constructor is reached,
///   resolves the work's own network, and refuses on it — because the
///   fixture work records `devnet` and [`spawn_status`] removes
///   `ANTSEAL_DEVNET_ENV`, so there is no devnet definition to select.
///
/// What neither witnesses is a **successful** RPC: that needs a running
/// devnet and lives in `crates/antseal-net/tests/devnet_backend.rs`, where
/// `backfill_block_numbers` has always been covered. The seam this row adds
/// between the two is therefore proven reachable and proven silent, and its
/// success path is proven only by the pre-existing devnet rows.
#[cfg(not(feature = "ant-backend"))]
const GATED_ARM: &str = "this build compiles no storage backend";

/// See the default-build arm above.
#[cfg(feature = "ant-backend")]
const GATED_ARM: &str = "the work's network has no usable definition here";

/// **U67 Accept row 2, the host-command half.** Hosting the pass in `status`
/// leaves `status`'s exit code and its output alone — asserted against the
/// **real binary**, because that claim is about the shipped dispatch path.
///
/// Two runs of one command on one vault, differing only in whether the
/// receipt's block-number slots are filled:
///
/// - the pass **runs in both** (its trace names which arm it took, so this
///   cannot pass against a build where the call was deleted — that is the
///   anti-vacuity, and it is a *fourth* witness of the wiring beside the
///   source scan);
/// - both exit **0**;
/// - the two `--json` documents differ in exactly one place, the receipt's
///   `block_numbers` array — so an attempted-and-unsuccessful pass adds,
///   removes and perturbs nothing;
/// - the record file is **byte-identical** across the run in which the pass
///   found something to do and could not do it.
///
/// Negative control for the exit-code half: an unknown work id through the
/// same harness exits non-zero, so "exits 0" is a claim this test could
/// observe failing. Negative control for the output half: the two documents
/// *do* differ, at the located key, so "equal everywhere else" is not
/// vacuous over two identical strings.
///
/// **What this does not cover.** In a default build the pass stops at
/// `no-source`, so what is witnessed is a backfill that could not run, not
/// one whose RPC refused mid-flight. The RPC-refused arm is
/// `a_failing_source_is_silent_and_writes_nothing` in the library's own test
/// module, where a source can be scripted to fail.
#[test]
fn hosting_the_pass_leaves_status_exit_code_and_output_alone() {
    let fixture = seal_one("u67-status", 0x6A);
    let printed = antseal_cli::pipeline::hex32(&fixture.work_id);
    let root = fixture.vault.layout.root().to_path_buf();

    // Run A — every slot filled by the pipeline's own payment. Nothing to do.
    let filled = spawn_status(
        &root,
        &["--json", "--passphrase-fd", "0", "status", &printed],
        Some(BACKFILL_LOG),
    );
    assert_eq!(filled.code, Some(0), "stderr:\n{}", filled.stderr);
    assert!(
        filled.stderr.contains(BACKFILL_NOT_NEEDED_ARM),
        "the pass did not report the `nothing-unfilled` arm — either it never ran, or it \
         took another one.\nstderr:\n{}",
        filled.stderr
    );

    // Run B — the same command, the same vault, every slot emptied.
    {
        let vault = fixture.vault.unlock();
        fixture.unenrich(&vault);
    }
    let before = std::fs::read(fixture.receipt_path()).expect("the record exists");
    let empty = spawn_status(
        &root,
        &["--json", "--passphrase-fd", "0", "status", &printed],
        Some(BACKFILL_LOG),
    );
    assert_eq!(empty.code, Some(0), "stderr:\n{}", empty.stderr);
    assert!(
        empty.stderr.contains(BACKFILL_ATTEMPTED_ARM),
        "the pass did not report an attempt on a work with empty slots — the production \
         caller is not running in the shipped binary.\nstderr:\n{}",
        empty.stderr
    );
    // The source constructor really ran, and took THIS build's arm. Without
    // this line the `ant-backend` half of U67 would be compile-witnessed and
    // never observed running (Q153 keeps `heavy-features` local-only).
    assert!(
        empty.stderr.contains(GATED_ARM),
        "the payment-RPC source constructor did not report `{GATED_ARM}` — this build's arm of \
         `backend::payment_rpc` was not reached.\nstderr:\n{}",
        empty.stderr
    );

    // Non-gating at the record: a pass that found work and could not do it
    // wrote nothing. Byte-identity, not plaintext equality — the record's
    // ciphertext is randomized per write, so this proves no write happened.
    assert_eq!(
        std::fs::read(fixture.receipt_path()).expect("the record exists"),
        before,
        "the failed pass rewrote the journaled receipt"
    );

    // Non-gating in the output: one located difference and no other.
    let a: serde_json::Value = serde_json::from_str(filled.stdout.trim()).expect("run A is json");
    let b: serde_json::Value = serde_json::from_str(empty.stdout.trim()).expect("run B is json");
    let (mut a, mut b) = (a, b);
    let path = ["result", "receipt", "block_numbers"];
    let a_numbers = a.pointer(&format!("/{}", path.join("/"))).cloned();
    let b_numbers = b.pointer(&format!("/{}", path.join("/"))).cloned();
    assert_ne!(
        a_numbers, b_numbers,
        "the two runs are indistinguishable, so 'equal everywhere else' asserts nothing"
    );
    assert_eq!(
        b_numbers,
        Some(serde_json::json!([])),
        "run B should render no block number at all"
    );
    for (document, _) in [(&mut a, ()), (&mut b, ())] {
        if let Some(slot) = document.pointer_mut(&format!("/{}", path.join("/"))) {
            *slot = serde_json::Value::Null;
        }
    }
    assert_eq!(
        a, b,
        "the attempted backfill perturbed the `status` document somewhere other than the \
         block-number array it is about"
    );

    // The exit-code assertion is reachable in both directions.
    let unknown = spawn_status(
        &root,
        &["--passphrase-fd", "0", "status", &"ab".repeat(32)],
        None,
    );
    assert_ne!(
        unknown.code,
        Some(0),
        "the harness cannot observe a non-zero exit, so 'exits 0' above proves nothing"
    );
}

/// The trace sentence a pass emits when it had something to try.
///
/// Read off the module's own `pub const` rather than spelled here, for the
/// reason `HOOK_ARMED` records: a test that wrote the sentence itself would
/// go green on the day the pass stopped running and the line stopped being
/// emitted.
const BACKFILL_ATTEMPTED_ARM: &str = antseal_cli::pipeline::receipt_backfill::BACKFILL_ATTEMPTED;

/// The trace sentence a pass emits when every slot was already filled.
const BACKFILL_NOT_NEEDED_ARM: &str = antseal_cli::pipeline::receipt_backfill::BACKFILL_NOT_NEEDED;

/// The two arms must stay distinguishable by substring search — one must not
/// be a prefix of the other, or a not-needed run would satisfy an
/// "attempted" assertion. The same precaution `upgrade_hook.rs` takes for
/// `HOOK_ARMED`/`HOOK_NOT_ARMED`, and for the same reason: those consts are
/// this suite's only handle on which arm a spawned invocation took.
#[test]
fn the_two_trace_arms_cannot_be_mistaken_for_each_other() {
    assert_ne!(BACKFILL_ATTEMPTED_ARM, BACKFILL_NOT_NEEDED_ARM);
    assert!(!BACKFILL_ATTEMPTED_ARM.contains(BACKFILL_NOT_NEEDED_ARM));
    assert!(!BACKFILL_NOT_NEEDED_ARM.contains(BACKFILL_ATTEMPTED_ARM));
}

/// The skip vocabulary is closed and every arm has a distinct name, so a
/// trace or an assertion cannot silently collapse two reasons into one.
#[test]
fn every_skip_arm_has_its_own_name() {
    let mut names: Vec<&str> = BackfillSkip::ALL.iter().map(|skip| skip.name()).collect();
    let count = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), count, "two skip arms share a name: {names:?}");
    assert!(count >= 8, "the arm list shrank to {count}");
}

// ─────────────────────────────────────────────────────────────────────
// D173 §2 R14 / D174 §2 R6 — no Autonomi session and no key in `status`
// ─────────────────────────────────────────────────────────────────────

/// A loopback JSON-RPC stub standing in for a devnet's payment RPC:
/// `eth_chainId` answers `0x7a69` (31337), every other method answers `null`
/// ("not yet visible"), and each method name is recorded in the order asked.
/// One request per connection (`Connection: close`), so the provider
/// reconnects for every call and a sequential accept loop serves it.
#[cfg(feature = "ant-backend")]
struct ReceiptRpcStub {
    address: std::net::SocketAddr,
    methods: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(feature = "ant-backend")]
impl ReceiptRpcStub {
    /// The devnet chain id the stub reports, as `eth_chainId` renders it.
    const CHAIN_HEX: &'static str = "0x7a69";

    fn start() -> Self {
        use std::sync::atomic::Ordering;

        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind the loopback RPC stub");
        let address = listener.local_addr().expect("the stub's address");
        let methods = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = {
            let methods = std::sync::Arc::clone(&methods);
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(mut stream) = stream {
                        // A malformed exchange fails only the assertion that
                        // reads the method log.
                        drop(Self::serve_one(&mut stream, &methods));
                    }
                }
            })
        };
        Self {
            address,
            methods,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.address)
    }

    fn methods(&self) -> Vec<String> {
        match self.methods.lock() {
            Ok(methods) => methods.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Serve one HTTP/1.1 JSON-RPC request, echoing its id.
    fn serve_one(
        stream: &mut std::net::TcpStream,
        methods: &std::sync::Mutex<Vec<String>>,
    ) -> std::io::Result<()> {
        use std::io::Read as _;

        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let head = String::from_utf8_lossy(&buffer[..header_end]).to_ascii_lowercase();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while buffer.len() < header_end + length {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        let body_end = (header_end + length).min(buffer.len());
        let request: serde_json::Value =
            serde_json::from_slice(&buffer[header_end..body_end]).unwrap_or_default();
        let method = request["method"].as_str().unwrap_or_default().to_owned();
        let result = if method == "eth_chainId" {
            serde_json::Value::from(Self::CHAIN_HEX)
        } else {
            serde_json::Value::Null
        };
        match methods.lock() {
            Ok(mut seen) => seen.push(method),
            Err(poisoned) => poisoned.into_inner().push(method),
        }
        let reply = serde_json::json!({
            "jsonrpc": "2.0",
            "id": request["id"].clone(),
            "result": result,
        })
        .to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{reply}",
            reply.len()
        )?;
        stream.flush()
    }
}

#[cfg(feature = "ant-backend")]
impl Drop for ReceiptRpcStub {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        drop(std::net::TcpStream::connect(self.address));
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
    }
}

/// A devnet export whose payment RPC is `rpc_url` and whose one bootstrap
/// peer is `bootstrap` — both loopback, both this test's. NON-SECRET: a
/// walletless (nine-key) export, the two contract addresses Anvil's
/// well-known deterministic deployments; nothing here pays.
#[cfg(feature = "ant-backend")]
fn loopback_export(dir: &Path, rpc_url: &str, bootstrap: std::net::SocketAddr) -> PathBuf {
    let text = format!(
        "# antseal devnet environment: a loopback one, held by a test\n\
         ANTSEAL_DEVNET_RPC_URL='{rpc_url}'\n\
         ANTSEAL_DEVNET_CHAIN_ID='31337'\n\
         ANTSEAL_DEVNET_TOKEN_ADDRESS='0x5FbDB2315678afecb367f032d93F642f64180aa3'\n\
         ANTSEAL_DEVNET_PAYMENT_VAULT_ADDRESS='0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512'\n\
         ANTSEAL_DEVNET_BOOTSTRAP='{bootstrap}'\n\
         ANTSEAL_DEVNET_NODE_COUNT='1'\n\
         ANTSEAL_DEVNET_BASE_PORT='{port}'\n\
         ANTSEAL_DEVNET_DATA_DIR='{data}'\n\
         ANTSEAL_DEVNET_PID='{pid}'\n",
        port = bootstrap.port(),
        data = dir.display(),
        pid = std::process::id(),
    );
    let path = dir.join("loopback-devnet.env");
    std::fs::write(&path, text).expect("write the loopback devnet export");
    path
}

/// Spawn `antseal <args>` over `vault_root` with `export` as its one devnet
/// definition, the fixture passphrase on stdin, the backfill and backend
/// traces on, and upstream's on-disk client state (`client_adaptive.json`,
/// S42) confined to `data_home` rather than the developer's.
#[cfg(feature = "ant-backend")]
fn spawn_with_export(vault_root: &Path, args: &[&str], export: &Path, data_home: &Path) -> Spawned {
    let mut command = spawn::antseal();
    command
        .args(args)
        .env("ANTSEAL_DIR", vault_root)
        .env("RUST_LOG", BACKFILL_LOG)
        .env("ANTSEAL_DEVNET_ENV", export)
        .env("XDG_DATA_HOME", data_home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().expect("spawn antseal");
    let _ = child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(common::FIXTURE_PASSPHRASE);
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait for antseal");
    Spawned {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Drain and count every datagram waiting on `socket` (its read timeout is
/// what ends the drain).
#[cfg(feature = "ant-backend")]
fn datagrams_received(socket: &std::net::UdpSocket) -> usize {
    let mut buffer = [0u8; 4096];
    let mut count = 0;
    while socket.recv_from(&mut buffer).is_ok() {
        count += 1;
    }
    count
}

/// `connect_read_only`'s one trace, emitted inside its future — so only when
/// a storage connection is actually attempted.
#[cfg(feature = "ant-backend")]
const READER_CONNECT_TRACE: &str = "connecting the read-only reader";

/// **D173 §2 R14, through the spawned binary: `status` reads its receipt with
/// no Autonomi session and no key.** A `devnet` work with every block-number
/// slot emptied, a payment RPC that is a loopback stub, and one bootstrap
/// peer that is a loopback UDP socket **this test holds** across the run.
/// `status` exits 0, the pass reports an attempt, the stub saw the chain-id
/// guard and the receipt read — and **zero** datagrams reached the bootstrap
/// socket. Until D173 §2 R14 the same `status` opened `SealBackend::connect`
/// — a full `Client::connect` over that peer, with the vault's wallet key
/// loaded to read a public receipt — and with `arbitrum-one`'s peers vendored
/// that would have made `status` dial mainnet to read a chain.
///
/// # Preconditions, asserted inside the row
///
/// Both are what the old route needed to get as far as the dial, so a zero
/// that could be explained by the old route skipping early proves nothing:
///
/// 1. **A wallet record exists** — the payer's route loaded the vault's key
///    before connecting and returned `None` without one.
/// 2. **The RPC stub saw `eth_chainId`** — the payment RPC was reached and
///    answered the chain the export pins, so the payer's route would have
///    passed its own guard and gone on to `Client::connect`.
///
/// # Control
///
/// A `restore` of the same work over the same export dials the same peer
/// (the read-only reader's `Client::connect`, D170 §2 R1), and the held
/// socket sees its datagrams — so the socket can witness a dial, and the
/// zero above is a measurement rather than a deaf instrument.
#[cfg(feature = "ant-backend")]
#[test]
fn status_reads_its_receipt_with_no_autonomi_session_while_restore_dials() {
    use antseal_cli::vault::wallet::{WalletKeyHandle, load_wallet_key, store_wallet_key};

    // NON-SECRET: the repeated-byte fixture scalar `backend.rs`'s own tests
    // use — a valid secp256k1 scalar by construction and obviously not a key.
    const FIXTURE_WALLET_KEY: [u8; 32] = [0x5A; 32];

    let fixture = seal_one("d173-no-session", 0x6B);
    let printed = antseal_cli::pipeline::hex32(&fixture.work_id);
    let root = fixture.vault.layout.root().to_path_buf();
    let scratch = fixture.vault.root.join("scratch");
    std::fs::create_dir_all(&scratch).expect("the scratch directory");

    // PRECONDITION 1: a wallet record exists.
    {
        let vault = fixture.vault.unlock();
        store_wallet_key(
            &vault,
            &WalletKeyHandle::from_bytes(FIXTURE_WALLET_KEY),
            &mut ChaCha20Rng::from_seed([0x6C; 32]),
        )
        .expect("store the fixture wallet record");
        assert!(
            load_wallet_key(&vault)
                .expect("the wallet record reads")
                .is_some(),
            "PRECONDITION: the vault holds a wallet record, so a payer built over it would \
             have had a key to load"
        );
        fixture.unenrich(&vault);
    }

    // The held bootstrap socket and the payment-RPC stub, both loopback.
    let bootstrap =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("bind the held bootstrap socket");
    bootstrap
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .expect("a read timeout on the held socket");
    let peer = bootstrap.local_addr().expect("the held socket's address");
    assert!(
        antseal_net::network::storage_gate::check(&[peer]).is_ok(),
        "PRECONDITION: the storage gate admits a lone loopback peer, so a storage session \
         opened over this export would dial it rather than be refused"
    );
    let rpc = ReceiptRpcStub::start();
    let export = loopback_export(&scratch, &rpc.url(), peer);

    // The row.
    let status = spawn_with_export(
        &root,
        &["--json", "--passphrase-fd", "0", "status", &printed],
        &export,
        &scratch.join("data-home-status"),
    );
    assert_eq!(status.code, Some(0), "stderr:\n{}", status.stderr);
    assert!(
        status.stderr.contains(BACKFILL_ATTEMPTED_ARM),
        "the pass did not report an attempt on a work with empty slots.\nstderr:\n{}",
        status.stderr
    );
    // The claim, judged first so a red names it whatever else the run did.
    let during_status = datagrams_received(&bootstrap);
    assert_eq!(
        during_status, 0,
        "`status` opened an Autonomi session: {during_status} datagram(s) reached the bootstrap \
         peer its export named. The receipt read is a chain read over the payment RPC and \
         nothing else — no `Client::connect`, no wallet key (D173 §2 R14)"
    );
    // What the zero rests on: a source was constructed and used.
    assert!(
        !status.stderr.contains("no payment RPC"),
        "the source constructor refused, so no session of any kind was opened and the zero \
         above proves nothing.\nstderr:\n{}",
        status.stderr
    );
    // PRECONDITION 2: the stub saw the chain-id guard.
    let methods = rpc.methods();
    assert!(
        methods.iter().any(|method| method == "eth_chainId"),
        "PRECONDITION: the RPC stub never saw eth_chainId — the payment RPC was not reached, \
         so the zero above proves nothing about the session: {methods:?}\nstderr:\n{}",
        status.stderr
    );
    assert!(
        methods
            .iter()
            .any(|method| method == "eth_getTransactionReceipt"),
        "the receipt was not read over the provider the guard ran on: {methods:?}"
    );

    // CONTROL: `restore` over the same export dials the same peer.
    let out_dir = scratch.join("restored");
    let out_arg = out_dir.to_str().expect("a utf-8 scratch path").to_owned();
    let restore = spawn_with_export(
        &root,
        &[
            "--json",
            "--passphrase-fd",
            "0",
            "restore",
            &printed,
            "-o",
            &out_arg,
        ],
        &export,
        &scratch.join("data-home-restore"),
    );
    assert!(
        restore.stderr.contains(READER_CONNECT_TRACE),
        "CONTROL: `restore` attempted no storage connection, so the zero above has no \
         positive control. exit {:?}\nstderr:\n{}",
        restore.code,
        restore.stderr
    );
    let during_restore = datagrams_received(&bootstrap);
    assert!(
        during_restore >= 1,
        "CONTROL: a `restore` connected over the same bootstrap peer and the held socket saw \
         nothing — it cannot witness a dial, so the zero above proves nothing. exit {:?}\n\
         stderr:\n{}",
        restore.code,
        restore.stderr
    );
}
