//! [`SealSession`] — the unlocked vault and the durable receipt sink,
//! minted together so a paying command cannot have one without the other
//! (S36).
//!
//! # What S31 left open, and why a builder call was not enough
//!
//! S31 landed [`VaultReceiptSink`]: D37 Decision 2's per-sub-batch receipt
//! write, performed *inline* from the capture hook so `pay` cannot submit
//! the next transaction until the last one is on disk. It also made the
//! sink's **target** structural — the pipeline calls
//! [`SealJournal::arm_receipts`](crate::pipeline::journal::SealJournal::arm_receipts)
//! immediately before every `pay`, on every path that can pay, so the sink
//! can never be pointed at the wrong work.
//!
//! What it did not make structural was the sink's **presence**.
//! `VaultJournal::with_receipt_sink` was an ordinary builder call, and the
//! only production caller (`seal`) did not make it: the command built an
//! in-memory sink for the backend and a bare journal for the pipeline. That
//! journal behaves exactly as the tree did before S31 — the hook fires,
//! nothing durable happens, and a crash between sub-batch txs re-pays. It
//! compiles, it runs, and it is silently wrong: the S27 shape, one level up.
//!
//! # The two layers, because the type system alone does not close it
//!
//! U36's answer to the same problem needed both halves, and so does this.
//!
//! 1. **The type.** [`SealSession::open`] takes the [`UnlockedVault`] **by
//!    value**, so a session is the only handle to it afterwards, and mints
//!    the one sink beside it. [`SealSession::journal`] is the only way to
//!    get a journal out of a session, and it always attaches that sink.
//!    [`run_seal`](crate::seal_run::run_seal) takes a `&SealSession` rather
//!    than a `&UnlockedVault`, so the *paying* command has no expression
//!    available to it that produces a sinkless journal.
//! 2. **The scan.** A future command could still reach past the session and
//!    call `VaultJournal::new` itself, or mint a second sink so the backend
//!    fires one object while the journal arms another. The test below reads
//!    the crate's own sources and refuses both, and it is proven red against
//!    a planted violation rather than trusted.
//!
//! # What is deliberately *not* forced
//!
//! The non-paying commands — `restore`, `verify --live`, `status --upgrade`
//! — go on constructing their backend with
//! [`ReadOnly`](crate::backend::ReadOnly) and never need a session at all.
//! "This path does not pay" stays written down rather than omitted, which is
//! the same call `backend.rs` made for the sink argument itself.
//!
//! The test suites likewise keep `VaultJournal::new`: the red-direction rows
//! that prove the sink is doing work (`resume.rs`'s
//! `without_a_durable_sink_the_same_crash_re_pays_the_landed_sub_batches`,
//! S18's `case1c-RED`) exist precisely to build the sinkless pairing on
//! purpose. A rule that made the bypass unrepresentable would delete the
//! evidence that the fix matters.

use std::sync::Arc;

use rand_core::TryCryptoRng;

use crate::pipeline::VaultReceiptSink;
use crate::pipeline::vault_journal::VaultJournal;
use crate::vault::session::UnlockedVault;
use crate::vault::store::WorkStore;

/// One command's unlocked vault, paired with the D37 receipt sink that must
/// accompany it whenever that command can pay.
///
/// Hand [`receipts`](Self::receipts) to
/// [`SealBackend::connect`](crate::backend::SealBackend::connect) and drive
/// the pipeline over [`journal`](Self::journal): both name the same object,
/// so the sink the backend fires from inside `pay` is the sink the pipeline
/// armed with the drawn `seal_id`.
pub struct SealSession {
    vault: Arc<UnlockedVault>,
    receipts: Arc<VaultReceiptSink>,
}

impl std::fmt::Debug for SealSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The vault is deliberately absent: its `Debug` is redacted anyway,
        // and a session's interesting state is the sink's.
        f.debug_struct("SealSession")
            .field("receipts", &self.receipts)
            .finish_non_exhaustive()
    }
}

impl SealSession {
    /// Take ownership of an unlocked vault and mint its receipt sink.
    ///
    /// **By value on purpose.** The caller unlocks once and gives the vault
    /// up; from here on the only handle is this session's `Arc`.
    /// `UnlockedVault` stays `!Clone`, so there is still exactly one
    /// `VaultKey` in the process and it still zeroizes on its single drop —
    /// the `Arc` shares that one instance with the `'static` sink rather
    /// than copying any secret material (S31's constraint, unchanged).
    #[must_use]
    pub fn open(vault: UnlockedVault) -> Self {
        let vault = Arc::new(vault);
        let receipts = VaultReceiptSink::new(Arc::clone(&vault));
        Self { vault, receipts }
    }

    /// The unlocked vault, for the reads and writes that are not the
    /// journal's (the U34 bookkeeping record, D45's resume scan, U19's
    /// listing).
    #[must_use]
    pub fn vault(&self) -> &UnlockedVault {
        &self.vault
    }

    /// This session's sink, for
    /// [`SealBackend::connect`](crate::backend::SealBackend::connect).
    ///
    /// There is exactly one per session and no other way to obtain one on a
    /// paying path, so "the backend's sink" and "the journal's sink" cannot
    /// be two different objects.
    #[must_use]
    pub fn receipts(&self) -> Arc<VaultReceiptSink> {
        Arc::clone(&self.receipts)
    }

    /// A journal over this session's vault, **with the sink attached**.
    ///
    /// This is the whole point of the type: there is no second constructor,
    /// no `Option`, and no builder step to forget. A pipeline driven over
    /// this journal arms the sink on every path that can pay.
    #[must_use]
    pub fn journal<'v, R: TryCryptoRng + ?Sized>(&'v self, rng: &'v mut R) -> VaultJournal<'v, R> {
        VaultJournal::new(WorkStore::new(&self.vault), rng).with_receipt_sink(self.receipts())
    }
}

/// Files under `dir` (recursively) whose **production** source names
/// `needle`.
///
/// "Production" means the part of each file before its first `#[cfg(test)]`
/// line: the suites name both forms on purpose (the red-direction rows are
/// built out of exactly the pairing this scan forbids), and a rule that
/// could not tell the two apart would either delete that evidence or be
/// switched off the first time it fired.
///
/// Returned paths are relative to `dir` and sorted, so an assertion failure
/// names the offending file rather than a count. Pure and directory-taking
/// so the scan itself can be proven red against a planted violation.
#[cfg(test)]
fn production_files_naming(dir: &std::path::Path, needle: &str) -> (Vec<String>, usize) {
    let mut named = Vec::new();
    let mut visited = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                visited += 1;
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let production = match text.find("#[cfg(test)]") {
                    Some(at) => &text[..at],
                    None => &text[..],
                };
                if production.contains(needle) {
                    named.push(
                        path.strip_prefix(dir)
                            .unwrap_or(&path)
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
        }
    }
    named.sort();
    (named, visited)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{SealSession, production_files_naming};
    use crate::pipeline::journal::SealJournal;
    use crate::vault::kdf::KdfSelection;
    use crate::vault::layout::VaultLayout;
    use crate::vault::session::{create_vault, unlock_vault};

    /// NON-SECRET test passphrase.
    fn passphrase() -> antseal_core::crypto::secrets::SecretBuf {
        antseal_core::crypto::secrets::SecretBuf::new(b"seal-session-test-passphrase".to_vec())
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "antseal-s36-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("mk dir");
        dir
    }

    fn src_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    /// **S36's type layer, exercised rather than asserted by reading.** A
    /// journal obtained from a session arms the session's sink — so a
    /// receipt captured through the backend's hook lands in the work record
    /// the pipeline named, with no builder call in between.
    #[test]
    fn a_session_journal_arms_the_session_sink() {
        use antseal_core::crypto::secrets::{MasterSecret, SealId};
        use antseal_net::{GasSummary, PaymentReceipt};

        use crate::pipeline::journal::WorkIdentity;
        use crate::vault::store::{SealShapingFlags, WorkStore};

        let dir = temp_dir("armed");
        let layout = VaultLayout::at(dir.join("vault"));
        let mut rng = crate::rng::OsEntropy;
        create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng).expect("create");
        let session = SealSession::open(unlock_vault(&layout, &passphrase()).expect("unlock"));

        let seal_id = SealId::generate(&mut rng).expect("seal id");
        let w = MasterSecret::generate(&mut rng).expect("W");
        {
            let mut rng = crate::rng::OsEntropy;
            let journal = session.journal(&mut rng);
            journal
                .begin(&WorkIdentity {
                    seal_id,
                    w: w.secret_ref(),
                    network: "devnet".to_owned(),
                    degraded: false,
                    unanchored: true,
                    input_paths_as_given: vec!["a.txt".to_owned()],
                    input_paths_absolute: vec!["/w/a.txt".to_owned()],
                    shaping: SealShapingFlags::default(),
                })
                .expect("begin");
            // What the pipeline does immediately before every `pay`.
            journal.arm_receipts(&seal_id, None);
        }

        // What the backend's hook does from inside `pay`. Nothing else
        // happens in between — no builder call, no second handle.
        session.receipts().capture(&PaymentReceipt {
            blobs: Vec::new(),
            tx_map: std::collections::BTreeMap::new(),
            txs: Vec::new(),
            storage_cost_atto: 7_777,
            gas: GasSummary { gas_cost_wei: 0 },
        });

        assert_eq!(session.receipts().writes(), 1);
        assert_eq!(session.receipts().fault(), None);
        let mut rng = crate::rng::OsEntropy;
        let reader = crate::pipeline::VaultJournal::new(WorkStore::new(session.vault()), &mut rng);
        assert_eq!(
            reader
                .receipt(&seal_id)
                .expect("read")
                .expect("the capture was journaled — the session's journal armed the sink")
                .storage_cost_atto,
            7_777
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The vault key's lifetime is unchanged by the pairing: the session
    /// owns the only `UnlockedVault`, shares it with the `'static` sink, and
    /// both die together when the command ends.
    #[test]
    fn a_session_holds_exactly_two_handles_to_one_vault() {
        let dir = temp_dir("lifetime");
        let layout = VaultLayout::at(dir.join("vault"));
        let mut rng = crate::rng::OsEntropy;
        create_vault(&layout, &passphrase(), KdfSelection::Argon2id, &mut rng).expect("create");
        let session = SealSession::open(unlock_vault(&layout, &passphrase()).expect("unlock"));

        // The session's own `Arc` plus the sink's — no more. A third would
        // mean something outlives the command holding the vault key.
        assert_eq!(Arc::strong_count(&session.vault), 2);
        let handed_out = session.receipts();
        assert_eq!(
            Arc::strong_count(&session.vault),
            2,
            "handing the sink to the backend must not clone the vault"
        );
        drop(handed_out);
        drop(session);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **S36's scan layer, first half.** A sinkless journal is nameable in
    /// production sources in exactly one place — this module, where the
    /// sink is attached in the same expression.
    ///
    /// The bypass this closes is a hurried future command building its own
    /// journal: it compiles, it runs, and a crash between sub-batch txs
    /// re-pays. That is not a compile error anywhere, so it has to be a
    /// failing test.
    #[test]
    fn the_sinkless_journal_constructor_is_named_in_exactly_one_production_file() {
        let (named, visited) = production_files_naming(&src_dir(), "VaultJournal::new(");
        assert!(
            visited > 20,
            "the scan visited only {visited} source files — it is not looking where it thinks"
        );
        assert_eq!(
            named,
            vec!["seal_session.rs".to_owned()],
            "`VaultJournal::new` builds a journal with NO D37 receipt sink. A paying path that \
             uses one gets the pre-S31 tree back: the capture hook fires, nothing durable \
             happens, and a crash between sub-batch txs pays for the landed sub-batches a \
             second time (S36). Go through `SealSession::journal`, which cannot omit the sink"
        );
    }

    /// **S36's scan layer, second half.** Exactly one production file mints
    /// a sink, so the object the backend fires and the object the pipeline
    /// arms cannot drift apart.
    ///
    /// The first half alone does not close this: a command could take its
    /// journal from a session and still hand
    /// `SealBackend::connect` a *second*, freshly-minted sink. Every capture
    /// would then be written by a sink nobody ever armed — recorded as
    /// [`ReceiptSinkFault::NotArmed`](crate::pipeline::ReceiptSinkFault::NotArmed),
    /// and nothing durable on disk.
    #[test]
    fn the_receipt_sink_is_minted_in_exactly_one_production_file() {
        let (named, visited) = production_files_naming(&src_dir(), "VaultReceiptSink::new(");
        assert!(visited > 20, "the scan visited only {visited} source files");
        assert_eq!(
            named,
            vec!["seal_session.rs".to_owned()],
            "a second `VaultReceiptSink` means the backend fires one object while the pipeline \
             arms another, so every capture is written by a sink that was never told which work \
             it belongs to (S36). One session, one sink: `SealSession::receipts`"
        );
    }

    /// **The scan proven red.** Both rows above are only worth their verdict
    /// if the scan can fail; run it against a planted violation and a
    /// deliberately-exempt test module, and check it reports the first and
    /// ignores the second.
    #[test]
    fn the_scan_reports_a_planted_violation_and_ignores_test_modules() {
        let dir = temp_dir("scan-red");
        std::fs::create_dir_all(dir.join("nested")).expect("mk nested");
        std::fs::write(dir.join("clean.rs"), "fn ok() { let _ = 1; }\n").expect("write");
        // The violation: a command building its own sinkless journal.
        std::fs::write(
            dir.join("nested").join("hurried_command.rs"),
            "fn seal() { let j = VaultJournal::new(store, rng); }\n",
        )
        .expect("write");
        // The exemption: the same expression, but inside a test module —
        // which is where the red-direction rows legitimately live.
        std::fs::write(
            dir.join("red_row.rs"),
            "fn prod() {}\n#[cfg(test)]\nmod tests {\n let j = VaultJournal::new(s, r);\n}\n",
        )
        .expect("write");
        // Not Rust: the scan must not read it at all.
        std::fs::write(dir.join("notes.md"), "VaultJournal::new(\n").expect("write");

        let (named, visited) = production_files_naming(&dir, "VaultJournal::new(");
        assert_eq!(
            visited, 3,
            "three .rs files, and the .md is not one of them"
        );
        assert_eq!(
            named,
            vec!["nested/hurried_command.rs".to_owned()],
            "the scan must catch the planted violation, must not catch the test-module use, and \
             must name the file it found"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
