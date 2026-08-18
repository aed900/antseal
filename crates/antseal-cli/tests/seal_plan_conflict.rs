//! D24 §1's `--split` x `--no-fine-tree` refusal, through the **binary**
//! (U82, decision [D149] §2 R10 T7).
//!
//! # Why this suite exists at all, when the unit tests already cover the rule
//!
//! `crates/antseal-cli/src/seal_plan.rs`'s own test module drives
//! `build_plan` directly and pins the message, the class and the exit code.
//! What it cannot pin is the **venue**, and the venue is the whole of D24
//! rationale 1: *"re-running a failed command costs seconds"* is a claim
//! about a refusal that fires before the vault lock, before the passphrase
//! prompt and before the network connect. Called directly, `build_plan`
//! answers identically wherever it is called from.
//!
//! U82's original Accept row asked for *"a test that asserts zero backend
//! calls"*. That assertion could not fail: `build_plan` takes
//! `(&SealArgs, NetworkId, &Path)` and no backend is in scope. D149 §2 R10
//! replaces it with this one, which discriminates by **outcome per venue**:
//! run into a `HOME` with no vault at all, the refusal must be **27**, and
//! the same check misplaced one layer down answers something else in every
//! build —
//!
//! | check lives in | default build | `--features ant-backend` |
//! | --- | --- | --- |
//! | `build_plan` (correct) | **27** | **27** |
//! | `run_seal` / `Pipeline::seal` | 23, the storage seam | 2, *"no vault exists"* |
//!
//! — because both of those sit downstream of `open_layout()`
//! (`commands.rs`, kept first by U73) on the feature build and downstream of
//! the backend seam on the default one. So a green here is evidence about
//! ordering, not merely about the message.
//!
//! # Why not `seal_command.rs`
//!
//! That suite is `--split`-free by construction and owns the U13/U14 command
//! layer. This is one decision's refusal with two live arms; it gets its own
//! file so the negative control sits beside the positive.
//!
//! NON-SECRET: every fixture byte string is documented at its site.
//!
//! [D149]: ../../../docs/decisions/D149-split-x-no-fine-tree-the-abort-and-its-read.md

#[path = "common/spawn.rs"]
mod spawn;

use std::path::PathBuf;

use antseal_cli::backend::BackendArm;

/// A scratch work directory that removes itself.
struct Work {
    dir: PathBuf,
    home: PathBuf,
}

impl Work {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "antseal-d24-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        // A `HOME` with **no vault in it**: any code that reached the vault
        // would fail loudly and distinctly rather than pass by accident.
        let home = dir.join("home");
        std::fs::create_dir_all(&home).expect("mk work dir");
        Self { dir, home }
    }

    fn file(&self, name: &str, bytes: &[u8]) -> &Self {
        std::fs::write(self.dir.join(name), bytes).expect("write fixture file");
        self
    }

    /// `antseal <args>` against this work, with Q16's anchor-network gate
    /// armed by the shared helper and `RUST_LOG` cleared so a developer's
    /// exported filter cannot change what stderr carries.
    fn run(&self, args: &[&str]) -> (Option<i32>, String) {
        let out = spawn::antseal()
            .env_remove("RUST_LOG")
            .current_dir(&self.dir)
            .env("HOME", &self.home)
            .args(args)
            .output()
            .expect("spawn antseal");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What a `seal` plan that *passes* validation meets next, into a
/// vault-less `HOME`: this build's exit code. Neither arm is 27, which is
/// what makes the negative control below able to fail.
fn next_stage_for_a_valid_seal_plan() -> i32 {
    match BackendArm::THIS_BUILD {
        // No adapter exists, so the storage seam refuses.
        BackendArm::NotCompiled => 23,
        // The adapter exists, so the honest next answer is the vault this
        // HOME does not have (`open_layout()`, kept first by U73).
        BackendArm::Compiled => 2,
    }
}

/// **T7.** The refusal is reachable from a bare binary with no vault, no
/// network and no passphrase — which is only true if it is raised in plan
/// validation.
#[test]
fn the_conflict_is_refused_before_the_vault_the_passphrase_and_the_connect() {
    // NON-SECRET fixture: two blank-line-separated ASCII paragraphs, so the
    // file is unambiguously text under `is_text` (strict UTF-8) and
    // `--split blank-lines` has something to cut.
    let work = Work::new("t7");
    work.file("notes.txt", b"para one\n\npara two\n");

    // D149 §1.1's own M1 invocation, plus an explicit network so the
    // `--no-anchor` x `arbitrum-one` guard — the *other* producer of 27 in
    // this function — cannot be what answers.
    let (code, stderr) = work.run(&[
        "seal",
        "--split",
        "blank-lines",
        "--no-fine-tree",
        "notes.txt",
        "notes.txt",
        "--network",
        "devnet",
    ]);

    assert_eq!(
        code,
        Some(27),
        "the {} arm must refuse in build_plan, not downstream of the vault \
         (a misplaced check answers {}): {stderr}",
        BackendArm::THIS_BUILD.name(),
        next_stage_for_a_valid_seal_plan()
    );
    // The code alone would also be produced by a D46 argument problem, so
    // pin the sentence. `is selected for splitting` is the file-name slot;
    // asserting the bare path would be satisfied by the pattern half of the
    // same message.
    assert!(
        stderr.contains("notes.txt is selected for splitting"),
        "{stderr}"
    );
    assert!(stderr.contains("--split blank-lines"), "{stderr}");
    assert!(stderr.contains("--no-fine-tree notes.txt"), "{stderr}");
    assert!(
        stderr.contains("Seal it as a separate work without --split"),
        "{stderr}"
    );
    // Nothing downstream was reached: neither refusal's own words appear.
    assert!(!stderr.contains("no vault exists"), "{stderr}");
    assert!(!stderr.contains("storage backend compiled in"), "{stderr}");
}

/// The negative control, live: D24 §1 exempts binary matches (G6), so
/// `--split blank-lines --no-fine-tree '*.dat'` over a genuinely
/// invalid-UTF-8 file must reach the next stage rather than be refused.
///
/// The fixture is `0xFF` bytes under a name that is **not** `.bin`: NUL
/// padding and ASCII headers are valid UTF-8, so neither a `.bin` name nor
/// a zero-filled file proves anything about text-ness (D149 §1.5).
#[test]
fn a_binary_match_under_split_still_reaches_the_next_stage() {
    let work = Work::new("t7-binary");
    work.file("notes.txt", b"para one\n\npara two\n");
    work.file("opaque.dat", &[0xFFu8; 64]);

    let (code, stderr) = work.run(&[
        "seal",
        "notes.txt",
        "opaque.dat",
        "--split",
        "blank-lines",
        "--no-fine-tree",
        "*.dat",
        "--network",
        "devnet",
    ]);

    assert!(
        !stderr.contains("is selected for splitting"),
        "a binary match is not a D24 §1 conflict (G6): {stderr}"
    );
    assert_eq!(
        code,
        Some(next_stage_for_a_valid_seal_plan()),
        "an exempt plan must reach the {} arm's next gate: {stderr}",
        BackendArm::THIS_BUILD.name()
    );
}
