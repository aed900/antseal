//! U76 — end-to-end proof that D73 §4 R5 **X2** is runnable, over the
//! **compiled** `metric-vault-fp` binary rather than over a copy of its
//! logic.
//!
//! # Why this drives the process and not a function
//!
//! U76's defect was never that a fingerprint could not be computed — it was
//! that *no command printed the value*, so X2 *"cannot be run with the
//! shipped binaries, by anyone"*. A test that called a Rust function would
//! reproduce exactly the state U76 describes: a reachable value with no
//! route. So every assertion here goes through `Command::new(BIN)`, which is
//! the artifact a maintainer actually runs against submitted bundles.
//!
//! The bin's own `#[cfg(test)] mod tests` covers the construction in
//! process (salt reaches the digest, tag reaches the digest, a signatures
//! map is refused, both salt-file shapes parse). This file covers the parts
//! only a process can show: the printed form, the exit-code taxonomy, the
//! collision grouping, and that nothing key-shaped reaches stdout or stderr.
//!
//! # Both directions, because a collision-only test would pass on a stub
//!
//! `always_return("aaaaaaaaaaaaaaaa")` collapses every pair of bundles and
//! would satisfy any test that only checked the collision. Every collapse
//! assertion here is therefore paired with a separation assertion over the
//! *same* run.
//!
//! Gated on `test-util` because that is what the bin's `required-features`
//! names: without it cargo does not build the target and
//! `CARGO_BIN_EXE_metric-vault-fp` does not exist.

#![cfg(all(feature = "test-util", not(target_arch = "wasm32")))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use antseal_core::bundle::SealProof;
use antseal_core::crypto::error::SigAlg;
use antseal_core::test_util::bundle_fixtures::{self, Selection, shapes};

/// The compiled tool. `env!` rather than a hand-built path: cargo defines
/// this only when the target was actually built, so a stale or absent
/// binary is a compile error rather than a silently skipped test.
const BIN: &str = env!("CARGO_BIN_EXE_metric-vault-fp");

/// D73 §4 R7 fixes the rendered width at 16 hex characters.
const FP_HEX_LEN: usize = 16;

const EXIT_DISTINCT: i32 = 0;
const EXIT_ERROR: i32 = 1;
const EXIT_X2_FIRED: i32 = 2;

// ---------------------------------------------------------------------------
// scratch fixtures
// ---------------------------------------------------------------------------

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "antseal-u76-e2e-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self { dir }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, bytes).expect("write fixture");
        path
    }

    /// A salt file at mode 600. The value is a labelled fixture constant,
    /// **not** a metric salt: project rule 6 keeps real secret material out
    /// of fixtures, and D73 R7's salt is generated once by the maintainer
    /// and never committed.
    fn salt_file(&self, name: &str, fill: u8) -> PathBuf {
        let path = self.write(name, &[fill; 32]);
        chmod_600(&path);
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn chmod_600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Two `.sealproof` byte strings from the **one** fixture vault: different
/// works, different bytes, different `work_id` — D73 R5 X7's *"two bundles
/// produced from a single vault, submitted as if from two participants"*.
fn one_vault_pair() -> (Vec<u8>, Vec<u8>) {
    let first_spec = shapes::single_binary().with_seed(11);
    let second_spec = shapes::multi_file().with_seed(22);
    let first = bundle_fixtures::build(&first_spec, &Selection::all(first_spec.files.len()));
    let second = bundle_fixtures::build(&second_spec, &Selection::all(second_spec.files.len()));
    assert_ne!(
        first.bytes, second.bytes,
        "the planted pair is byte-identical, so a collapse would prove nothing"
    );
    assert_ne!(
        work_id_of(&first.bytes),
        work_id_of(&second.bytes),
        "the planted pair shares a work_id, so X3 would strike before X2 could"
    );
    (first.bytes, second.bytes)
}

fn work_id_of(bytes: &[u8]) -> [u8; 32] {
    let proof = SealProof::decode(bytes).expect("fixture decodes");
    antseal_core::manifest::work_id(proof.manifest().body_bytes()).into_bytes()
}

fn ed25519_pubkey(bytes: &[u8]) -> Vec<u8> {
    let proof = SealProof::decode(bytes).expect("fixture decodes");
    proof
        .manifest()
        .body()
        .pubkeys()
        .get(SigAlg::Ed25519)
        .expect("hybrid policy carries an Ed25519 key")
        .to_vec()
}

/// `bytes` with one byte of the embedded Ed25519 public key changed — a
/// bundle that still decodes and reports a **different** vault.
///
/// Deliberately a second, independent implementation of the bin's own
/// `mutate_ed25519_pubkey`: if the two ever disagree about where the key
/// lives, this file reds rather than agreeing with a bug.
fn as_second_vault(bytes: &[u8]) -> Vec<u8> {
    let needle = ed25519_pubkey(bytes);
    let hits: Vec<usize> = bytes
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle.as_slice())
        .map(|(offset, _)| offset)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "the Ed25519 public key occurs {} times; the mutation site is ambiguous",
        hits.len()
    );
    let mut out = bytes.to_vec();
    out[hits[0]] ^= 0x01;
    assert_ne!(
        ed25519_pubkey(&out),
        needle,
        "the mutation did not change the key the tool reads"
    );
    out
}

// ---------------------------------------------------------------------------
// running the tool
// ---------------------------------------------------------------------------

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    raw_stdout: Vec<u8>,
    raw_stderr: Vec<u8>,
}

fn run(args: &[&Path]) -> Run {
    let mut command = Command::new(BIN);
    for arg in args {
        command.arg(arg);
    }
    let Output {
        status,
        stdout,
        stderr,
    } = command.output().expect("the tool runs");
    Run {
        code: status
            .code()
            .expect("the tool exits rather than signalling"),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        raw_stdout: stdout,
        raw_stderr: stderr,
    }
}

fn run_str(args: &[&str]) -> Run {
    run(&args.iter().map(Path::new).collect::<Vec<_>>())
}

/// The 16-hex fingerprint the tool printed for `path`, from its own output.
fn fingerprint_for(output: &str, path: &Path) -> String {
    let needle = path.display().to_string();
    let line = output
        .lines()
        .find(|line| line.ends_with(&needle))
        .unwrap_or_else(|| panic!("no line for {needle} in:\n{output}"));
    let field = line
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("empty line for {needle}"));
    assert_eq!(
        field.len(),
        FP_HEX_LEN,
        "D73 R7 fixes 16 hex characters, got {field:?}"
    );
    assert!(
        field
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "fingerprint is not lowercase hex: {field:?}"
    );
    field.to_owned()
}

// ---------------------------------------------------------------------------
// the two directions, in one run
// ---------------------------------------------------------------------------

/// **X2 runs end to end, both ways.** This is `Accept` row 1 in one test:
/// two bundles from one vault collapse, and a bundle from another vault does
/// not — measured over the same invocation, so a stub that always collapses
/// and a stub that never collapses both fail it.
#[test]
fn two_bundles_from_one_vault_collapse_and_a_third_from_another_does_not() {
    let scratch = Scratch::new("both-directions");
    let (first, second) = one_vault_pair();
    let other_vault = as_second_vault(&first);

    let a = scratch.write("a.sealproof", &first);
    let b = scratch.write("b.sealproof", &second);
    let c = scratch.write("c.sealproof", &other_vault);
    let salt = scratch.salt_file("salt.bin", 0x5A);

    let result = run(&[Path::new("--salt-file"), &salt, &a, &b, &c]);
    assert_eq!(
        result.code, EXIT_X2_FIRED,
        "X2 must fire on the planted duplicate.\nstdout:\n{}\nstderr:\n{}",
        result.stdout, result.stderr
    );

    let fp_a = fingerprint_for(&result.stdout, &a);
    let fp_b = fingerprint_for(&result.stdout, &b);
    let fp_c = fingerprint_for(&result.stdout, &c);

    // Direction 1 — the collapse.
    assert_eq!(
        fp_a, fp_b,
        "two bundles from one vault reported different vault_fp; X2 cannot \
         collapse what it cannot recognise"
    );
    // Direction 2 — the separation. Without this the test passes on a stub.
    assert_ne!(
        fp_a, fp_c,
        "a bundle carrying a different sealer public key reported the same \
         vault_fp ({fp_a}); the column cannot distinguish participants"
    );

    // The report must name the colliding pair and must NOT name the third.
    assert!(
        result.stdout.contains("X2 FIRED"),
        "the verdict is not stated in the output:\n{}",
        result.stdout
    );
    let verdict = result
        .stdout
        .split("X2 FIRED")
        .nth(1)
        .expect("verdict section");
    let group = verdict
        .lines()
        .find(|line| line.trim_start().starts_with(&fp_a))
        .unwrap_or_else(|| panic!("no collision group for {fp_a} in:\n{verdict}"));
    assert!(
        group.contains(&a.display().to_string()) && group.contains(&b.display().to_string()),
        "the collision group does not name both submissions: {group}"
    );
    assert!(
        !verdict.contains(&c.display().to_string()),
        "the third bundle was reported as part of a collapse: {verdict}"
    );
}

/// Two bundles that are **not** one vault must exit clean, with no verdict
/// section at all. The mirror of the test above: if `EXIT_X2_FIRED` were
/// returned unconditionally, that test would still pass and this one would
/// not.
#[test]
fn two_bundles_from_different_vaults_exit_clean() {
    let scratch = Scratch::new("distinct");
    let (first, _) = one_vault_pair();
    let other_vault = as_second_vault(&first);

    let a = scratch.write("a.sealproof", &first);
    let c = scratch.write("c.sealproof", &other_vault);
    let salt = scratch.salt_file("salt.bin", 0x5A);

    let result = run(&[Path::new("--salt-file"), &salt, &a, &c]);
    assert_eq!(
        result.code, EXIT_DISTINCT,
        "distinct vaults must not fire X2.\nstdout:\n{}\nstderr:\n{}",
        result.stdout, result.stderr
    );
    assert!(
        !result.stdout.contains("X2 FIRED"),
        "a verdict was reported for distinct vaults:\n{}",
        result.stdout
    );
    assert_ne!(
        fingerprint_for(&result.stdout, &a),
        fingerprint_for(&result.stdout, &c)
    );
}

// ---------------------------------------------------------------------------
// project rule 6 — nothing key-shaped, and nothing salt-shaped, gets out
// ---------------------------------------------------------------------------

/// `Accept` row 3, measured rather than asserted: no raw key byte and no
/// raw salt byte reaches stdout or stderr, in either the clean or the
/// verdict path, and neither does their hex rendering.
#[test]
fn no_key_bytes_and_no_salt_bytes_reach_the_output() {
    let scratch = Scratch::new("no-leak");
    let (first, second) = one_vault_pair();
    let a = scratch.write("a.sealproof", &first);
    let b = scratch.write("b.sealproof", &second);
    let salt_fill = 0x3Cu8;
    let salt = scratch.salt_file("salt.bin", salt_fill);
    let salt_bytes = [salt_fill; 32];

    let result = run(&[Path::new("--salt-file"), &salt, &a, &b]);
    assert_eq!(
        result.code, EXIT_X2_FIRED,
        "the leak check needs the verdict path, and X2 did not fire.\nstdout:\n{}\nstderr:\n{}",
        result.stdout, result.stderr
    );

    let ed = ed25519_pubkey(&first);
    let proof = SealProof::decode(&first).expect("decodes");
    let mldsa = proof
        .manifest()
        .body()
        .pubkeys()
        .get(SigAlg::MlDsa65)
        .expect("hybrid policy carries an ML-DSA key")
        .to_vec();

    // Guard the guard: the needles must be long enough that finding one
    // would be meaningful, and short enough to be findable if leaked.
    assert_eq!(ed.len(), 32, "Ed25519 public keys are 32 bytes");
    assert!(mldsa.len() > 1000, "ML-DSA-65 public keys are 1952 bytes");

    for (label, needle) in [
        ("ed25519 pubkey", ed.as_slice()),
        ("ml-dsa pubkey", &mldsa[..64]),
        ("salt", salt_bytes.as_slice()),
    ] {
        for (stream, raw) in [
            ("stdout", &result.raw_stdout),
            ("stderr", &result.raw_stderr),
        ] {
            assert!(!contains(raw, needle), "{label} bytes reached {stream}");
            assert!(
                !text_of(raw).contains(&hex(needle)),
                "{label} hex reached {stream}"
            );
        }
    }

    // And the positive half: the thing that *is* supposed to be there is.
    assert_eq!(fingerprint_for(&result.stdout, &a).len(), FP_HEX_LEN);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn text_of(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// determinism, and the refusal taxonomy
// ---------------------------------------------------------------------------

/// One vault, one fingerprint, across separate processes. A per-run value —
/// a random salt, a timestamp, an address — would make every row distinct
/// and X2 unable to fire at all.
#[test]
fn the_fingerprint_is_stable_across_processes() {
    let scratch = Scratch::new("stable");
    let (first, _) = one_vault_pair();
    let a = scratch.write("a.sealproof", &first);
    let salt = scratch.salt_file("salt.bin", 0x77);

    let one = run(&[Path::new("--salt-file"), &salt, &a]);
    let two = run(&[Path::new("--salt-file"), &salt, &a]);
    assert_eq!(one.code, EXIT_DISTINCT);
    assert_eq!(two.code, EXIT_DISTINCT);
    assert_eq!(
        one.stdout, two.stdout,
        "two runs over one bundle disagreed; the fingerprint is not a pure \
         function of (salt, pubkeys)"
    );
}

/// The same bundle under two different salts must fingerprint differently,
/// end to end. This is what makes the committed metric sheet unlinkable to
/// any other salted table, and it is the process-level half of the bin's own
/// `the_salt_reaches_the_fingerprint`.
#[test]
fn a_different_salt_gives_a_different_fingerprint() {
    let scratch = Scratch::new("salted");
    let (first, _) = one_vault_pair();
    let a = scratch.write("a.sealproof", &first);
    let salt_one = scratch.salt_file("one.bin", 0x01);
    let salt_two = scratch.salt_file("two.bin", 0x02);

    let one = run(&[Path::new("--salt-file"), &salt_one, &a]);
    let two = run(&[Path::new("--salt-file"), &salt_two, &a]);
    assert_ne!(
        fingerprint_for(&one.stdout, &a),
        fingerprint_for(&two.stdout, &a),
        "the salt does not reach the fingerprint"
    );
}

/// Three failure classes, three distinct messages, all on exit 1 — and
/// crucially **not** on exit 2, so an operational failure can never be read
/// as an X2 verdict.
#[test]
fn every_refusal_is_exit_one_with_its_own_message() {
    let scratch = Scratch::new("refusals");
    let (first, _) = one_vault_pair();
    let a = scratch.write("a.sealproof", &first);
    let salt = scratch.salt_file("salt.bin", 0x5A);
    let junk = scratch.write("junk.sealproof", b"not a bundle at all");

    let missing_salt = run(&[&a]);
    assert_eq!(
        missing_salt.code, EXIT_ERROR,
        "a missing --salt-file must be exit 1, never an X2 verdict: {}",
        missing_salt.stderr
    );
    assert!(
        missing_salt.stderr.contains("--salt-file is required"),
        "unhelpful: {}",
        missing_salt.stderr
    );

    let no_bundles = run(&[Path::new("--salt-file"), &salt]);
    assert_eq!(
        no_bundles.code, EXIT_ERROR,
        "an empty bundle list must be exit 1, never an X2 verdict: {}",
        no_bundles.stderr
    );
    assert!(
        no_bundles.stderr.contains("no bundles given"),
        "unhelpful: {}",
        no_bundles.stderr
    );

    let bad_bundle = run(&[Path::new("--salt-file"), &salt, &junk]);
    assert_eq!(
        bad_bundle.code, EXIT_ERROR,
        "a malformed bundle must not be reported as an X2 verdict"
    );
    assert!(
        bad_bundle.stderr.contains("not a decodable .sealproof")
            && bad_bundle.stderr.contains(&junk.display().to_string()),
        "the refusal must name the file and the class: {}",
        bad_bundle.stderr
    );

    let unknown_flag = run_str(&["--vault-fp"]);
    assert_eq!(
        unknown_flag.code, EXIT_ERROR,
        "an unknown option must be exit 1, never an X2 verdict: {}",
        unknown_flag.stderr
    );
    assert!(
        unknown_flag.stderr.contains("unknown option --vault-fp"),
        "unhelpful: {}",
        unknown_flag.stderr
    );

    for result in [&missing_salt, &no_bundles, &bad_bundle, &unknown_flag] {
        assert_ne!(
            result.code, EXIT_X2_FIRED,
            "an operational failure used the X2 exit code"
        );
    }
}

/// A salt file anyone on the machine can read voids R6.4's privacy promise
/// silently. It is refused, and the refusal names the mode without quoting
/// a byte of the file.
#[cfg(unix)]
#[test]
fn a_world_readable_salt_file_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = Scratch::new("salt-mode");
    let (first, _) = one_vault_pair();
    let a = scratch.write("a.sealproof", &first);
    let salt = scratch.salt_file("salt.bin", 0x5A);
    std::fs::set_permissions(&salt, std::fs::Permissions::from_mode(0o644)).expect("chmod");

    let result = run(&[Path::new("--salt-file"), &salt, &a]);
    assert_eq!(
        result.code, EXIT_ERROR,
        "a 0644 salt file was not refused; R6.4's privacy promise is void whenever \
         the salt is readable by anyone on the machine.\nstdout:\n{}\nstderr:\n{}",
        result.stdout, result.stderr
    );
    assert!(
        result.stderr.contains("readable by group or other") && result.stderr.contains("0644"),
        "the refusal must name the problem and the mode: {}",
        result.stderr
    );
    assert!(
        result.stdout.is_empty(),
        "a fingerprint was printed despite the refusal: {}",
        result.stdout
    );
}

// ---------------------------------------------------------------------------
// D73 §4 R5 X7 — the instrument on itself, through the process
// ---------------------------------------------------------------------------

/// X7 is *"the plant-a-fault rule, and it is not optional"*. The binary
/// carries its own planted-duplicate run so a maintainer can produce the
/// record R7's header block demands without hand-building bundles; this
/// asserts that run passes and reports both directions.
#[test]
fn the_self_test_runs_x7_and_reports_both_directions() {
    let result = run_str(&["--self-test"]);
    assert_eq!(
        result.code, EXIT_DISTINCT,
        "X7's planted-duplicate run failed.\nstdout:\n{}\nstderr:\n{}",
        result.stdout, result.stderr
    );
    for expected in [
        "X2 FIRED",
        "X2 did NOT fire across vaults",
        "SELF-TEST PASSED",
        "docs/success-metric.md",
    ] {
        assert!(
            result.stdout.contains(expected),
            "the transcript is missing {expected:?}:\n{}",
            result.stdout
        );
    }
    // It must need neither a salt file nor a bundle, or a maintainer cannot
    // run it before the first submission arrives.
    assert!(result.stderr.is_empty(), "stderr: {}", result.stderr);
}

/// `--self-test` must refuse to be mixed with a real run, so a transcript
/// pasted into the metric sheet can never be a mixture of fixture output and
/// submission output.
#[test]
fn the_self_test_refuses_to_be_mixed_with_a_real_run() {
    let scratch = Scratch::new("mixed");
    let salt = scratch.salt_file("salt.bin", 0x5A);
    let result = run(&[Path::new("--self-test"), Path::new("--salt-file"), &salt]);
    assert_eq!(
        result.code, EXIT_ERROR,
        "--self-test mixed with a real run must be refused: {}",
        result.stderr
    );
    assert!(
        result.stderr.contains("--self-test takes no salt file"),
        "unhelpful: {}",
        result.stderr
    );
}
