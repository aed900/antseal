//! `metric-vault-fp` — the distinctness instrument D73 §4 R5 **X2** reads.
//!
//! # Why this binary exists (U76)
//!
//! D73 §4 R5 X2 collapses two success-metric rows that claim distinct
//! participants but carry the **same sealer public key**: they are one
//! vault, and they become one row. X2 reads manifest key 5 `pubkeys`
//! (`docs/format/registry-v1.md` §7.2 key 5 — the **section**, never a
//! line: the registry is frozen, its line numbers are not, and a rotted
//! pointer is silent). D73 §4 R5 **X7** then turns the instrument on
//! itself — *if X2 has never fired, the count may not be declared met*.
//!
//! That value is in every bundle and
//! [`ManifestBodyV1::pubkeys`](antseal_core::manifest::ManifestBodyV1::pubkeys)
//! exists to reach it, but **no shipped command printed it**: `show`'s
//! `--json` view never reaches the keys and `VerificationReport` carries
//! `signature_scheme` and no key bytes. So X2 could not be run, by anyone,
//! and by X7 the metric could not honestly be declared met.
//!
//! This is D73 §7 item 2's *"small maintainer-side tool over the library
//! accessor"*, and D73 §6 item 7 rules it **a tooling question, not a format
//! one**: nothing here changes a wire format, and D29's frozen `show` table
//! is untouched. The alternative arm — a real `show --json` field — was
//! **not taken**: it moves that frozen table and lands a new key in D65's
//! tier for a use case that is not a user's.
//!
//! # What it prints, and what it refuses to print
//!
//! A **fingerprint**, never key bytes. D73 §4 R7 calls the column `vault_fp`
//! and *opaque*, and D73 §4 R6.4 binds the project: `docs/success-metric.md`
//! *"carries no bundle, no public key, no `work_id`, no wallet address"*. A
//! metric sheet that published participants' raw public keys would be a
//! worse instrument than one that published a digest. Nothing in this
//! binary's output, and nothing in any of its error messages, contains key
//! bytes or salt bytes — only paths, lengths and fingerprints.
//!
//! # The construction
//!
//! ```text
//! VAULT_FP_DOMAIN = "antseal/d73/r7/vault-fp/v1\x00"
//!
//! preimage = VAULT_FP_DOMAIN
//!         ‖ salt                                  (32 B, secret, never committed)
//!         ‖ LE64(entry_count)
//!         ‖ for each (alg, key) in ascending wire order:
//!               LE64(sig_alg_to_wire(alg)) ‖ LE64(key.len()) ‖ key
//!
//! vault_fp = lowercase_hex(SHA-256(preimage)[0..8])      // 16 hex chars (R7)
//! ```
//!
//! **The domain tag is a string, not a registry byte, deliberately.** The
//! spec's one-byte tag registry is frozen at `0x00`–`0x06` (MVP-SPEC.md line
//! 79, [`antseal_core::crypto::domain`]) and a grep-enforced test stops any
//! other module hard-coding a tag byte — minting a new one would be a format
//! event, which D73 §6 item 7 says this is not. So this takes the tree's
//! *other* convention, the one already used for digests that are tooling
//! rather than wire format: an ASCII slash-path tag with a trailing NUL, the
//! shape of `vectors::RECOMPUTED_DIGEST_DOMAIN` and of
//! `R30_REPORT_DIGEST_DOMAIN`, whose comment states the same reason — it
//! *"must not collide with … any tag in the C1 registry (this is test
//! infrastructure, not wire format)"*. Its first byte is `b'a'` = `0x61`,
//! above `MAX_DOMAIN_TAG`, so it is disjoint from the spec registry **by
//! construction** — the identical argument [`antseal_core::crypto::domain`]
//! makes for `work_id` and `anchor_digest`.
//!
//! **Why a tag is load-bearing here specifically.** R7 gives `vault_fp` and
//! `work_fp` the **same** 32-byte salt. Untagged they would be
//! `SHA-256(salt ‖ x)` over two different value spaces under one key, which
//! is the cross-protocol confusion shape. With the tag, a `vault_fp`
//! preimage cannot be a `work_fp` preimage whatever the content.
//!
//! **Why every field is length-prefixed.** The tree's own stated reason, at
//! `R30_REPORT_DIGEST_DOMAIN`'s call site: *"both fields are length-prefixed
//! so no two (name, bytes) pairs can collide by concatenation."* Here the
//! entry count is bound and each `(alg, key)` pair carries its own width, so
//! no two different maps share a preimage. Ascending wire order is
//! [`SigAlgMap`]'s decode invariant, so the preimage is canonical: one vault
//! always yields one fingerprint.
//!
//! # Why no raw bytes can come back out
//!
//! The output is the first 8 bytes of a SHA-256 digest — **64 bits** — over
//! a preimage of at least ~2 kB (Ed25519's 32 B plus ML-DSA-65's 1952 B).
//! Recovery is not merely hard, it is information-theoretically unavailable.
//!
//! The realistic attack is not recovery but **confirmation**, and that is
//! what the salt is for. `antseal_core::crypto::confirmation_attack` states
//! the project's position: *"a bare hash `H(m)` is binding but not hiding
//! whenever `m` is guessable"* — and a candidate public key is exactly the
//! guessable kind, since anyone holding one bundle from a suspected
//! participant has it. Without a salt, a reader of a committed
//! `docs/success-metric.md` could hash a candidate key and confirm that
//! person took part. With a secret 32-byte salt in the preimage, that
//! computation is unavailable to them, which is what makes R6.4's privacy
//! promise real rather than nominal.
//!
//! Length extension is not a threat in this shape. `SHA-256(salt ‖ m)` is a
//! broken *MAC*, but nothing here is authenticated: an extension yields a
//! digest for a longer message of the attacker's choosing, which buys
//! nothing against an equality-only distinctness column. HMAC-SHA256 would
//! close the class outright and is the obvious upgrade if `vault_fp` ever
//! becomes something anyone relies on for authenticity; it is recorded here
//! and deliberately not taken, because it is a further divergence from R7's
//! stated formula than this row needs.
//!
//! # Collision margin, and why the truncation is safe
//!
//! 64 bits. For *n* rows the birthday collision probability is about
//! `n²/2^65`: at R1's target of ten rows, ≈2.7 × 10⁻¹⁸; at a thousand,
//! ≈2.7 × 10⁻¹⁴. R7 fixes the 16-hex width and this keeps it.
//!
//! The failure mode points the safe way. A collision makes X2 fire
//! *spuriously* and **collapse** two genuine participants — it deflates the
//! count. That is precisely the asymmetry R5 demands of X2: *"X2 can only
//! ever deflate an inflated count; it can never confirm a real one."* A
//! truncation that could inflate would be unacceptable; this one cannot.
//!
//! # Divergence from D73 §4 R7, stated rather than silent
//!
//! R7 writes `vault_fp = SHA-256(salt ‖ pubkeys-bytes)`. This implementation
//! differs in two ways, both recorded here so no later reader has to
//! re-derive them:
//!
//! 1. **The domain tag is prepended** (reasoning above).
//! 2. **`pubkeys-bytes` is pinned.** R7 does not say what those bytes *are*
//!    — envelope CBOR? the body sub-slice? the keys concatenated? — so any
//!    implementation whatever must choose, and an unrecorded choice is how
//!    two runs of "the same" fingerprint disagree. This one is the
//!    length-prefixed canonical enumeration above.
//!
//! Both change the digest R7's literal formula would produce. Nothing is
//! invalidated by that: `docs/success-metric.md` **does not exist yet** — it
//! is Q35's deliverable (D73 §7 item 1) — so no `vault_fp` value has ever
//! been published, and the property R7 actually needs is preserved exactly:
//! salted, opaque, 16 hex characters, equal **iff** same vault. This is
//! flagged for the registrar as a D73 dated-addendum candidate.
//!
//! # Venue
//!
//! `antseal-core`, behind `required-features = ["test-util"]`, following
//! `anchor-smoke-driver`. That feature is *"never enabled by any production
//! build"*, so this tool cannot reach a user's `PATH` or a signed release
//! artifact — D73 §7 item 2's *"a use case that is not a user's"*. It is
//! nevertheless in `local-gate.sh`'s `GATE_LIGHT_FEATURES`, so the required
//! gate compiles, lints and tests it every run and it cannot rot unseen.
//! `--self-test` genuinely needs the feature: it builds its planted
//! duplicate from `test_util::bundle_fixtures`.
//!
//! # Usage
//!
//! ```text
//! metric-vault-fp --salt-file <PATH> <BUNDLE.sealproof>...
//! metric-vault-fp --self-test
//! ```
//!
//! Exit codes: `0` every bundle distinct · `1` usage, I/O or decode failure
//! · `2` **X2 fired** — at least two bundles are one vault.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use antseal_core::bundle::SealProof;
use antseal_core::manifest::{SigAlgMap, SigMaterial, sig_alg_to_wire};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// the construction
// ---------------------------------------------------------------------------

/// The domain tag. See the module docs for why it is a string rather than a
/// byte from the frozen `crypto::domain` registry.
const VAULT_FP_DOMAIN: &[u8] = b"antseal/d73/r7/vault-fp/v1\x00";

/// D73 §4 R7: the metric salt is a single 32-byte random value, generated
/// once, held by the maintainer and never committed.
const SALT_LEN: usize = 32;

/// D73 §4 R7 truncates to 16 hex characters, i.e. the first 8 digest bytes.
const FP_BYTES: usize = 8;

/// Exit code: every submitted bundle carries a distinct `vault_fp`.
const EXIT_DISTINCT: u8 = 0;
/// Exit code: usage, I/O or decode failure. Says nothing about X2.
const EXIT_ERROR: u8 = 1;
/// Exit code: **X2 fired** — two or more submissions are one vault.
const EXIT_X2_FIRED: u8 = 2;

/// `vault_fp` for one `pubkeys` map, as 16 lowercase hex characters.
///
/// Refuses a [`SigMaterial::Signature`] map outright rather than
/// fingerprinting it: the two maps have the same Rust type, and a
/// distinctness column silently computed over *signatures* would vary per
/// bundle and make X2 unable to fire at all — a falsifier that certifies
/// whatever it is pointed at, which is the exact defect U76 exists to
/// remove.
fn vault_fp(salt: &[u8; SALT_LEN], pubkeys: &SigAlgMap) -> Result<String, ToolError> {
    if pubkeys.material() != SigMaterial::Pubkey {
        return Err(ToolError::WrongMaterial);
    }
    let mut digest = Sha256::new();
    digest.update(VAULT_FP_DOMAIN);
    digest.update(salt);
    digest.update(pubkeys.len().to_le_bytes());
    for (alg, key) in pubkeys.iter() {
        digest.update(sig_alg_to_wire(alg).to_le_bytes());
        digest.update((key.len() as u64).to_le_bytes());
        digest.update(key);
    }
    Ok(hex(&digest.finalize()[..FP_BYTES]))
}

/// Lowercase hex. Local rather than borrowed from `test_util`, so the
/// production path of this tool does not depend on a test-only helper.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` is infallible; the result is discarded
        // rather than unwrapped (`clippy::unwrap_used` is a warning here
        // and CI hardens it with `-D warnings`).
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// errors — paths, lengths and counts only; never key bytes, never salt bytes
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum ToolError {
    Usage(String),
    /// The salt file's mode lets somebody other than its owner read it.
    /// The mode is printed; the contents never are.
    SaltPermissions {
        path: PathBuf,
        mode: u32,
    },
    /// Wrong shape. Reports the observed **length**, never a byte of it.
    SaltShape {
        path: PathBuf,
        len: usize,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Decode {
        path: PathBuf,
        message: String,
    },
    WrongMaterial,
    /// `--self-test` found the instrument unable to do its job. The message
    /// names which of X7's directions failed.
    SelfTest(String),
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => write!(f, "{message}\n\n{USAGE}"),
            Self::SaltPermissions { path, mode } => write!(
                f,
                "salt file {} is readable by group or other (mode {mode:04o}); \
                 D73 R7 holds the metric salt privately — run `chmod 600 {}`",
                path.display(),
                path.display()
            ),
            Self::SaltShape { path, len } => write!(
                f,
                "salt file {}: expected {SALT_LEN} raw bytes or {} hex characters, found {len} bytes",
                path.display(),
                SALT_LEN * 2
            ),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Decode { path, message } => {
                write!(
                    f,
                    "{}: not a decodable .sealproof: {message}",
                    path.display()
                )
            }
            Self::WrongMaterial => f.write_str(
                "refusing to fingerprint a signatures map: vault_fp is defined over \
                 manifest key 5 `pubkeys` (D73 §4 R5 X2)",
            ),
            Self::SelfTest(message) => write!(f, "SELF-TEST FAILED: {message}"),
        }
    }
}

const USAGE: &str = "\
usage:
  metric-vault-fp --salt-file <PATH> <BUNDLE.sealproof>...
  metric-vault-fp --self-test
  metric-vault-fp --help

  --salt-file <PATH>  the D73 R7 metric salt: 32 raw bytes or 64 hex
                      characters. Owner-readable only (mode 600). Never
                      committed, never printed.
  --self-test         run D73 R5 X7's planted duplicate and prove X2 can
                      fire. Needs no salt file and no bundle.

exit codes:
  0  every bundle carries a distinct vault_fp
  1  usage, I/O or decode failure
  2  X2 FIRED - two or more submissions are one vault";

// ---------------------------------------------------------------------------
// argv
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    // `args_os`, not `args`: `args` panics on a non-UTF-8 argument, and a
    // maintainer's bundle path is not this tool's to validate.
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&argv) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("metric-vault-fp: {error}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run(argv: &[OsString]) -> Result<ExitCode, ToolError> {
    let mut salt_file: Option<PathBuf> = None;
    let mut bundles: Vec<PathBuf> = Vec::new();
    let mut want_self_test = false;
    let mut index = 0;

    while index < argv.len() {
        let arg = &argv[index];
        match arg.to_str() {
            Some("--help" | "-h") => {
                println!("{USAGE}");
                return Ok(ExitCode::from(EXIT_DISTINCT));
            }
            Some("--self-test") => want_self_test = true,
            Some("--salt-file") => {
                index += 1;
                let value = argv
                    .get(index)
                    .ok_or_else(|| ToolError::Usage("--salt-file needs a path".to_owned()))?;
                salt_file = Some(PathBuf::from(value));
            }
            Some(other) if other.starts_with('-') => {
                return Err(ToolError::Usage(format!("unknown option {other}")));
            }
            _ => bundles.push(PathBuf::from(arg)),
        }
        index += 1;
    }

    if want_self_test {
        if salt_file.is_some() || !bundles.is_empty() {
            return Err(ToolError::Usage(
                "--self-test takes no salt file and no bundles".to_owned(),
            ));
        }
        return self_test();
    }

    let salt_file =
        salt_file.ok_or_else(|| ToolError::Usage("--salt-file is required".to_owned()))?;
    if bundles.is_empty() {
        return Err(ToolError::Usage("no bundles given".to_owned()));
    }

    let salt = read_salt(&salt_file)?;
    report(&salt, &bundles)
}

// ---------------------------------------------------------------------------
// the salt
// ---------------------------------------------------------------------------

fn read_salt(path: &Path) -> Result<[u8; SALT_LEN], ToolError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let meta = std::fs::metadata(path).map_err(|source| ToolError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Err(ToolError::SaltPermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
    }

    let raw = std::fs::read(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    if let Ok(exact) = <[u8; SALT_LEN]>::try_from(raw.as_slice()) {
        return Ok(exact);
    }

    // Hex form, tolerating surrounding whitespace so an ordinary
    // `xxd`/`openssl rand -hex 32 > salt` file works.
    let trimmed: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if trimmed.len() == SALT_LEN * 2 {
        let mut out = [0u8; SALT_LEN];
        for (slot, pair) in out.iter_mut().zip(trimmed.chunks_exact(2)) {
            let hi = hex_nibble(pair[0]);
            let lo = hex_nibble(pair[1]);
            match (hi, lo) {
                (Some(hi), Some(lo)) => *slot = (hi << 4) | lo,
                _ => {
                    return Err(ToolError::SaltShape {
                        path: path.to_path_buf(),
                        len: raw.len(),
                    });
                }
            }
        }
        return Ok(out);
    }

    Err(ToolError::SaltShape {
        path: path.to_path_buf(),
        len: raw.len(),
    })
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// X2 over a set of submitted bundles
// ---------------------------------------------------------------------------

fn fingerprint_bundle(salt: &[u8; SALT_LEN], path: &Path) -> Result<String, ToolError> {
    let bytes = std::fs::read(path).map_err(|source| ToolError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    fingerprint_bytes(salt, &bytes).map_err(|error| match error {
        ToolError::Decode { message, .. } => ToolError::Decode {
            path: path.to_path_buf(),
            message,
        },
        other => other,
    })
}

/// The whole read path in one place, so the in-process tests and the
/// binary's own file path exercise the same code.
fn fingerprint_bytes(salt: &[u8; SALT_LEN], bytes: &[u8]) -> Result<String, ToolError> {
    let proof = SealProof::decode(bytes).map_err(|source| ToolError::Decode {
        path: PathBuf::new(),
        message: source.to_string(),
    })?;
    vault_fp(salt, proof.manifest().body().pubkeys())
}

fn report(salt: &[u8; SALT_LEN], bundles: &[PathBuf]) -> Result<ExitCode, ToolError> {
    let mut groups: BTreeMap<String, Vec<&PathBuf>> = BTreeMap::new();
    for path in bundles {
        let fingerprint = fingerprint_bundle(salt, path)?;
        println!("{fingerprint}  {}", path.display());
        groups.entry(fingerprint).or_default().push(path);
    }

    let collisions: Vec<(&String, &Vec<&PathBuf>)> =
        groups.iter().filter(|(_, paths)| paths.len() > 1).collect();
    if collisions.is_empty() {
        return Ok(ExitCode::from(EXIT_DISTINCT));
    }

    println!("\nX2 FIRED (D73 §4 R5) — these submissions carry one sealer public key");
    println!("and are therefore ONE vault. They collapse to one row:");
    for (fingerprint, paths) in collisions {
        let joined: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        println!("  {fingerprint}: {}", joined.join(", "));
    }
    Ok(ExitCode::from(EXIT_X2_FIRED))
}

// ---------------------------------------------------------------------------
// D73 §4 R5 X7 — the planted duplicate, run by the instrument on itself
// ---------------------------------------------------------------------------

/// The label deriving the self-test's salt. **Not** a metric salt: it is
/// `SHA-256(label ‖ TEST_MASTER_SECRET_W)` via
/// [`antseal_core::test_util::alternate_test_secret`], the house derivation
/// for fixture secrets, so project rule 6's "no secret material in fixtures"
/// holds by construction and the self-test needs no salt file.
const SELF_TEST_SALT_LABEL: &[u8] = b"antseal U76 metric-vault-fp self-test salt";

/// The second vault of the self-test's key-material direction.
const SELF_TEST_SECOND_VAULT_LABEL: &[u8] = b"antseal U76 metric-vault-fp second vault";

fn self_test() -> Result<ExitCode, ToolError> {
    use antseal_core::crypto::material::MasterSecretRef;
    use antseal_core::crypto::sig_policy::{SigPolicy, public_keys};
    use antseal_core::test_util::bundle_fixtures::{Selection, shapes};
    use antseal_core::test_util::{TEST_MASTER_SECRET_W, alternate_test_secret, bundle_fixtures};

    let salt = alternate_test_secret(SELF_TEST_SALT_LABEL);

    println!("D73 §4 R5 X7 — planted-duplicate run of X2");
    println!(
        "instrument: metric-vault-fp, domain \"{}\"",
        render_domain_tag(VAULT_FP_DOMAIN)
    );

    // ── direction 1: ONE vault, two genuinely different submissions ──────
    //
    // Every `bundle_fixtures` bundle is sealed under the single fixture
    // master secret `TEST_MASTER_SECRET_W`, so two different works built
    // from it are exactly D73 R5 X7's *"two bundles produced from a single
    // vault, submitted as if from two participants"*.
    let first = bundle_fixtures::build(
        &shapes::single_binary().with_seed(1),
        &Selection::all(shapes::single_binary().files.len()),
    );
    let second = bundle_fixtures::build(
        &shapes::multi_file().with_seed(2),
        &Selection::all(shapes::multi_file().files.len()),
    );

    if first.bytes == second.bytes {
        return Err(ToolError::SelfTest(
            "the two planted submissions are byte-identical, so a collapse would \
             prove nothing about pubkeys"
                .to_owned(),
        ));
    }

    let first_work = decoded_work_id(&first.bytes)?;
    let second_work = decoded_work_id(&second.bytes)?;
    if first_work == second_work {
        return Err(ToolError::SelfTest(
            "the two planted submissions share a work_id, so X3 would strike the \
             row before X2 could and the plant tests the wrong falsifier"
                .to_owned(),
        ));
    }

    let first_fp = fingerprint_bytes(&salt, &first.bytes)?;
    let second_fp = fingerprint_bytes(&salt, &second.bytes)?;
    println!("  submission A  work_fp-ish {first_work}  vault_fp {first_fp}");
    println!("  submission B  work_fp-ish {second_work}  vault_fp {second_fp}");

    if first_fp != second_fp {
        return Err(ToolError::SelfTest(format!(
            "X2 DID NOT FIRE on the planted duplicate: two bundles from one vault \
             produced different vault_fp ({first_fp} vs {second_fp})"
        )));
    }
    println!("  X2 FIRED: distinct works, one vault_fp — the rows collapse. ✓");

    // ── direction 2: a different vault must NOT collapse (end to end) ────
    //
    // `bundle_fixtures` has no alternate-signer knob, so the second vault is
    // modelled by mutating the Ed25519 public key **inside a real bundle**,
    // asserted to still decode. That is the honest statement of what it is:
    // the axis under test is "the bytes of manifest key 5 changed", which is
    // exactly what X2 reads.
    let mutated = mutate_ed25519_pubkey(&first.bytes)?;
    let mutated_fp = fingerprint_bytes(&salt, &mutated)?;
    println!("  submission C  (A with one public-key byte changed)  vault_fp {mutated_fp}");
    if mutated_fp == first_fp {
        return Err(ToolError::SelfTest(format!(
            "X2 OVER-FIRED: a bundle carrying a different sealer public key produced \
             the same vault_fp ({mutated_fp}), so the column cannot distinguish \
             participants at all"
        )));
    }
    println!("  X2 did NOT fire across vaults — the rows stay separate. ✓");

    // ── direction 3: two genuinely distinct vaults, at key-material level ─
    //
    // Direction 2 mutates bytes; this derives two real `pubkeys` maps from
    // two real master secrets through `public_keys`, the same call the
    // production sealer makes at `antseal-cli/src/pipeline/seal.rs:534`.
    let policy = SigPolicy::hybrid();
    let second_w = alternate_test_secret(SELF_TEST_SECOND_VAULT_LABEL);
    if second_w == TEST_MASTER_SECRET_W {
        return Err(ToolError::SelfTest(
            "the derived second vault equals the first; the direction is vacuous".to_owned(),
        ));
    }
    let map_of = |w: &[u8; 32]| -> Result<SigAlgMap, ToolError> {
        SigAlgMap::new(
            SigMaterial::Pubkey,
            public_keys(MasterSecretRef::from_bytes(w), &policy),
        )
        .map_err(|error| ToolError::SelfTest(format!("could not build a pubkeys map: {error}")))
    };
    let fp_one = vault_fp(&salt, &map_of(&TEST_MASTER_SECRET_W)?)?;
    let fp_two = vault_fp(&salt, &map_of(&second_w)?)?;
    println!("  vault W   vault_fp {fp_one}");
    println!("  vault W'  vault_fp {fp_two}");
    if fp_one == fp_two {
        return Err(ToolError::SelfTest(format!(
            "two master secrets produced one vault_fp ({fp_one})"
        )));
    }
    println!("  two derived vaults, two fingerprints. ✓");

    println!("\nSELF-TEST PASSED — X2 fires on a planted duplicate and does not fire");
    println!("across vaults. Record this run's date in docs/success-metric.md's header");
    println!("block (D73 §4 R7's X7 planted-fault record) before declaring the count met.");
    Ok(ExitCode::from(EXIT_DISTINCT))
}

/// Short hex of the work id, for the self-test transcript only. The full
/// `work_id` is not a secret, but D73 R6.4 keeps it out of committed files,
/// so the transcript carries a prefix rather than the value.
fn decoded_work_id(bytes: &[u8]) -> Result<String, ToolError> {
    use antseal_core::manifest::work_id;
    let proof = SealProof::decode(bytes).map_err(|source| ToolError::Decode {
        path: PathBuf::new(),
        message: source.to_string(),
    })?;
    Ok(hex(
        &work_id(proof.manifest().body_bytes()).as_bytes()[..FP_BYTES]
    ))
}

/// Return `bytes` with one byte of the embedded Ed25519 **public key**
/// changed — a bundle that still decodes but reports a different vault.
///
/// The key is located by value, and the occurrence count is **asserted**:
/// if the needle appeared zero or more than once the mutation would be
/// ambiguous and this returns an error rather than silently mutating
/// something else. Only lengths and offsets are ever printed.
fn mutate_ed25519_pubkey(bytes: &[u8]) -> Result<Vec<u8>, ToolError> {
    use antseal_core::crypto::error::SigAlg;

    let proof = SealProof::decode(bytes).map_err(|source| ToolError::Decode {
        path: PathBuf::new(),
        message: source.to_string(),
    })?;
    let needle = proof
        .manifest()
        .body()
        .pubkeys()
        .get(SigAlg::Ed25519)
        .ok_or_else(|| {
            ToolError::SelfTest("fixture bundle carries no Ed25519 public key".to_owned())
        })?
        .to_vec();

    let hits: Vec<usize> = bytes
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle.as_slice())
        .map(|(offset, _)| offset)
        .collect();
    let [offset] = hits[..] else {
        return Err(ToolError::SelfTest(format!(
            "the Ed25519 public key occurs {} times in the bundle; a single \
             unambiguous site is required to model a second vault",
            hits.len()
        )));
    };

    let mut out = bytes.to_vec();
    out[offset] ^= 0x01;
    // The mutation must leave a decodable bundle, or the direction proves
    // nothing about what a decoder reads.
    SealProof::decode(&out).map_err(|source| {
        ToolError::SelfTest(format!(
            "the mutated bundle no longer decodes ({source}); the second-vault \
         direction would be testing the decoder, not X2"
        ))
    })?;
    Ok(out)
}

/// The domain tag rendered for the transcript, non-graphic bytes escaped.
fn render_domain_tag(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                (*byte as char).to_string()
            } else {
                format!("\\x{byte:02x}")
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// unit tests — the two-direction property, at the level where it is cheap
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use antseal_core::crypto::material::MasterSecretRef;
    use antseal_core::crypto::sig_policy::{SigPolicy, public_keys};
    use antseal_core::test_util::{TEST_MASTER_SECRET_W, alternate_test_secret};

    const A_SALT: [u8; SALT_LEN] = [0x5A; SALT_LEN];
    const B_SALT: [u8; SALT_LEN] = [0xA5; SALT_LEN];

    fn pubkeys_of(w: &[u8; 32]) -> SigAlgMap {
        SigAlgMap::new(
            SigMaterial::Pubkey,
            public_keys(MasterSecretRef::from_bytes(w), &SigPolicy::hybrid()),
        )
        .expect("hybrid pubkeys are a valid map")
    }

    fn second_vault() -> [u8; 32] {
        alternate_test_secret(b"antseal U76 unit-test second vault")
    }

    /// X2's collapse direction: one vault, one fingerprint, every time.
    #[test]
    fn one_vault_always_yields_one_fingerprint() {
        let first = vault_fp(&A_SALT, &pubkeys_of(&TEST_MASTER_SECRET_W)).expect("pubkey material");
        let second =
            vault_fp(&A_SALT, &pubkeys_of(&TEST_MASTER_SECRET_W)).expect("pubkey material");
        assert_eq!(
            first, second,
            "the same vault produced two fingerprints; X2 cannot collapse \
             what it cannot recognise"
        );
        assert_eq!(first.len(), FP_BYTES * 2, "D73 R7 fixes 16 hex characters");
        assert!(
            first
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "fingerprint must be lowercase hex, got {first}"
        );
    }

    /// The other direction, and the one a collision-only test would miss:
    /// two vaults must NOT collapse.
    #[test]
    fn two_vaults_yield_two_fingerprints() {
        let w2 = second_vault();
        assert_ne!(
            w2, TEST_MASTER_SECRET_W,
            "the derivation must move the secret"
        );
        let first = vault_fp(&A_SALT, &pubkeys_of(&TEST_MASTER_SECRET_W)).expect("pubkey material");
        let second = vault_fp(&A_SALT, &pubkeys_of(&w2)).expect("pubkey material");
        assert_ne!(
            first, second,
            "two distinct vaults collided on {first}; the distinctness column \
             would collapse genuine participants"
        );
    }

    /// The salt is in the preimage, not decoration. Without this, a metric
    /// sheet's fingerprints would be computable by anyone holding a
    /// candidate public key — the confirmation attack
    /// `crypto::confirmation_attack` documents.
    #[test]
    fn the_salt_reaches_the_fingerprint() {
        let keys = pubkeys_of(&TEST_MASTER_SECRET_W);
        let under_a = vault_fp(&A_SALT, &keys).expect("pubkey material");
        let under_b = vault_fp(&B_SALT, &keys).expect("pubkey material");
        assert_ne!(
            under_a, under_b,
            "two salts produced one fingerprint, so the salt is not in the preimage"
        );
    }

    /// The domain tag is in the preimage, so a `vault_fp` cannot be a
    /// `work_fp` under R7's shared salt.
    #[test]
    fn the_domain_tag_reaches_the_fingerprint() {
        let keys = pubkeys_of(&TEST_MASTER_SECRET_W);
        let tagged = vault_fp(&A_SALT, &keys).expect("pubkey material");

        // The untagged R7-literal form, computed here and nowhere else.
        let mut untagged = Sha256::new();
        untagged.update(A_SALT);
        untagged.update(keys.len().to_le_bytes());
        for (alg, key) in keys.iter() {
            untagged.update(sig_alg_to_wire(alg).to_le_bytes());
            untagged.update((key.len() as u64).to_le_bytes());
            untagged.update(key);
        }
        assert_ne!(
            tagged,
            hex(&untagged.finalize()[..FP_BYTES]),
            "the domain tag does not reach the digest"
        );
        assert!(
            VAULT_FP_DOMAIN[0] > antseal_core::crypto::domain::MAX_DOMAIN_TAG,
            "the tag's first byte must sit above the frozen one-byte registry \
             so it is disjoint from every spec tag by construction"
        );
        assert_eq!(
            VAULT_FP_DOMAIN.last(),
            Some(&0u8),
            "the tree's string-tag convention terminates with NUL"
        );
    }

    /// No raw key byte can appear in the rendered form: it is 16 hex
    /// characters and nothing else, over a preimage thousands of bytes long.
    #[test]
    fn the_rendered_form_carries_no_key_bytes() {
        let keys = pubkeys_of(&TEST_MASTER_SECRET_W);
        let rendered = vault_fp(&A_SALT, &keys).expect("pubkey material");
        let bytes = rendered.as_bytes();
        assert_eq!(
            bytes.len(),
            FP_BYTES * 2,
            "the rendered form is not 16 hex characters, so something other \
             than a truncated digest is being printed: {rendered:?}"
        );
        let mut total_key_bytes = 0usize;
        for (_, key) in keys.iter() {
            total_key_bytes += key.len();
            assert!(
                !bytes
                    .windows(key.len().min(bytes.len()))
                    .any(|w| key.starts_with(w)),
                "the rendered fingerprint is a prefix-slice of a public key"
            );
        }
        assert!(
            total_key_bytes > bytes.len() * 8,
            "the preimage must be far larger than the 64-bit output for the \
             information-theoretic claim to hold ({total_key_bytes} B in, \
             {} bits out)",
            bytes.len() * 4
        );
    }

    /// A signatures map has the same Rust type as a pubkeys map. Refusing it
    /// is what stops a per-bundle-varying column silently replacing X2's.
    #[test]
    fn a_signatures_map_is_refused_rather_than_fingerprinted() {
        use antseal_core::crypto::sig_policy::sign_body;
        let signatures = SigAlgMap::new(
            SigMaterial::Signature,
            sign_body(
                MasterSecretRef::from_bytes(&TEST_MASTER_SECRET_W),
                &SigPolicy::hybrid(),
                b"body bytes",
            ),
        )
        .expect("hybrid signatures are a valid map");
        let Err(error) = vault_fp(&A_SALT, &signatures) else {
            panic!("a signatures map was fingerprinted; vault_fp is defined over pubkeys only");
        };
        assert!(
            matches!(error, ToolError::WrongMaterial),
            "wrong error class: {error}"
        );
        assert!(
            error.to_string().contains("pubkeys"),
            "the refusal must name the field it defends: {error}"
        );
    }

    /// Salt parsing accepts both shapes and rejects everything else — and
    /// no error message may quote a byte of the file.
    #[test]
    fn salt_parsing_accepts_both_shapes_and_leaks_nothing() {
        let dir = scratch_dir("salt-shapes");
        let raw_path = dir.join("raw.bin");
        let hex_path = dir.join("hex.txt");
        let short_path = dir.join("short.bin");
        let value = [0x11u8; SALT_LEN];

        write_private(&raw_path, &value);
        write_private(&hex_path, format!("{}\n", hex(&value)).as_bytes());
        write_private(&short_path, &value[..31]);

        // `assert_eq!` / `expect_err` on a `Result<[u8; SALT_LEN], _>` render
        // the Ok value — the SALT — into the panic message whenever the
        // thing under test is broken, which is the one moment it must not.
        // Every comparison here is therefore made without rendering bytes.
        assert!(
            read_salt(&raw_path).is_ok_and(|got| got == value),
            "the 32-raw-byte salt form did not parse"
        );
        assert!(
            read_salt(&hex_path).is_ok_and(|got| got == value),
            "the 64-hex-character salt form did not parse"
        );

        let Err(error) = read_salt(&short_path) else {
            panic!("a 31-byte file was accepted as a salt; neither shape matches it");
        };
        let rendered = error.to_string();
        assert!(rendered.contains("found 31 bytes"), "unhelpful: {rendered}");
        assert!(
            !rendered.contains(&hex(&value[..4])),
            "the error quoted salt content"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A salt file anyone can read is refused: D73 R7 holds the salt
    /// privately, and a readable one silently voids R6.4's privacy promise.
    #[cfg(unix)]
    #[test]
    fn a_group_readable_salt_file_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("salt-mode");
        let path = dir.join("salt.bin");
        write_private(&path, &[0x22u8; SALT_LEN]);
        let permissions = std::fs::Permissions::from_mode(0o640);
        std::fs::set_permissions(&path, permissions).expect("chmod");

        let Err(error) = read_salt(&path) else {
            panic!("a group-readable (0640) salt file was accepted; the mode check does not run");
        };
        assert!(
            matches!(error, ToolError::SaltPermissions { .. }),
            "wrong error class: {error}"
        );
        assert!(
            error.to_string().contains("0640"),
            "mode not named: {error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// X7 itself: the self-test must pass, and it is the check that proves
    /// the falsifier can fire.
    #[test]
    fn the_x7_self_test_passes() {
        let code = self_test().expect("self-test must not error");
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(EXIT_DISTINCT)),
            "self-test reported a non-zero exit"
        );
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "antseal-u76-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod 600");
        }
    }
}
