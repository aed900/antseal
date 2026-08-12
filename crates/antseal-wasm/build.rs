//! Stamps the source commit into the module's build-info export.
//!
//! D63 §5 R3 requires the page footer to render its identity **from the
//! module's own export** and never from separately injected HTML, so the two
//! cannot disagree undetectably; the commit is the one identity field the
//! crate cannot read off itself.
//!
//! It is **supplied, never discovered**: this script runs no `git`, spawns no
//! process and reads no repository state. `scripts/wasm-pack-build.sh` passes
//! `ANTSEAL_SOURCE_COMMIT`, and a build without it stamps `unknown` rather
//! than failing — a `cargo build -p antseal-wasm` in a source tarball with no
//! `.git` must still work. That keeps D63 §5 R5's "no network access, no
//! discovery during the build" fence intact and keeps the build a pure
//! function of its inputs.
//!
//! `rerun-if-env-changed` is what makes the stamp non-stale: without it cargo
//! would keep a cached object compiled against a previous commit, and the
//! footer would publish a commit the artifact does not come from — the exact
//! mixed-deploy failure R27/Q19's parity gate exists to detect.

fn main() {
    println!("cargo::rerun-if-env-changed=ANTSEAL_SOURCE_COMMIT");

    let commit = std::env::var("ANTSEAL_SOURCE_COMMIT").unwrap_or_else(|_| "unknown".to_owned());

    // The value lands inside a `cargo::rustc-env=` directive and then inside
    // the module's JSON build-info document, so it is validated here rather
    // than trusted: a newline would forge a second cargo directive, and a
    // quote would break the JSON a page parses. `unknown` and a lowercase hex
    // object name are the only two accepted shapes.
    let acceptable = commit == "unknown"
        || (!commit.is_empty()
            && commit.len() <= 64
            && commit.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(
        acceptable,
        "ANTSEAL_SOURCE_COMMIT must be `unknown` or 1-64 hex characters, got {commit:?}"
    );

    println!("cargo::rustc-env=ANTSEAL_SOURCE_COMMIT={commit}");
}
