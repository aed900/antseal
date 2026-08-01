//! CLI error taxonomy and exit-code scheme (U1 stub surface; the full U2
//! taxonomy lands next).
//!
//! Every failure of a dispatched command is a [`CliError`]; `main` maps it
//! deterministically to a documented exit code. No variant may ever carry
//! secret material — `Display` output reaches stderr and (under `--json`)
//! stdout, and project rule 6 bars secrets from both.

use thiserror::Error;

/// The milestone a stubbed command's real handler arrives with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Milestone {
    /// M1 — storage: seal/restore/vault handlers land within this milestone.
    M1,
    /// M2 — anchors.
    M2,
    /// M3 — reveal + verifier.
    M3,
}

impl std::fmt::Display for Milestone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Milestone::M1 => "M1",
            Milestone::M2 => "M2",
            Milestone::M3 => "M3",
        })
    }
}

/// Top-level CLI error. One variant per user-distinguishable failure;
/// each maps to exactly one exit code.
#[derive(Debug, Error)]
pub enum CliError {
    /// The canonical surface is frozen from day one (U1); this command's
    /// handler has not landed yet.
    #[error(
        "`antseal {command}` is not implemented until {milestone}: the command surface is \
         frozen from day one so scripts written today keep parsing, and handlers land \
         milestone by milestone"
    )]
    NotImplemented {
        /// Space-joined command path, e.g. `"vault export"`.
        command: &'static str,
        /// When the real handler arrives.
        milestone: Milestone,
    },
}

impl CliError {
    /// The documented exit code for this error (0 is success and never
    /// appears here; 2 is clap's usage-error code, produced on the
    /// `clap::Error` path in `main_entry`, never by a `CliError`).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::NotImplemented { .. } => 3,
        }
    }
}
