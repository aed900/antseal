//! The vault store: on-disk layout, versioned header, crash-safe file
//! discipline, and the single-writer lock (U5).
//!
//! This module is the **in-crate layout documentation** U5's Accept
//! requires, and the code below makes the partition structural: the
//! beside-the-AEAD set is a closed three-variant enum
//! ([`layout::BesideFile`]), everything else resolves under the
//! ciphertext-only store area.
//!
//! # Layout of the vault directory (default `~/.antseal/`, override via
//! the `ANTSEAL_DIR` environment variable — a path, never a secret)
//!
//! ```text
//! ~/.antseal/
//! ├── config.toml     BESIDE the AEAD (U4): operator preferences only —
//! │                   default network, per-network contracts/RPC
//! │                   endpoints, reserved TSA-list + online-endpoint
//! │                   override slots. Never secrets, never per-work data.
//! ├── vault.header    BESIDE the AEAD: format version + opaque KDF block
//! │                   (schema owned by U6/D40) + wrap-mode id (U8/D50).
//! │                   Necessarily pre-unlock; tamper is caught at unlock
//! │                   by U6's AAD binding, parameter bombs by the D40 §3
//! │                   caps, oversized/garbled files by this module's
//! │                   parse caps.
//! ├── vault.lock      BESIDE the AEAD: the single-writer lockfile.
//! │                   Contains no data (an advisory pid for error
//! │                   messages); the lock itself is the OS file lock,
//! │                   which the kernel releases when the holder dies —
//! │                   a leftover file is inert, never stale state.
//! └── store/          INSIDE the AEAD — every byte under store/ is
//!     │               ciphertext under the vault key (U6). No plaintext
//!     │               file may ever be created here.
//!     ├── wallet      the Arbitrum wallet record (own sub-key, U10)
//!     └── works/      per-work records (U9): `W`, titles, source paths,
//!                     costs, completion state, the seal journal with
//!                     staged ciphertext bytes (+ D43 cache state),
//!                     `PaymentReceipt`s, consent records, invocation
//!                     identity, and ALL anchor artifacts (`.ots`, TSA
//!                     tokens, fetch dates) — the full MVP-SPEC.md
//!                     line 143 enumeration.
//! ```
//!
//! # The D42 partition (docs/decisions/D42-vault-encryption-boundary.md)
//!
//! Exactly **three things live beside the passphrase AEAD** — the config
//! file, the vault header, and the lockfile; that list is exhaustive and
//! nothing secret or per-work may ever join it. **Everything else lives
//! inside**, including all anchor artifacts and every per-work record —
//! the encrypted-at-rest mandate of MVP-SPEC.md line 143 holds with no
//! carve-outs. Transient atomic-write temp files (see [`fs`]) may exist
//! beside momentarily but only ever contain those beside-classes or AEAD
//! ciphertext.
//!
//! **AAD riders (D42, implemented by U6/U9; recorded here because this
//! module owns the header bytes they bind):** every AEAD under the vault
//! key binds the entire serialized KDF header (the exact bytes
//! [`header::VaultHeader::encode`] produces) as AAD, so a parameter
//! downgrade is an authentication failure for every record, not just a
//! monolith; every per-record AEAD additionally binds the record's
//! identity (work id + record class), so a blob spliced between slots or
//! vaults fails authentication. Honest limit, recorded: whole-vault
//! rollback (restoring an older copy of the directory) is undetectable
//! offline and out of scope.
//!
//! # Crash-safe write discipline
//!
//! All mutating writes go through [`fs::atomic_write`] (same-directory
//! temp file → write → fsync → rename → parent-dir fsync), so a reader of
//! any beside-file or store record observes the old bytes or the new
//! bytes, never a torn mix; a crash leaves at worst an inert `.tmp` file.
//! Concurrent processes are excluded by [`lock::VaultLock`] before any
//! mutation — U5's kill-tests and the M1 pay/finalize journal integrity
//! both stand on these two primitives.

pub mod fs;
pub mod header;
pub mod layout;
pub mod lock;
