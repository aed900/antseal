//! Writing and editing the `.ots` container (tasks **A13**, **A14**;
//! decision D58 §7).
//!
//! `antseal-core` **reads** `.ots` files and has no serialiser, deliberately.
//! This is the writing half, and it lives on the acquisition side because
//! every byte it emits either came verbatim from a calendar or is one of the
//! 65 header bytes and the `0xff` separators. Nothing here re-encodes parsed
//! structure, which is D58 §7.3's second rider — *"do not round-trip a
//! received file to store it"* — obeyed by construction rather than by care:
//! [`OtsArtifact`](antseal_core::anchor::ots::OtsArtifact) deliberately does
//! not retain an unknown attestation's payload bytes, so a re-encoder could
//! not be written from it even if someone wanted one.
//!
//! # The `0xff` byte is a child-list separator, not a binary fork
//!
//! This is the single most costly thing to get wrong here, and the wrong
//! reading is the natural one. The grammar is
//!
//! ```text
//! node    := 0xff child 0xff child … 0xff child child     (N children, N-1 markers)
//! child   := 0x00 attestation | op node
//! ```
//!
//! — a **loop**, matching the reference implementation's
//! `while tag == 0xff:` and this project's own
//! [`walk`](antseal_core::anchor::ots) (`is_last_child = first != TAG_FORK`).
//! A marker is never followed by another marker: the byte after one is read
//! as a child *tag*.
//!
//! So "wrap the attestation in a fork" — replacing a child `C` with
//! `ff C X` to add a sibling — emits `ff ff C X` whenever `C` was not already
//! the last child, and `0xff` is then read as an **op tag**, which fails as
//! [`OtsError::UnknownOp`](antseal_core::anchor::ots::OtsError::UnknownOp).
//! The correct edit for appending a sibling to the child that is currently
//! last is to insert `0xff ‖ new-child` immediately **before** it
//! ([`splice_sibling_before`]): the new child becomes a non-last child and the
//! old one stays last, so the operation is idempotent in shape and can be
//! repeated for a second, third and fourth calendar.
//!
//! # Locating an attestation without a second parser
//!
//! A14 has to splice at a byte offset that only a parse can know, and this
//! crate must not grow a second `.ots` parser — D58 §4 is a whole section
//! about two implementations reporting different attestations from identical
//! bytes, which is the failure antseal exists to deny.
//!
//! So nothing here parses. [`pending_attestation_bytes`] **constructs** the
//! exact wire encoding of a pending attestation from a URI the one parser
//! reported, and [`locate_pending`] requires that needle to occur in the file
//! exactly as many times as that parser found pending attestations naming
//! that URI. The k-th occurrence is then the k-th such attestation, because
//! the parser's document order *is* byte order (it pushes attestations as it
//! walks the stream left to right). A mismatch in the count — a coincidental
//! byte match, a calendar that encoded its length non-minimally, a file this
//! code did not assemble — refuses the splice instead of guessing at one.

use antseal_core::anchor::ots::{OTS_DIGEST_TYPE_SHA256, OTS_MAGIC, OTS_PENDING_TAG, OTS_VERSION};

/// The container header: 31-byte magic ‖ version varuint ‖ digest-type tag ‖
/// 32 digest bytes (D58 §7.1).
pub const OTS_HEADER_LEN: usize = 65;

/// `0xff` — the child-list separator. See the module docs: it precedes every
/// child but the last, so N children cost N−1 of them.
pub const TAG_FORK: u8 = 0xff;

/// `0x00` — a child that is an attestation.
pub const TAG_ATTESTATION: u8 = 0x00;

const _: () = assert!(OTS_HEADER_LEN == OTS_MAGIC.len() + 1 + 1 + 32);

/// Why a container edit was refused.
///
/// Every arm means *the stored artifact was left exactly as it was*. There is
/// no partial edit: an edit is computed into a fresh `Vec` and either returned
/// whole or not at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ContainerError {
    /// The pending attestation to splice beside was not found in the file at
    /// the expected multiplicity.
    ///
    /// Carries counts, never bytes: the file is attacker-writable under the
    /// vault-tamper threat A42's allowlist exists for, and a message quoting
    /// its contents would be a channel out of it.
    #[error(
        "the pending attestation for this calendar occurs {found} time(s) in the stored artifact \
         but the parser reported {expected}: refusing to edit a file this code cannot place"
    )]
    Unlocatable {
        /// Needle occurrences found by byte search.
        found: usize,
        /// Pending attestations naming this URI, per the parser.
        expected: usize,
    },
    /// The occurrence index asked for does not exist.
    #[error("pending attestation #{index} was requested but only {found} exist")]
    NoSuchOccurrence {
        /// The index requested.
        index: usize,
        /// How many exist.
        found: usize,
    },
    /// The edit would produce an artifact no `.sealproof` could embed.
    ///
    /// Caught at merge, which is A28's Accept row: *"a merged `.ots` that
    /// would exceed `MAX_OTS_BYTES` fails at merge, not at bundle build"*. A
    /// stored artifact that cannot be revealed is a seal that anchored and
    /// then could not be shown.
    #[error("the merged artifact would be {len} bytes, over the {limit}-byte embeddable ceiling")]
    TooLarge {
        /// Size the edit would have produced.
        len: u64,
        /// The ceiling.
        limit: u64,
    },
}

/// The 65-byte container header for `anchor_digest`.
///
/// The three format constants come from `antseal-core` by name — they are the
/// ones its parser checks in steps 1–3, so a header built here cannot disagree
/// with the parser that reads it.
#[must_use]
pub fn container_header(anchor_digest: &[u8; 32]) -> [u8; OTS_HEADER_LEN] {
    let mut header = [0_u8; OTS_HEADER_LEN];
    let (magic, rest) = header.split_at_mut(OTS_MAGIC.len());
    magic.copy_from_slice(&OTS_MAGIC);
    // The version is a varuint, and 1 encodes as one byte. Asserted rather
    // than assumed, so a future version bump past 127 fails loudly here
    // instead of silently emitting a truncated header.
    const _: () = assert!(OTS_VERSION < 128);
    rest[0] = OTS_VERSION as u8;
    rest[1] = OTS_DIGEST_TYPE_SHA256;
    rest[2..].copy_from_slice(anchor_digest);
    header
}

/// Assemble a merged `.ots` from calendar response bodies, in the order given.
///
/// `header ‖ 0xff ‖ b₀ ‖ 0xff ‖ b₁ ‖ … ‖ 0xff ‖ b_{n-2} ‖ b_{n-1}` — D58
/// §7.3's recipe. Each body is copied verbatim; nothing is re-encoded.
///
/// The caller owns branch **order** (D58 §7.3's first rider: the container
/// does not require one, so two seals of the same digest at the same
/// calendars would otherwise produce different files). [`super::submit`] sorts
/// by the response bytes.
#[must_use]
pub fn assemble(anchor_digest: &[u8; 32], branches: &[Vec<u8>]) -> Vec<u8> {
    let total = OTS_HEADER_LEN
        + branches.iter().map(Vec::len).sum::<usize>()
        + branches.len().saturating_sub(1);
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&container_header(anchor_digest));
    for (index, branch) in branches.iter().enumerate() {
        if index + 1 < branches.len() {
            out.push(TAG_FORK);
        }
        out.extend_from_slice(branch);
    }
    out
}

/// The exact wire bytes of a pending attestation naming `uri`:
/// `0x00 ‖ tag(8) ‖ varuint(payload_len) ‖ varuint(uri_len) ‖ uri`.
///
/// Minimal varuint encoding, which is what every real calendar emits (all six
/// A25 captures). The parser *accepts* non-minimal encodings — `.ots` is a
/// foreign format and rejecting padding upstream tolerates would be a
/// rejection upstream does not make — so a calendar that padded one would make
/// [`locate_pending`] find zero occurrences and refuse the splice. That is the
/// safe direction: a missed upgrade, never a corrupted artifact.
#[must_use]
pub fn pending_attestation_bytes(uri: &str) -> Vec<u8> {
    let mut payload = varuint(uri.len() as u64);
    payload.extend_from_slice(uri.as_bytes());

    let mut out = Vec::with_capacity(1 + OTS_PENDING_TAG.len() + 2 + payload.len());
    out.push(TAG_ATTESTATION);
    out.extend_from_slice(&OTS_PENDING_TAG);
    out.extend_from_slice(&varuint(payload.len() as u64));
    out.extend_from_slice(&payload);
    out
}

/// Little-endian base-128 varuint, minimally encoded.
fn varuint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value % 128) as u8;
        value /= 128;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// Byte offset where the `occurrence`-th pending attestation naming `uri`
/// begins.
///
/// `expected` is how many pending attestations naming `uri` the **parser**
/// reported for this file. Requiring the byte search to agree with it is what
/// makes index-matching sound: see the module docs.
///
/// # Errors
///
/// [`ContainerError::Unlocatable`] when the two counts disagree, and
/// [`ContainerError::NoSuchOccurrence`] when the index is out of range.
pub fn locate_pending(
    file: &[u8],
    uri: &str,
    occurrence: usize,
    expected: usize,
) -> Result<usize, ContainerError> {
    let needle = pending_attestation_bytes(uri);
    let found: Vec<usize> = file
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == needle.as_slice()).then_some(offset))
        .collect();

    if found.len() != expected {
        return Err(ContainerError::Unlocatable {
            found: found.len(),
            expected,
        });
    }
    found
        .get(occurrence)
        .copied()
        .ok_or(ContainerError::NoSuchOccurrence {
            index: occurrence,
            found: found.len(),
        })
}

/// Insert `sibling` as a new child of the node whose **last** child begins at
/// `offset`.
///
/// Emits `file[..offset] ‖ 0xff ‖ sibling ‖ file[offset..]`. See the module
/// docs for why the insertion goes *before* the existing child and not after
/// it, and why that keeps the operation repeatable.
///
/// Every pre-existing byte survives at its own relative position: this is a
/// pure insertion, never a rewrite.
///
/// # Errors
///
/// [`ContainerError::TooLarge`] when the result would exceed `limit`.
pub fn splice_sibling_before(
    file: &[u8],
    offset: usize,
    sibling: &[u8],
    limit: u64,
) -> Result<Vec<u8>, ContainerError> {
    let len = file.len() as u64 + 1 + sibling.len() as u64;
    if len > limit {
        return Err(ContainerError::TooLarge { len, limit });
    }
    let mut out = Vec::with_capacity(len as usize);
    out.extend_from_slice(&file[..offset]);
    out.push(TAG_FORK);
    out.extend_from_slice(sibling);
    out.extend_from_slice(&file[offset..]);
    Ok(out)
}

#[cfg(test)]
mod tests;
