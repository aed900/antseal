//! The **iterative** `.ots` parser and op-DAG executor (task **A11**).
//!
//! # Iterative, by requirement
//!
//! D58 §10.3 rule 1: *"An explicit `Vec` work-stack, no recursive descent.
//! This is what makes native and wasm32 behave identically at depth and what
//! makes `MAX_OTS_DEPTH` a policy rather than a stack measurement."* The
//! rejected crate recursed and bounded itself at 255 because that is what its
//! author's stack held; measured, a 255-op chain needed 163 840 B of stack in
//! release and 1 048 576 B in debug against `wasm-ld`'s 1 MiB default, and a
//! wasm stack overflow is a **trap**, not an error (D58 §3.5).
//! `super::tests::parser_is_iterative_at_max_depth` witnesses the property
//! rather than restating it: it parses a `MAX_OTS_DEPTH` chain on a 256 KiB
//! thread, which a recursive implementation cannot survive.
//!
//! # No shift by a runtime value, anywhere
//!
//! The varuint reader accumulates by **multiplication**, never by a left
//! shift of a running bit offset.
//! That is not a style choice: D58 §3.3 measured an 87-byte `.ots` that
//! panics in a debug build and *parses to a different answer in a release
//! build* out of an unbounded shift, and this project's CI has **no release
//! test lane anywhere**, so a cross-profile divergence is structurally
//! invisible to it. The property is guaranteed by construction and witnessed
//! by `super::tests::ots_module_contains_no_runtime_shift`.
//!
//! # Work-stack memory, bounded twice
//!
//! Only the frames on the *current root-to-node path* are live, so the stack
//! holds at most `MAX_OTS_DEPTH + 1` values of at most `MAX_OTS_VALUE_BYTES`
//! each. That product (33.5 MiB) is the paper bound; the real one is much
//! smaller, because the only ops that grow a value are `append` and
//! `prepend`, and **every byte of growth is a byte of operand in the input**.
//! A `.ots` reaching the paper bound would itself be tens of megabytes. This
//! is why D58 §10.3 rule 5 can say `parse_ots` needs no total-size cap of its
//! own: work is bounded by the limits, not by the caller's diligence.
//!
//! # CPU, bounded by the same two constants
//!
//! D58 states the memory argument and not this one, so it is written out
//! here. The only unbounded-work primitive in the executor is SHA-256, and
//! **total hashing is at most `MAX_OTS_OPS × MAX_OTS_VALUE_BYTES` = 128 MiB**
//! — the op cap bounds how many times it can run and the value cap bounds
//! what it can run over. That ceiling is reachable only in principle: raising
//! the running value costs operand bytes in the input one for one, and a
//! `sha256` collapses it back to 32, so an attacker who wants many large
//! hashes must either pay for them in input length or fan them out under one
//! fork, where the width cap applies. It matters that the bound exists at
//! all, because this parser runs in a browser tab on bytes a counterparty
//! supplied.

use super::error::{OtsError, PayloadDefect};
use super::exec::{self, OpKind};
use super::limits::{
    MAX_OTS_ATTESTATION_PAYLOAD_BYTES, MAX_OTS_ATTESTATIONS, MAX_OTS_BRANCH_WIDTH, MAX_OTS_DEPTH,
    MAX_OTS_OPERAND_BYTES, MAX_OTS_OPS,
};
use super::{OtsArtifact, OtsAttestation, OtsShape};

// ── container constants (D58 §7.1) ───────────────────────────────────────

/// The 31-byte container magic (`ser.rs:25` of the rejected crate; verified
/// byte-for-byte against every fixture in `testdata/anchors/A25-bootstrap/`).
///
/// `pub` because A13 **writes** the container this parser reads, from another
/// crate, and a second copy of these bytes over there is the drift D84 §5
/// forbids for limits and this project forbids for format surface generally.
/// Exported as [`super::OTS_MAGIC`].
pub const MAGIC: [u8; 31] = *b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

/// The only major version this codec reads. `pub` for A13's writer, as
/// [`super::OTS_VERSION`].
pub const VERSION_1: u64 = 1;

/// Digest-type tag `0x08` = SHA-256. Written in decimal for the reason
/// [`super::exec`] records. `pub` for A13's writer, as
/// [`super::OTS_DIGEST_TYPE_SHA256`].
pub const DIGEST_TYPE_SHA256: u8 = 8;

/// Length of the start digest a `0x08` header declares.
const START_DIGEST_LEN: usize = 32;

/// `0x00` — an attestation node; terminates this path.
const TAG_ATTESTATION: u8 = 0;

/// `0xff` — fork marker. It precedes **every child but the last**, so `N`
/// children cost `N - 1` markers and `ff A ff B C` is three children
/// (D58 §7.2). A marker is never followed by another marker: the byte after
/// it is read as a child tag, exactly as the reference implementation does.
const TAG_FORK: u8 = 255;

/// Length of an attestation type tag.
const ATTESTATION_TAG_LEN: usize = 8;

/// `83 df e3 0d 2e f9 0c 8e` — a calendar's pending attestation. Payload is a
/// varbytes URI. `pub` for the same reason as [`MAGIC`]: A14 has to *find* one
/// of these in a stored file to splice an upgrade beside it, and a second copy
/// of the tag in the anchor crate could drift from the one that parses it.
/// Exported as [`super::OTS_PENDING_TAG`].
pub const PENDING_TAG: [u8; ATTESTATION_TAG_LEN] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];

/// `05 88 96 0d 73 d7 19 01` — a Bitcoin attestation. Payload is a varuint
/// block height.
const BITCOIN_TAG: [u8; ATTESTATION_TAG_LEN] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

/// Most bytes a varuint may occupy.
///
/// Nine continuation-free bytes carry 63 bits, so a decoded value always fits
/// `u64` and the accumulator can never overflow. Minimal encoding is **not**
/// required (D58 §10.3 rule 3): `.ots` is a foreign format this project does
/// not control, and rejecting a non-minimal varuint that a future calendar
/// emits would be a rejection the reference implementation does not make.
const MAX_VARUINT_BYTES: usize = 9;

/// Radix of the little-endian base-128 varuint encoding.
const VARUINT_RADIX: u64 = 128;

/// Mask for a varuint byte's payload bits.
const VARUINT_PAYLOAD_MASK: u8 = 0x7f;

/// A varuint byte's continuation flag.
const VARUINT_CONTINUE: u8 = 0x80;

// ── the reader ───────────────────────────────────────────────────────────

/// A cursor over bytes that are already in memory.
///
/// `&[u8]`, not `std::io::Read`: `antseal-core` parses a slice the caller
/// already holds, and a `Read` cursor would buy nothing and cost an
/// unreachable I/O error arm in a crate that must stay WASM-safe (D58 §6).
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Bytes not yet consumed.
    const fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    /// The cursor, for error payloads.
    const fn offset(&self) -> u64 {
        self.pos as u64
    }

    fn read_byte(&mut self) -> Result<u8, OtsError> {
        let Some(byte) = self.bytes.get(self.pos) else {
            return Err(OtsError::Truncated {
                offset: self.offset(),
                needed: 1,
            });
        };
        self.pos += 1;
        Ok(*byte)
    }

    /// Borrow the next `n` bytes. **Never allocates** — an attacker-chosen
    /// length can therefore not become an allocation, which is the whole of
    /// D58 §3.1's defect (`vec![0; n]` *before* the read).
    fn read_bytes(&mut self, n: u64) -> Result<&'a [u8], OtsError> {
        let remaining = self.remaining() as u64;
        if n > remaining {
            return Err(OtsError::Truncated {
                offset: self.offset(),
                needed: n - remaining,
            });
        }
        // `n <= remaining <= usize::MAX`, so the cast is exact.
        let end = self.pos + n as usize;
        let Some(slice) = self.bytes.get(self.pos..end) else {
            return Err(OtsError::Truncated {
                offset: self.offset(),
                needed: n,
            });
        };
        self.pos = end;
        Ok(slice)
    }

    /// Little-endian base-128 varuint, bounded at [`MAX_VARUINT_BYTES`].
    ///
    /// Accumulates as `value + payload * radix^i` rather than by OR-ing in a
    /// payload left-shifted by `7 * i`; see the module docs.
    fn read_varuint(&mut self) -> Result<u64, OtsError> {
        let start = self.offset();
        let mut value: u64 = 0;
        let mut place: u64 = 1;

        for i in 0..MAX_VARUINT_BYTES {
            let byte = self.read_byte()?;
            let term = u64::from(byte & VARUINT_PAYLOAD_MASK)
                .checked_mul(place)
                .ok_or(OtsError::VarintTooLong { offset: start })?;
            value = value
                .checked_add(term)
                .ok_or(OtsError::VarintTooLong { offset: start })?;
            if byte & VARUINT_CONTINUE == 0 {
                return Ok(value);
            }
            if i + 1 < MAX_VARUINT_BYTES {
                place = place
                    .checked_mul(VARUINT_RADIX)
                    .ok_or(OtsError::VarintTooLong { offset: start })?;
            }
        }
        Err(OtsError::VarintTooLong { offset: start })
    }
}

// ── the work stack ───────────────────────────────────────────────────────

/// One node of the op DAG, live only while it is on the current path.
struct Frame {
    /// The running value at this node. `None` once the path has crossed a
    /// registered-but-unimplemented op (D58 §9.4).
    value: Option<Vec<u8>>,
    /// Edges from the root, root at 0 (D58 §9.3's normative definition).
    depth: u32,
    /// Children started so far, for [`MAX_OTS_BRANCH_WIDTH`].
    children: u32,
    /// Whether the op edge that created this node was its parent's **last**
    /// child, so completing this node completes the parent too.
    closes_parent: bool,
}

/// The work stack, shaped so that **it cannot be empty**.
///
/// A separate `root` rather than `Vec::pop().unwrap()`: the invariant "there
/// is always a current node" is then a property of the type rather than of
/// an `expect` message, and `#![deny(clippy::unwrap_used)]` has nothing to
/// forgive.
struct Walk {
    root: Frame,
    rest: Vec<Frame>,
}

impl Walk {
    fn top(&mut self) -> &mut Frame {
        self.rest.last_mut().unwrap_or(&mut self.root)
    }

    fn top_ref(&self) -> &Frame {
        self.rest.last().unwrap_or(&self.root)
    }

    /// Mark the current node complete, unwinding through every ancestor the
    /// completion also closes. Returns `true` when the whole DAG is done.
    fn complete_top(&mut self) -> bool {
        loop {
            match self.rest.pop() {
                // The completed node was the root: the walk is over.
                None => return true,
                // Its creating edge was its parent's last child, so the
                // parent is complete too — keep unwinding.
                Some(frame) if frame.closes_parent => {}
                // The parent still has children to read.
                Some(_) => return false,
            }
        }
    }
}

// ── the public entry point ───────────────────────────────────────────────

/// Parse and execute a `.ots` artifact against the digest it must stamp.
///
/// See [`super::parse_ots`] for the contract; this is its body.
pub(super) fn parse_measured(
    bytes: &[u8],
    anchor_digest: &[u8; START_DIGEST_LEN],
) -> Result<(OtsArtifact, OtsShape), OtsError> {
    let mut reader = Reader::new(bytes);

    // Step 1 — the 31-byte magic. Checked as a whole so that an input too
    // short to hold it is `bad-magic` rather than `truncated`: nothing
    // shorter than 31 bytes is an `.ots` file at all, and step 1 is first.
    let header = reader.read_bytes(MAGIC.len() as u64);
    match header {
        Ok(magic) if magic == MAGIC => {}
        _ => return Err(OtsError::BadMagic),
    }

    // Step 2 — major version.
    let version = reader.read_varuint()?;
    if version != VERSION_1 {
        return Err(OtsError::UnsupportedVersion { version });
    }

    // Step 3 — digest type.
    let digest_type = reader.read_byte()?;
    if digest_type != DIGEST_TYPE_SHA256 {
        return Err(OtsError::UnsupportedDigestType { tag: digest_type });
    }

    // Step 4 — the start digest must be present.
    let start_digest = reader.read_bytes(START_DIGEST_LEN as u64)?;

    // Step 5 — and it must be this seal's `anchor_digest`.
    //
    // Ordinary comparison, not constant-time: both operands are public. The
    // start digest is in the artifact an adversary supplied and
    // `anchor_digest` is derived from the manifest, which the bundle carries
    // in the clear (MVP-SPEC.md line 121).
    if start_digest != anchor_digest.as_slice() {
        return Err(OtsError::DigestMismatch);
    }

    // Step 6 — the walk.
    let (attestations, shape) = walk(&mut reader, start_digest)?;

    // Step 7 — the file must end exactly where the DAG does.
    let extra = reader.remaining();
    if extra != 0 {
        return Err(OtsError::TrailingBytes {
            extra: extra as u64,
        });
    }

    Ok((OtsArtifact { attestations }, shape))
}

/// Walk the DAG iteratively, executing ops and collecting attestations.
fn walk(
    reader: &mut Reader<'_>,
    start_digest: &[u8],
) -> Result<(Vec<OtsAttestation>, OtsShape), OtsError> {
    let mut attestations: Vec<OtsAttestation> = Vec::new();
    let mut shape = OtsShape {
        max_value_bytes: start_digest.len() as u32,
        ..OtsShape::default()
    };
    let mut ops: u32 = 0;
    let mut walk = Walk {
        root: Frame {
            value: Some(start_digest.to_vec()),
            depth: 0,
            children: 0,
            closes_parent: false,
        },
        rest: Vec::new(),
    };

    loop {
        // The tag that begins the next child of the current node. A `0xff`
        // says "another child follows"; anything else *is* the last child's
        // tag.
        let first = reader.read_byte()?;
        let is_last_child = first != TAG_FORK;

        // Rule f — width, counted at the child's start so that an over-wide
        // node is rejected before any of its content is read.
        {
            let top = walk.top();
            top.children = top.children.saturating_add(1);
            shape.max_width = shape.max_width.max(top.children);
            if top.children > MAX_OTS_BRANCH_WIDTH {
                return Err(OtsError::BranchTooWide {
                    limit: MAX_OTS_BRANCH_WIDTH,
                });
            }
        }

        let child_tag = if is_last_child {
            first
        } else {
            reader.read_byte()?
        };

        if child_tag == TAG_ATTESTATION {
            // Rule g — count before reading anything about the attestation.
            if attestations.len() as u64 >= u64::from(MAX_OTS_ATTESTATIONS) {
                return Err(OtsError::TooManyAttestations {
                    limit: MAX_OTS_ATTESTATIONS,
                });
            }
            let commitment = walk.top_ref().value.clone();
            let (attestation, declared) = parse_attestation(reader, commitment)?;
            shape.max_attestation_payload_bytes = shape.max_attestation_payload_bytes.max(declared);
            attestations.push(attestation);
            shape.attestations = shape.attestations.saturating_add(1);

            if is_last_child && walk.complete_top() {
                break;
            }
            continue;
        }

        // Otherwise a child is an op followed by its subtree.
        let Some(op) = OpKind::from_tag(child_tag) else {
            return Err(OtsError::UnknownOp { tag: child_tag });
        };

        // Rule b — depth of the child being entered, before rule c, so a
        // single over-long chain reports `too-deep` and not `too-many-ops`
        // (D58 §9.3).
        let depth = walk.top_ref().depth.saturating_add(1);
        shape.max_depth = shape.max_depth.max(depth);
        if depth > MAX_OTS_DEPTH {
            return Err(OtsError::TooDeep {
                limit: MAX_OTS_DEPTH,
            });
        }

        // Rule c — running op total.
        ops = ops.saturating_add(1);
        shape.ops = ops;
        if ops > MAX_OTS_OPS {
            return Err(OtsError::TooManyOps { limit: MAX_OTS_OPS });
        }

        // Rule d — the operand length, checked **before** the operand is
        // read. Only append and prepend have one.
        let operand: &[u8] = if op.takes_operand() {
            let declared = reader.read_varuint()?;
            if declared > u64::from(MAX_OTS_OPERAND_BYTES) {
                return Err(OtsError::OperandTooLong {
                    limit: MAX_OTS_OPERAND_BYTES,
                    declared,
                });
            }
            shape.max_operand_bytes = shape.max_operand_bytes.max(declared as u32);
            reader.read_bytes(declared)?
        } else {
            &[]
        };

        // Rule e lives inside `exec::apply`, checked before allocating.
        let value = exec::apply(op, walk.top_ref().value.as_deref(), operand)?;
        if let Some(bytes) = value.as_deref() {
            shape.max_value_bytes = shape.max_value_bytes.max(bytes.len() as u32);
        }
        walk.rest.push(Frame {
            value,
            depth,
            children: 0,
            closes_parent: is_last_child,
        });
    }

    Ok((attestations, shape))
}

/// Parse one attestation, with its payload **sub-sliced** to the declared
/// length.
///
/// This is D58 §4's fix and the reason
/// `anchor-ots-attestation-payload-not-consumed` exists. The rejected crate
/// read the declared length and then **ignored it**, parsing the height or
/// the URI out of the *outer* stream; measured, a 90-byte `.ots` therefore
/// made that crate report `bitcoin(height=1)` **and** `pending(uri="ab")`
/// where `python-opentimestamps` reports one Bitcoin attestation. Sealer-
/// authored bytes showing different anchors to different verifiers is what
/// antseal exists to deny.
fn parse_attestation(
    reader: &mut Reader<'_>,
    commitment: Option<Vec<u8>>,
) -> Result<(OtsAttestation, u32), OtsError> {
    let tag = read_attestation_tag(reader)?;

    // Rule h — the declared payload length, checked **before** the bytes are
    // read. The 80-byte `.ots` of D58 §3.1 dies here.
    let declared = reader.read_varuint()?;
    if declared > u64::from(MAX_OTS_ATTESTATION_PAYLOAD_BYTES) {
        return Err(OtsError::AttestationPayloadTooLong {
            limit: MAX_OTS_ATTESTATION_PAYLOAD_BYTES,
            declared,
        });
    }
    let payload = reader.read_bytes(declared)?;
    // `declared <= MAX_OTS_ATTESTATION_PAYLOAD_BYTES`, so the cast is exact.
    let payload_len = declared as u32;

    if tag == PENDING_TAG {
        let uri = parse_pending_uri(payload)?;
        return Ok((OtsAttestation::Pending { uri, commitment }, payload_len));
    }
    if tag == BITCOIN_TAG {
        let height = parse_bitcoin_height(payload)?;
        return Ok((
            OtsAttestation::Bitcoin {
                height,
                merkle_root: commitment,
            },
            payload_len,
        ));
    }
    // An attestation type this verifier does not know: skipped structurally,
    // carried as evidence, never verified. **The payload bytes are
    // deliberately not retained** — only the length (D58 §10.2).
    Ok((
        OtsAttestation::UnknownType { tag, payload_len },
        payload_len,
    ))
}

fn read_attestation_tag(reader: &mut Reader<'_>) -> Result<[u8; ATTESTATION_TAG_LEN], OtsError> {
    let bytes = reader.read_bytes(ATTESTATION_TAG_LEN as u64)?;
    let mut tag = [0_u8; ATTESTATION_TAG_LEN];
    for (slot, byte) in tag.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    Ok(tag)
}

/// A pending attestation's payload is a varbytes UTF-8 calendar URI, and
/// **nothing else** — rule i.
fn parse_pending_uri(payload: &[u8]) -> Result<String, OtsError> {
    let mut sub = Reader::new(payload);
    let len = sub.read_varuint().map_err(in_payload)?;
    let uri = sub.read_bytes(len).map_err(in_payload)?;
    if sub.remaining() != 0 {
        return Err(OtsError::AttestationPayloadNotConsumed {
            defect: PayloadDefect::Leftover,
        });
    }
    String::from_utf8(uri.to_vec()).map_err(|_| OtsError::AttestationPayloadNotConsumed {
        defect: PayloadDefect::NotUtf8,
    })
}

/// A Bitcoin attestation's payload is a varuint block height, and **nothing
/// else** — rule i. D58 §4's weaker instance lives here too: fed a
/// `len = 1` around a 3-byte height, the rejected crate reported
/// `height = 16384` and re-serialised with `len = 3`.
fn parse_bitcoin_height(payload: &[u8]) -> Result<u64, OtsError> {
    let mut sub = Reader::new(payload);
    let height = sub.read_varuint().map_err(in_payload)?;
    if sub.remaining() != 0 {
        return Err(OtsError::AttestationPayloadNotConsumed {
            defect: PayloadDefect::Leftover,
        });
    }
    Ok(height)
}

/// Re-label a sub-reader failure.
///
/// A read past the end of a *payload sub-slice* is not a truncated file — the
/// bytes are there, the attestation's own length header lied about them. An
/// over-long varuint stays what it is: the 9-byte bound is one rule and holds
/// everywhere.
const fn in_payload(error: OtsError) -> OtsError {
    match error {
        OtsError::Truncated { .. } => OtsError::AttestationPayloadNotConsumed {
            defect: PayloadDefect::ShortRead,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varuint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value % VARUINT_RADIX) as u8;
            value /= VARUINT_RADIX;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | VARUINT_CONTINUE);
        }
    }

    #[test]
    fn varuints_round_trip_including_the_largest_encodable_value() {
        for value in [
            0,
            1,
            127,
            128,
            16_383,
            16_384,
            449_397,
            449_399,
            u64::from(u32::MAX),
            // 2^63 - 1 — the largest value nine 7-bit groups can carry, and
            // the reason no accumulator here can overflow.
            9_223_372_036_854_775_807,
        ] {
            let encoded = varuint(value);
            assert!(
                encoded.len() <= MAX_VARUINT_BYTES,
                "{value} needs {} bytes",
                encoded.len()
            );
            let mut reader = Reader::new(&encoded);
            assert_eq!(reader.read_varuint(), Ok(value));
            assert_eq!(reader.remaining(), 0);
        }
    }

    /// Non-minimal encodings are accepted, deliberately (D58 §10.3 rule 3):
    /// `.ots` is a foreign format and rejecting a padded varuint a future
    /// calendar emits would be a rejection the reference does not make.
    #[test]
    fn a_non_minimal_varuint_is_accepted() {
        let encoded = [0x81, 0x80, 0x80, 0x00];
        let mut reader = Reader::new(&encoded);
        assert_eq!(reader.read_varuint(), Ok(1));
    }

    #[test]
    fn a_ten_byte_varuint_is_rejected_without_reading_an_eleventh() {
        let encoded = [0x80_u8; 16];
        let mut reader = Reader::new(&encoded);
        assert_eq!(
            reader.read_varuint(),
            Err(OtsError::VarintTooLong { offset: 0 })
        );
        assert_eq!(
            reader.remaining(),
            16 - MAX_VARUINT_BYTES,
            "the reader must stop at the bound, not run to the end"
        );
    }

    #[test]
    fn read_bytes_never_allocates_from_a_declared_length() {
        // 549 755 813 887 — D58 §3.1's allocation, requested against 4 bytes
        // of input. It must be an error, not a 512 GiB `Vec`.
        let mut reader = Reader::new(&[1, 2, 3, 4]);
        assert_eq!(
            reader.read_bytes(549_755_813_887),
            Err(OtsError::Truncated {
                offset: 0,
                needed: 549_755_813_883,
            })
        );
    }

    #[test]
    fn the_magic_is_thirty_one_bytes_and_matches_every_committed_fixture() {
        assert_eq!(MAGIC.len(), 31);
        for fixture in super::super::ALL_OTS_FIXTURES {
            assert_eq!(
                fixture.get(..MAGIC.len()),
                Some(MAGIC.as_slice()),
                "fixture does not open with the container magic"
            );
        }
    }
}
