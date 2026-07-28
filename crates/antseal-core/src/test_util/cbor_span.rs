//! **A span-locating cursor over canonical CBOR** (task F25), built on the
//! F3 decoder's own public surface — never beside it.
//!
//! # Why this exists
//!
//! F15's splicing primitives ([`super::tamper_rows_format`]) are deliberately
//! built out of [`CanonicalDecoder::map`] plus [`CanonicalDecoder::position`],
//! so a fixture can never disagree with the decoder about where a map head
//! ends. That surface locates exactly two points: the **head** of the map at
//! offset 0, and the **end** of the whole slice. Every F15 mutation is
//! therefore an insertion at one of those two points, a head rewrite, or a
//! fixed-offset splice over the body's first entry — whose two bytes are
//! pinned by the registry.
//!
//! Three pieces of owed work need an *arbitrary* item's byte span instead:
//!
//! - D77 §6's mirror-only row, which must flip one **nested** unit's `kind`
//!   (`FileEntry::new` refuses to construct the shape, so a byte mutation is
//!   the only route) — landed by [`super::tamper_rows_caps`];
//! - most of F24's `cbor-` codes, which need a mutation at a nested
//!   `tstr`/`uint`/container rather than at a top-level head — landed by
//!   `super::tamper_rows_cbor`;
//! - per-layer variants of `cbor-truncated`, which need a cut at a chosen
//!   item boundary.
//!
//! The alternative — pinned byte offsets — is what the Q8 checker's own
//! `case_mut` comment argues against by experience: index-anchored fixtures
//! broke every time a row landed and said nothing useful when they did.
//!
//! # How it is built (and what it deliberately is not)
//!
//! One private recursive `skip_item`, driven entirely by
//! [`CanonicalDecoder::peek_kind`] plus the typed reads. There is **no second
//! CBOR implementation** here: no head byte is parsed, no length argument is
//! decoded, no shortest-form rule is re-stated. Every byte this module reports
//! an offset for was located by advancing the F3 decoder itself, which is what
//! makes [`item_span`] incapable of disagreeing with
//! [`check_canonical`](crate::codec::decode::check_canonical) — and what
//! [`tests::every_item_of_a_golden_document_is_itself_canonical`] asserts
//! rather than assumes.
//!
//! Two deliberate restrictions, both consequences of using the *schema*-shaped
//! surface rather than the generic walker:
//!
//! 1. **Map keys must be unsigned integers**, because [`MapReader::next_key`]
//!    enforces the v1 registry's key discipline (registry §1). A map with a
//!    `tstr` key is canonical CBOR that this cursor refuses. Every v1 document
//!    is uint-keyed, so the restriction is invisible where the cursor is used
//!    and it is *stricter*, never laxer, than `check_canonical`.
//! 2. **A negative integer below `i64::MIN` is not skippable**, because
//!    [`CanonicalDecoder::i64`] is the only public read for major type 1 and
//!    it reports `cbor-int-out-of-range` there. No v1 schema slot holds a
//!    negative integer at all (F24 records the same fact from the other
//!    direction), so this too is unreachable in practice.
//!
//! Both restrictions fail *closed*: [`item_span`] returns `None`, which a
//! fixture turns into a loud construction failure rather than a wrong splice.
//!
//! # Depth
//!
//! `skip_item` carries its own [`MAX_CBOR_DEPTH`] guard. F25's task text
//! claimed "recursion is already depth-bounded"; it is not — the bound lives
//! in `CanonicalDecoder::walk_item`, which is **private**, so nothing on the
//! public surface this module is built from carries it. The guard here is
//! per-invocation: [`span_at_path`] re-anchors a fresh cursor at each step, so
//! it bounds stack depth (the reason the bound exists) rather than absolute
//! document depth. v1's structural maximum is 6 containers (registry §7.6.3),
//! so no v1 document comes near either reading.
//!
//! # Addressing
//!
//! [`Step`] names one descent — a map entry's value, a map entry's key, or an
//! array element — so a blocked fixture is expressed as
//! `(path-to-item, mutation)` rather than as an offset. Paths do **not** cross
//! an embedded `bstr` boundary on purpose: a length-changing mutation inside
//! an embedded document must re-head the enclosing `bstr`, and the honest way
//! to do that is to decode the inner bytes out, mutate, and re-encode the
//! wrapper (F15's `body_fixture` does exactly this). A path that silently
//! spliced across the boundary would leave a stale length head — a *second*
//! mutation, which is precisely what the one-mutation-per-fixture rule forbids.

use crate::codec::caps::MAX_CBOR_DEPTH;
use crate::codec::decode::{CanonicalDecoder, DecodeError, ItemKind, MapReader};

// ---------------------------------------------------------------------------
// the span type
// ---------------------------------------------------------------------------

/// The byte extent of one canonical CBOR item, split at the end of its head.
///
/// Offsets are relative to the slice the span was located in, and both halves
/// are useful: a value-level mutation replaces `start..end`, while a
/// container-length mutation replaces `start..head_end` and leaves the
/// elements alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemSpan {
    /// Offset of the item's first head byte.
    pub start: usize,
    /// Offset one past the item's head — the first payload/element byte.
    /// Equal to `end` for an integer, whose head *is* the whole item.
    pub head_end: usize,
    /// Offset one past the item's last byte.
    pub end: usize,
}

impl ItemSpan {
    /// `(start, end)` — the F25-named pair.
    #[must_use]
    pub const fn range(self) -> (usize, usize) {
        (self.start, self.end)
    }

    /// Total byte width of the item.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        self.end - self.start
    }

    /// Byte width of the item's head alone.
    #[must_use]
    pub const fn head_len(self) -> usize {
        self.head_end - self.start
    }
}

// ---------------------------------------------------------------------------
// the cursor
// ---------------------------------------------------------------------------

/// Defensive error for arithmetic the decoder's own advance has already made
/// impossible — surfaced as an error, never a panic (project rule: library
/// code returns errors).
fn defensive(position: usize) -> DecodeError {
    DecodeError::Malformed {
        position: position as u64,
    }
}

/// Skip exactly one item, returning the offset one past its **head**.
///
/// The decoder is left positioned one past the item's last byte, so a caller
/// gets `end` from [`CanonicalDecoder::position`].
fn skip_item(d: &mut CanonicalDecoder<'_>, depth: u16) -> Result<usize, DecodeError> {
    if depth > MAX_CBOR_DEPTH {
        return Err(DecodeError::NestingTooDeep {
            position: d.position() as u64,
        });
    }
    let start = d.position();
    match d.peek_kind()? {
        ItemKind::Unsigned => {
            d.u64()?;
            Ok(d.position())
        }
        ItemKind::Negative => {
            // The only public read for major type 1. A nint below `i64::MIN`
            // is reported as `cbor-int-out-of-range` here; module docs record
            // why that is unreachable in v1.
            d.i64()?;
            Ok(d.position())
        }
        ItemKind::Bytes => {
            let payload = d.bytes()?;
            d.position()
                .checked_sub(payload.len())
                .ok_or_else(|| defensive(start))
        }
        ItemKind::Text => {
            let payload = d.str()?;
            d.position()
                .checked_sub(payload.len())
                .ok_or_else(|| defensive(start))
        }
        ItemKind::Array => {
            let count = d.array()?;
            let head_end = d.position();
            for _ in 0..count {
                skip_item(d, depth.saturating_add(1))?;
            }
            Ok(head_end)
        }
        ItemKind::Map => {
            let mut reader = d.map()?;
            let head_end = d.position();
            while reader.next_key(d)?.is_some() {
                skip_item(d, depth.saturating_add(1))?;
            }
            Ok(head_end)
        }
    }
}

/// The span of the item starting at `at`, or `None` if there is no canonical
/// item there (module docs: the cursor fails closed).
#[must_use]
pub fn item_span(bytes: &[u8], at: usize) -> Option<ItemSpan> {
    let tail = bytes.get(at..)?;
    let mut d = CanonicalDecoder::new(tail);
    let head_end = skip_item(&mut d, 0).ok()?;
    Some(ItemSpan {
        start: at,
        head_end: at.checked_add(head_end)?,
        end: at.checked_add(d.position())?,
    })
}

/// F25's named signature: `(start, end)` of the next item at `at`.
#[must_use]
pub fn span_of_next_item(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    item_span(bytes, at).map(ItemSpan::range)
}

// ---------------------------------------------------------------------------
// addressing
// ---------------------------------------------------------------------------

/// One descent into the item at the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Into the map at the cursor: the **value** of the entry keyed `k`.
    Value(u64),
    /// Into the map at the cursor: the entry keyed `k`'s **key item** itself.
    Key(u64),
    /// Into the array at the cursor: element `i`, zero-based.
    Index(u64),
}

/// Offset of the item one [`Step`] below the item at `at`.
fn descend(bytes: &[u8], at: usize, step: Step) -> Option<usize> {
    let tail = bytes.get(at..)?;
    let mut d = CanonicalDecoder::new(tail);
    match step {
        Step::Value(target) | Step::Key(target) => {
            let mut reader: MapReader = d.map().ok()?;
            loop {
                let key_start = d.position();
                let key = reader.next_key(&mut d).ok()??;
                let value_start = d.position();
                if key == target {
                    let offset = match step {
                        Step::Key(_) => key_start,
                        _ => value_start,
                    };
                    return at.checked_add(offset);
                }
                skip_item(&mut d, 1).ok()?;
            }
        }
        Step::Index(index) => {
            let count = d.array().ok()?;
            if index >= count {
                return None;
            }
            for _ in 0..index {
                skip_item(&mut d, 1).ok()?;
            }
            at.checked_add(d.position())
        }
    }
}

/// The span of the item addressed by `path`, relative to the top-level item
/// at offset 0. An empty path addresses the top-level item itself.
#[must_use]
pub fn span_at_path(bytes: &[u8], path: &[Step]) -> Option<ItemSpan> {
    let mut at = 0usize;
    for step in path {
        at = descend(bytes, at, *step)?;
    }
    item_span(bytes, at)
}

// ---------------------------------------------------------------------------
// splicing
// ---------------------------------------------------------------------------

/// Replace `bytes[at..at + old_len]` with `new`.
fn splice(bytes: &[u8], at: usize, old_len: usize, new: &[u8]) -> Option<Vec<u8>> {
    let before = bytes.get(..at)?;
    let after = bytes.get(at.checked_add(old_len)?..)?;
    let mut out = Vec::with_capacity(before.len() + new.len() + after.len());
    out.extend_from_slice(before);
    out.extend_from_slice(new);
    out.extend_from_slice(after);
    Some(out)
}

/// Replace the **whole item** at `path` with `new_item`.
#[must_use]
pub fn splice_item_at_path(bytes: &[u8], path: &[Step], new_item: &[u8]) -> Option<Vec<u8>> {
    let span = span_at_path(bytes, path)?;
    splice(bytes, span.start, span.byte_len(), new_item)
}

/// Replace only the **head** of the container at `path`, leaving its elements
/// byte-identical — the shape a claimed-length mutation needs.
#[must_use]
pub fn splice_head_at_path(bytes: &[u8], path: &[Step], new_head: &[u8]) -> Option<Vec<u8>> {
    let span = span_at_path(bytes, path)?;
    splice(bytes, span.start, span.head_len(), new_head)
}

/// The shortest-form (canonical) head for major type `major` carrying the
/// argument `arg`.
///
/// Emitting a head is *encoding*, not decoding, and it is the one thing this
/// module cannot borrow from the F3 decoder — F2's builders refuse to emit a
/// head whose claimed count the payload does not deliver, which is exactly
/// what a cap fixture is. It is the same seven-line writer `tests/parser_caps.rs`
/// hand-rolls for the same reason, and every head it produces is shortest-form,
/// so a fixture built with it exercises the cap rather than the head-canonicality
/// check that precedes every cap (D10 §4).
#[must_use]
pub fn canonical_head(major: u8, arg: u64) -> Vec<u8> {
    let mt = major << 5;
    if arg <= 23 {
        vec![mt | (arg as u8)]
    } else if arg <= u64::from(u8::MAX) {
        vec![mt | 24, arg as u8]
    } else if arg <= u64::from(u16::MAX) {
        let mut v = vec![mt | 25];
        v.extend_from_slice(&(arg as u16).to_be_bytes());
        v
    } else if arg <= u64::from(u32::MAX) {
        let mut v = vec![mt | 26];
        v.extend_from_slice(&(arg as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![mt | 27];
        v.extend_from_slice(&arg.to_be_bytes());
        v
    }
}

/// Major type 0 (unsigned integer).
pub const MAJOR_UINT: u8 = 0;
/// Major type 2 (byte string).
pub const MAJOR_BYTES: u8 = 2;
/// Major type 4 (array).
pub const MAJOR_ARRAY: u8 = 4;

// ---------------------------------------------------------------------------
// exhaustive enumeration (the agreement check's engine)
// ---------------------------------------------------------------------------

/// Every item of a document, outermost first, as spans.
///
/// The enumeration is the cursor applied to itself: an item's own span, then
/// every child's. It is what lets the agreement property be stated over *all*
/// items of a golden vector rather than over a hand-picked few.
#[must_use]
pub fn all_item_spans(bytes: &[u8]) -> Option<Vec<ItemSpan>> {
    let mut out = Vec::new();
    collect(bytes, 0, 0, &mut out)?;
    Some(out)
}

fn collect(bytes: &[u8], at: usize, depth: u16, out: &mut Vec<ItemSpan>) -> Option<()> {
    if depth > MAX_CBOR_DEPTH {
        return None;
    }
    let span = item_span(bytes, at)?;
    out.push(span);
    let tail = bytes.get(at..)?;
    let mut d = CanonicalDecoder::new(tail);
    // How many child items follow the head: `n` for an array, `2n` for a map
    // (each entry is a key item and a value item). A leaf's payload is bytes,
    // not items, so it has none and nothing below is checked.
    let children = match d.peek_kind().ok()? {
        ItemKind::Array => d.array().ok()?,
        ItemKind::Map => d.map().ok()?.remaining().checked_mul(2)?,
        ItemKind::Unsigned | ItemKind::Negative | ItemKind::Bytes | ItemKind::Text => {
            return Some(());
        }
    };
    let mut child = span.head_end;
    for _ in 0..children {
        collect(bytes, child, depth.saturating_add(1), out)?;
        child = item_span(bytes, child)?.end;
    }
    // The children exactly fill the container — the enumeration cannot end
    // short of, or past, the span the cursor reported for the parent.
    (child == span.end).then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::decode::check_canonical;
    use crate::manifest::Manifest;
    use crate::test_util::bundle_fixtures::{Selection, build, shapes};

    /// The two documents every F15 fixture derives from, plus the manifest
    /// body they nest — real sealed artifacts, not synthetic maps.
    fn documents() -> Vec<(&'static str, Vec<u8>)> {
        documents_with_minima()
            .into_iter()
            .map(|(name, bytes, _)| (name, bytes))
            .collect()
    }

    /// The same documents, each with the item count it must at least contain —
    /// pinned so a document that silently shrank (or an enumeration that
    /// silently stopped early) cannot make the agreement checks vacuous.
    fn documents_with_minima() -> Vec<(&'static str, Vec<u8>, usize)> {
        let work = shapes::single_binary().with_ed25519_only_policy();
        let built = build(&work, &Selection::all(1));
        let envelope = built.manifest.clone();
        let body = Manifest::decode(&envelope)
            .expect("the base manifest decodes")
            .body_bytes()
            .to_vec();
        vec![
            // bundle: ~60 items; envelope: exactly 7 ({0: bstr, 1: {0: bstr}});
            // body: ~50.
            ("bundle", built.bytes, 40),
            ("manifest envelope", envelope, 7),
            ("manifest body", body, 30),
        ]
    }

    /// **F25 accept, clause 1.** Every item the cursor locates is itself a
    /// complete canonical CBOR document — which is `check_canonical`'s own
    /// verdict, asked of the exact byte range the cursor reports. The two can
    /// therefore not disagree about where an item begins or ends.
    #[test]
    fn every_item_of_a_golden_document_is_itself_canonical() {
        for (name, bytes, minimum) in documents_with_minima() {
            let spans = all_item_spans(&bytes).unwrap_or_else(|| panic!("{name}: enumeration"));
            assert!(
                spans.len() >= minimum,
                "{name}: {} items, fewer than the pinned {minimum}",
                spans.len()
            );
            for span in &spans {
                let item = bytes
                    .get(span.start..span.end)
                    .unwrap_or_else(|| panic!("{name}: span {span:?} out of range"));
                assert_eq!(
                    check_canonical(item),
                    Ok(()),
                    "{name}: the item at {span:?} is not a canonical document"
                );
            }
            // The outermost span is the whole document, so the enumeration is
            // anchored rather than merely internally consistent.
            assert_eq!(spans[0].start, 0);
            assert_eq!(spans[0].end, bytes.len());
        }
    }

    /// **F25 accept, clause 1 (the splice half).** Walking an item's span and
    /// re-splicing it unchanged reproduces the input byte for byte — for
    /// *every* item, not for a chosen one.
    #[test]
    fn re_splicing_any_item_unchanged_reproduces_the_input() {
        for (name, bytes) in documents() {
            for span in all_item_spans(&bytes).unwrap_or_else(|| panic!("{name}: enumeration")) {
                let item = bytes.get(span.start..span.end).expect("in range");
                let rebuilt = splice(&bytes, span.start, span.byte_len(), item)
                    .unwrap_or_else(|| panic!("{name}: splice at {span:?}"));
                assert_eq!(rebuilt, bytes, "{name}: re-splicing {span:?} changed bytes");
                // The head/payload split is exact too: head ‖ payload is the
                // item, so a head-only rewrite cannot silently eat a payload
                // byte.
                assert!(span.head_end >= span.start && span.head_end <= span.end);
                let head = bytes.get(span.start..span.head_end).expect("head");
                let payload = bytes.get(span.head_end..span.end).expect("payload");
                let mut joined = head.to_vec();
                joined.extend_from_slice(payload);
                assert_eq!(joined, item);
            }
        }
    }

    /// A path reaches a nested item, and the item it reaches is the one the
    /// registry says is there: the base manifest body's file 0, unit 0,
    /// `kind` (key 1) — the byte D77's mirror-only fixture flips.
    #[test]
    fn a_path_reaches_the_nested_unit_kind() {
        use crate::manifest::registry::key as manifest_key;

        let (_, body) = documents()
            .into_iter()
            .find(|(name, _)| *name == "manifest body")
            .expect("the body document");
        let path = [
            Step::Value(manifest_key::body::FILES),
            Step::Index(0),
            Step::Value(manifest_key::file::UNITS),
            Step::Index(0),
            Step::Value(manifest_key::unit::KIND),
        ];
        let span = span_at_path(&body, &path).expect("the nested unit kind");
        assert_eq!(span.byte_len(), 1, "the kind value is a one-byte uint");
        assert_eq!(
            body.get(span.start),
            Some(&0u8),
            "the golden unit is `normal` (wire 0)"
        );
        // And the key item beside it really is key 1.
        let key_path = [
            Step::Value(manifest_key::body::FILES),
            Step::Index(0),
            Step::Value(manifest_key::file::UNITS),
            Step::Index(0),
            Step::Key(manifest_key::unit::KIND),
        ];
        let key_span = span_at_path(&body, &key_path).expect("the nested unit kind's key");
        assert_eq!(key_span.end, span.start, "the key immediately precedes it");
        assert_eq!(body.get(key_span.start), Some(&0x01u8));
    }

    /// A path that names a key the map does not carry, or an index past the
    /// array's end, resolves to `None` — it never falls through to a
    /// neighbouring item.
    #[test]
    fn a_path_that_does_not_resolve_returns_none() {
        let (_, body) = documents()
            .into_iter()
            .find(|(name, _)| *name == "manifest body")
            .expect("the body document");
        assert!(span_at_path(&body, &[Step::Value(9_999)]).is_none());
        assert!(
            span_at_path(&body, &[Step::Index(0)]).is_none(),
            "not an array"
        );
        assert!(
            span_at_path(
                &body,
                &[
                    Step::Value(crate::manifest::registry::key::body::FILES),
                    Step::Index(7)
                ]
            )
            .is_none()
        );
    }

    /// The cursor fails closed on input `check_canonical` also refuses, and
    /// on the two shapes the module docs record as out of its reach.
    #[test]
    fn the_cursor_fails_closed() {
        // Truncated, malformed, indefinite, float, tag — all refused.
        for bytes in [
            &[0x18u8][..],       // truncated argument
            &[0x1c],             // reserved additional info
            &[0x9f, 0xff],       // indefinite array
            &[0xf9, 0x3c, 0x00], // float
            &[0xc0, 0x00],       // tag
        ] {
            assert!(item_span(bytes, 0).is_none(), "input {bytes:02x?}");
            assert!(check_canonical(bytes).is_err(), "input {bytes:02x?}");
        }
        // A tstr-keyed map is canonical CBOR the cursor deliberately refuses
        // (module docs, restriction 1) — stricter than `check_canonical`,
        // never laxer.
        let tstr_keyed = [0xa1u8, 0x61, 0x61, 0x00];
        assert_eq!(check_canonical(&tstr_keyed), Ok(()));
        assert!(item_span(&tstr_keyed, 0).is_none());
        // Out of range start.
        assert!(item_span(&[0x00], 9).is_none());
    }

    /// A head rewrite touches the head and nothing else.
    #[test]
    fn a_head_splice_preserves_the_elements() {
        use crate::manifest::registry::key as manifest_key;

        let (_, body) = documents()
            .into_iter()
            .find(|(name, _)| *name == "manifest body")
            .expect("the body document");
        let path = [Step::Value(manifest_key::body::FILES)];
        let span = span_at_path(&body, &path).expect("the files array");
        let elements = body.get(span.head_end..span.end).expect("elements");
        let mutated = splice_head_at_path(&body, &path, &canonical_head(MAJOR_ARRAY, 1_000))
            .expect("head splice");
        assert_eq!(
            mutated.len(),
            body.len() + 2,
            "array(1) is one byte; array(1000) is three"
        );
        assert!(
            mutated
                .windows(elements.len())
                .any(|window| window == elements),
            "the elements survived the head rewrite verbatim"
        );
    }

    /// [`canonical_head`] emits shortest-form heads at every width boundary —
    /// the property that makes a cap fixture exercise the cap rather than the
    /// head-canonicality check that precedes it (D10 §4).
    #[test]
    fn the_head_writer_is_shortest_form_at_every_boundary() {
        for arg in [0u64, 23, 24, 255, 256, 65_535, 65_536, u64::from(u32::MAX)] {
            let head = canonical_head(MAJOR_BYTES, arg);
            let mut item = head.clone();
            item.resize(head.len() + usize::try_from(arg).expect("small"), 0);
            assert_eq!(
                check_canonical(&item),
                Ok(()),
                "bstr head for {arg} is not canonical"
            );
        }
        // One over `u32::MAX` takes the eight-byte width.
        assert_eq!(
            canonical_head(MAJOR_ARRAY, u64::from(u32::MAX) + 1).len(),
            9
        );
    }
}
