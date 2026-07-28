//! The **diagnostic sidecar** renderer shared by the `manifest` (F12) and
//! `bundle` (F13) vector kinds: a faithful, lossless, structural rendering of
//! one canonical CBOR item as JSON.
//!
//! # Why it exists
//!
//! F12/F13 commit *bytes*. Bytes alone cannot be reviewed, and cannot be
//! cross-checked by an implementation that shares no code with ours: an
//! independent decoder handed only a hex string has nothing to disagree
//! *with*. The sidecar is that second artifact — the same data item written
//! out structurally — and it is what **F14** (the independent-CBOR
//! cross-check, Python `cbor2 ==6.1.3`, decision D12) compares against:
//!
//! 1. `cbor2.loads(vector_bytes)` → render through the rules below → must
//!    equal the committed `diagnostic` **exactly**;
//! 2. re-encode the rendered item per RFC 8949 §4.2.1 → must equal the
//!    committed bytes.
//!
//! Step 1 catches "our encoder and our decoder agree with each other and are
//! both wrong"; step 2 catches a non-canonical encoding our own strict
//! decoder somehow admits. Neither is possible if the sidecar is generated
//! by re-serializing our own decode of our own bytes — so the sidecar is
//! produced by [`render`], which walks the committed bytes with the strict
//! F3 decoder and never consults the schema types at all.
//!
//! # The rendering (the whole contract — F14 implements exactly this)
//!
//! | CBOR item | JSON |
//! | --- | --- |
//! | unsigned integer (major 0) | a JSON number, non-negative |
//! | negative integer (major 1) | a JSON number, negative |
//! | byte string (major 2) | `{"b": "<lowercase hex>"}` |
//! | text string (major 3) | a JSON string |
//! | array (major 4) | a JSON array |
//! | map (major 5) | `{"m": [[key, value], …]}`, entries in wire order |
//!
//! The form is **unambiguous by construction**: a JSON object is either a
//! byte string or a map, told apart by its single key; nothing else renders
//! as an object. Map entries are pairs rather than a JSON object because
//! every key in the v1 registry is an *integer*, and JSON object keys are
//! strings — pairs keep the key's type and the wire order visible, and the
//! wire order is itself part of what the vector pins (deterministic CBOR
//! requires ascending keys, RFC 8949 §4.2.1).
//!
//! Integers render as JSON numbers and are therefore exact for any decoder
//! with arbitrary-precision or 64-bit integers (Python, Rust, Go). A reader
//! whose JSON numbers are IEEE doubles must treat values above 2^53 with
//! care; no value in any committed v1 vector approaches that bound, and
//! [`render`] rejects one that would (see [`DiagError::IntTooLargeForJson`])
//! rather than emit a number a reader could silently round.
//!
//! # Embedded CBOR is **not** recursed into
//!
//! A manifest envelope's `body` is a byte string whose contents are
//! themselves CBOR; so is a bundle's embedded manifest. [`render`] renders
//! them as byte strings, exactly as the wire says, because a generic walker
//! that guessed which byte strings are "really" CBOR would be inventing
//! schema knowledge it does not have — and because the layer boundary is
//! precisely what F6/F9's three-layer strict decode is about. Each layer is
//! rendered separately and named separately in the vector (`envelope`,
//! `body`, …), so the cross-check exercises all of them and the nesting
//! stays explicit.
//!
//! # WASM-safety
//!
//! Pure in-memory walking over the F3 decoder; no I/O, no optional
//! dependency, so this lives on the `test-vectors` tier with the rest of the
//! vector executors (P14).

use serde_json::{Value, json};

use crate::codec::{CanonicalDecoder, DecodeError, ItemKind};

/// The largest integer this renderer will emit as a JSON number.
///
/// `2^53 - 1` — the last integer an IEEE-754 double represents exactly, and
/// therefore the last one a JSON reader with double-typed numbers can round
/// -trip. Rendering above it would produce a sidecar that some conforming
/// readers disagree with, which is the one thing a cross-check artifact must
/// never do.
pub const MAX_JSON_SAFE_INT: u64 = (1u64 << 53) - 1;

/// Why a byte string could not be rendered.
#[derive(Debug, thiserror::Error)]
pub enum DiagError {
    /// The input is not canonical CBOR under the F3 profile (spec line 73).
    #[error("not canonical CBOR: {source}")]
    Cbor {
        /// The strict decoder's typed rejection.
        #[from]
        source: DecodeError,
    },
    /// An integer too large to render as an exactly-readable JSON number.
    #[error(
        "integer {value} exceeds the JSON-safe bound {MAX_JSON_SAFE_INT}: a sidecar must not \
         carry a number some conforming readers round"
    )]
    IntTooLargeForJson {
        /// The offending value.
        value: u64,
    },
}

/// Render one canonical CBOR item as its diagnostic sidecar (module docs).
///
/// The input must be exactly one item with no trailing bytes — the same
/// contract as [`crate::codec::decode::check_canonical`], and the reason a
/// sidecar can never describe more (or less) than the bytes it accompanies.
///
/// # Errors
///
/// [`DiagError::Cbor`] when the bytes are not canonical CBOR, and
/// [`DiagError::IntTooLargeForJson`] for an integer outside the JSON-safe
/// range.
pub fn render(bytes: &[u8]) -> Result<Value, DiagError> {
    let mut decoder = CanonicalDecoder::new(bytes);
    let value = render_item(&mut decoder)?;
    decoder.finish()?;
    Ok(value)
}

/// Render the next item, recursing through arrays and maps.
///
/// Depth is bounded by the decoder itself: every nested read goes through
/// the F3 layer, whose `MAX_NESTING_DEPTH` cap fires before this recursion
/// can grow deep enough to matter (F11).
fn render_item(d: &mut CanonicalDecoder<'_>) -> Result<Value, DiagError> {
    match d.peek_kind()? {
        ItemKind::Unsigned => Ok(Value::from(safe_int(d.u64()?)?)),
        // Not producible by the v1 registry (uint-only keys, uint-only
        // scalars), but rendering it keeps the walker total: a sidecar that
        // could not describe some canonical input would be a sidecar with a
        // blind spot.
        ItemKind::Negative => Ok(Value::from(d.i64()?)),
        ItemKind::Bytes => Ok(json!({ "b": super::vectors::hex(d.bytes()?) })),
        ItemKind::Text => Ok(Value::from(d.str()?)),
        ItemKind::Array => {
            let count = d.array()?;
            let mut items = Vec::new();
            for _ in 0..count {
                items.push(render_item(d)?);
            }
            Ok(Value::Array(items))
        }
        ItemKind::Map => {
            let mut reader = d.map()?;
            let mut entries = Vec::new();
            // `next_key` enforces strictly-ascending unsigned keys, so the
            // wire order this preserves is *the* canonical order — a
            // reordered sidecar cannot be produced from canonical bytes.
            while let Some(key) = reader.next_key(d)? {
                let value = render_item(d)?;
                entries.push(Value::Array(vec![Value::from(safe_int(key)?), value]));
            }
            Ok(json!({ "m": Value::Array(entries) }))
        }
    }
}

fn safe_int(value: u64) -> Result<u64, DiagError> {
    if value > MAX_JSON_SAFE_INT {
        return Err(DiagError::IntTooLargeForJson { value });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode_item;

    /// Every item kind the profile admits renders to its documented form.
    #[test]
    fn each_item_kind_renders_to_its_documented_form() {
        let bytes = encode_item(|e| {
            e.map(|m| {
                m.entry(0, |e| e.u64(1))?;
                m.entry(1, |e| e.str("text"))?;
                m.entry(2, |e| e.bytes(&[0xDE, 0xAD, 0xBE, 0xEF]))?;
                m.entry(3, |e| {
                    e.array(|a| {
                        a.item(|e| e.u64(7))?;
                        a.item(|e| e.bytes(&[0x00]))
                    })
                })
            })
        })
        .expect("fixture encodes");

        assert_eq!(
            render(&bytes).expect("fixture renders"),
            json!({"m": [
                [0, 1],
                [1, "text"],
                [2, {"b": "deadbeef"}],
                [3, [7, {"b": "00"}]],
            ]})
        );
    }

    /// The rendering is unambiguous: the only JSON objects are the
    /// single-key `b`/`m` forms, so a reader never has to guess.
    #[test]
    fn objects_are_tagged_by_exactly_one_key() {
        let bytes = encode_item(|e| e.map(|m| m.entry(0, |e| e.bytes(&[1, 2])))).expect("encodes");
        let rendered = render(&bytes).expect("renders");
        let outer = rendered.as_object().expect("map renders as an object");
        assert_eq!(outer.len(), 1);
        assert!(outer.contains_key("m"));
        let inner = rendered["m"][0][1].as_object().expect("bstr is an object");
        assert_eq!(inner.len(), 1);
        assert!(inner.contains_key("b"));
    }

    /// An embedded-CBOR byte string stays a byte string: the layer boundary
    /// is deliberately visible, never silently flattened (module docs).
    #[test]
    fn embedded_cbor_is_rendered_as_a_byte_string() {
        let inner = encode_item(|e| e.map(|m| m.entry(0, |e| e.u64(1)))).expect("encodes");
        let outer = encode_item(|e| e.map(|m| m.entry(0, |e| e.bytes(&inner)))).expect("encodes");
        assert_eq!(
            render(&outer).expect("renders"),
            json!({"m": [[0, {"b": super::super::vectors::hex(&inner)}]]})
        );
    }

    /// Non-canonical input is refused, so a sidecar can only ever describe
    /// bytes the strict decoder accepts.
    #[test]
    fn non_canonical_input_is_refused() {
        // Non-shortest encoding of 1 (0x1801 instead of 0x01).
        assert!(matches!(
            render(&[0x18, 0x01]),
            Err(DiagError::Cbor {
                source: DecodeError::NonShortestInt { .. }
            })
        ));
        // Trailing bytes after a complete item.
        assert!(render(&[0x01, 0x01]).is_err());
    }

    /// The JSON-safe bound is enforced rather than hoped for.
    #[test]
    fn oversized_integers_are_refused() {
        let bytes = encode_item(|e| e.u64(MAX_JSON_SAFE_INT + 1)).expect("encodes");
        assert!(matches!(
            render(&bytes),
            Err(DiagError::IntTooLargeForJson { .. })
        ));
        let at_bound = encode_item(|e| e.u64(MAX_JSON_SAFE_INT)).expect("encodes");
        assert_eq!(
            render(&at_bound).expect("at the bound is fine"),
            Value::from(MAX_JSON_SAFE_INT)
        );
    }
}
