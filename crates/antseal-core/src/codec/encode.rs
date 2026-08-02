//! Canonical CBOR encode layer (task F2).
//!
//! Guarantees RFC 8949 §4.2.1 Core Deterministic output for everything it
//! can emit (MVP-SPEC.md line 73): shortest-form integer and length heads
//! (delegated to the pinned `minicbor` encoder, whose emitters are the
//! §4.2.1 range match — source-verified in D7), definite lengths only
//! (the indefinite `begin_*` encoder calls are simply never exposed), no
//! floats (no API accepts one), and map keys emitted in strictly
//! ascending bytewise order of their encoded form.
//!
//! The v1 wire registry (F4) uses **only unsigned integer map keys**, and
//! for shortest-form unsigned integers ascending numeric order equals
//! ascending bytewise order of the encodings (asserted by
//! `sorted_key_equivalence_*` below), so [`MapEncoder`] sorts entries by
//! their `u64` key. Callers may therefore add entries in any order; the
//! wire order is the map's own property, not the call sites'. Duplicate
//! keys are an error, never a silent overwrite.
//!
//! Scope discipline: the only way to obtain encoded bytes is
//! [`encode_item`], and every closure scope (top level, array item, map
//! value) must emit **exactly one** item — enforced at scope close — so
//! partial or over-full output can never escape. Combined with the
//! builders, output is canonical by construction and byte-identical
//! across platforms and native/WASM (nothing here depends on `usize`
//! width, pointer values, or iteration order of any hash container).

use minicbor::encode::Encoder;

use super::caps::{MAX_BUNDLE_BYTES, MAX_MANIFEST_BYTES};

/// An artifact whose **encoded** size is capped (D10 §1 rows 1–2; task
/// F53).
///
/// The other seventeen D10 caps bound something a constructor can see — a
/// list length, a `bstr` length — so F41 could enforce them where the
/// parts are assembled. These two bound the *serialization*, which exists
/// only after `encode_*` returns, so they are the one class of cap that
/// has to be checked here.
///
/// There are exactly two, and no third is coming: the manifest **body**
/// deliberately has no constant of its own (it is a `bstr` inside the
/// envelope, so `len(body) < len(envelope)` by construction), and every
/// other capped byte field is an opaque artifact already gated at
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CappedArtifact {
    /// The manifest envelope —
    /// [`MAX_MANIFEST_BYTES`](super::caps::MAX_MANIFEST_BYTES).
    ManifestEnvelope,
    /// The `.sealproof` bundle —
    /// [`MAX_BUNDLE_BYTES`](super::caps::MAX_BUNDLE_BYTES).
    Bundle,
}

impl CappedArtifact {
    /// Both artifacts, so a test can sweep them exhaustively.
    pub const ALL: [Self; 2] = [Self::ManifestEnvelope, Self::Bundle];

    /// The frozen cap — read from the same constant the decode path
    /// compares its *input* against, so the two sides cannot drift.
    #[must_use]
    pub const fn cap(self) -> u64 {
        match self {
            Self::ManifestEnvelope => MAX_MANIFEST_BYTES,
            Self::Bundle => MAX_BUNDLE_BYTES,
        }
    }

    /// The **decode-side** code a verifier would report for an artifact
    /// this size — the code the seal side must therefore refuse with.
    ///
    /// These two strings are not new (D30 §3's append ceremony is not
    /// invoked and the universe stays at 194): they are
    /// [`ManifestError::InputTooLarge`](crate::manifest::ManifestError::InputTooLarge)
    /// and [`BundleError::InputTooLarge`](crate::bundle::BundleError::InputTooLarge),
    /// which `super::caps`' stage-1 ordering table already names in prose.
    /// `the_encode_gate_reports_the_decode_paths_own_codes` in
    /// `bundle::schema` and `manifest::envelope` asserts each against the
    /// owning error's own `code()`, so the copy here cannot drift from the
    /// original — the rule F42 recorded for the frozen registry (*a fact
    /// may be stated twice only if something checks the two copies*).
    #[must_use]
    pub const fn decode_code(self) -> &'static str {
        match self {
            Self::ManifestEnvelope => "manifest-too-large",
            Self::Bundle => "bundle-too-large",
        }
    }

    /// The gate itself: refuse an encoding the decode path would refuse.
    ///
    /// Checked on the finished bytes, which is the only place the quantity
    /// exists. `encoded.len() as u64` widens **up** (lossless on 32- and
    /// 64-bit) and the cap is never narrowed down to `usize`, the D10 §8
    /// rule that keeps one artifact from being valid on one target and
    /// invalid on the other.
    pub(crate) fn gate(self, encoded: &[u8]) -> Result<(), EncodeError> {
        let len = encoded.len() as u64;
        let cap = self.cap();
        if len > cap {
            return Err(EncodeError::TooLarge {
                artifact: self,
                len,
                cap,
            });
        }
        Ok(())
    }
}

impl core::fmt::Display for CappedArtifact {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ManifestEnvelope => "manifest envelope",
            Self::Bundle => "bundle",
        })
    }
}

/// Failure of the canonical encode layer.
///
/// Every variant is a **seal-side** report — encoding consumes only
/// caller-built values, never adversarial input, whose taxonomy lives in
/// [`super::decode::DecodeError`]. Three are caller bugs the layer
/// detects; [`Self::TooLarge`] is the one that reports a real property of
/// a real artifact. Library discipline applies to all four: misuse
/// surfaces as an `Err`, never a panic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// The same map key was supplied twice. Map keys are registry
    /// constants (F4), never secret material, so the key value is safe
    /// to carry.
    #[error("duplicate map key {key}")]
    DuplicateMapKey {
        /// The unsigned-integer key that was supplied more than once.
        key: u64,
    },

    /// A closure scope (top level, array item, or map value) emitted
    /// `count` items where exactly one is required.
    #[error("scope emitted {count} items where exactly one is required")]
    NotExactlyOneItem {
        /// Number of items the scope actually emitted.
        count: u64,
    },

    /// The underlying byte sink rejected a write. Unreachable in
    /// practice: the sink is an in-memory `Vec<u8>`, whose minicbor
    /// `Write` impl is infallible (`Error = Infallible`, verified against
    /// the pinned 2.3.0 source). The variant exists so the impossibility
    /// is an `Err`, not a panic path.
    #[error("the byte sink rejected a write")]
    Sink,

    /// The finished encoding exceeds its D10 aggregate byte cap (F53).
    ///
    /// Unlike its three siblings this is reachable from schema-valid
    /// parts: every *other* D10 cap bounds something a constructor can
    /// see, and F41 made all six constructors enforce those — but a
    /// manifest with a 17 MiB `title`, or a bundle whose individually
    /// legal anchors sum past 256 MiB, is assembled entirely from
    /// in-cap pieces. Without this check the seal side emits an artifact
    /// **no v1 verifier, including antseal's own, will decode**: on a
    /// pay-once network, permanently dead bytes.
    ///
    /// Reported with the decode path's own code (see
    /// [`CappedArtifact::decode_code`]), so a sealer and a verifier name
    /// the same defect the same way.
    #[error("encoded {artifact} of {len} bytes exceeds the {cap}-byte limit")]
    TooLarge {
        /// Which artifact overflowed.
        artifact: CappedArtifact,
        /// The encoded length actually produced.
        len: u64,
        /// The frozen cap.
        cap: u64,
    },
}

impl EncodeError {
    /// The stable error code, for the one variant that has one.
    ///
    /// `None` for the three caller-bug variants **on purpose**: they are
    /// internal invariants, unreachable for every value this crate builds
    /// (constant registry keys, one item per scope, an infallible `Vec`
    /// sink), so no artifact can ever carry them and D30's frozen universe
    /// deliberately does not name them. [`Self::TooLarge`] is the
    /// encode-side half of a *decode-side* rejection and therefore reuses
    /// that rejection's code rather than minting a second name for one
    /// outcome (D30 §1).
    #[must_use]
    pub const fn code(&self) -> Option<&'static str> {
        match self {
            Self::DuplicateMapKey { .. } | Self::NotExactlyOneItem { .. } | Self::Sink => None,
            Self::TooLarge { artifact, .. } => Some(artifact.decode_code()),
        }
    }
}

/// Map a minicbor emit result into this layer's error type.
///
/// The writer is `&mut Vec<u8>` (`Error = Infallible`), so the `Err` arm
/// is unreachable in practice; see [`EncodeError::Sink`].
fn sink<T>(
    r: Result<T, minicbor::encode::Error<core::convert::Infallible>>,
) -> Result<(), EncodeError> {
    match r {
        Ok(_) => Ok(()),
        Err(_) => Err(EncodeError::Sink),
    }
}

/// One encoding scope: a growing byte buffer plus the count of top-level
/// items emitted into it (for the exactly-one-item rule).
///
/// Not directly constructible — scopes are handed to closures by
/// [`encode_item`], [`ArrayEncoder::item`], and [`MapEncoder::entry`].
#[derive(Debug)]
pub struct CanonicalEncoder {
    buf: Vec<u8>,
    items: usize,
}

impl CanonicalEncoder {
    /// Fresh empty scope (crate-internal: scopes only exist inside the
    /// closure-driven builders).
    fn new_scope() -> Self {
        Self {
            buf: Vec::new(),
            items: 0,
        }
    }

    /// Close a scope that must contain exactly one item, yielding its
    /// bytes.
    fn into_single_item(self) -> Result<Vec<u8>, EncodeError> {
        if self.items == 1 {
            Ok(self.buf)
        } else {
            Err(EncodeError::NotExactlyOneItem {
                // usize -> u64 is lossless on all supported targets.
                count: self.items as u64,
            })
        }
    }

    /// Emit an unsigned integer (major type 0), shortest form.
    pub fn u64(&mut self, v: u64) -> Result<(), EncodeError> {
        self.items += 1;
        sink(Encoder::new(&mut self.buf).u64(v))
    }

    /// Emit a signed integer (major type 0 for `v >= 0`, major type 1
    /// otherwise), shortest form.
    pub fn i64(&mut self, v: i64) -> Result<(), EncodeError> {
        self.items += 1;
        sink(Encoder::new(&mut self.buf).i64(v))
    }

    /// Emit a definite-length byte string (major type 2), shortest-form
    /// length head.
    pub fn bytes(&mut self, b: &[u8]) -> Result<(), EncodeError> {
        self.items += 1;
        sink(Encoder::new(&mut self.buf).bytes(b))
    }

    /// Emit a definite-length UTF-8 text string (major type 3),
    /// shortest-form length head. Validity is by construction: the input
    /// is `&str`.
    pub fn str(&mut self, s: &str) -> Result<(), EncodeError> {
        self.items += 1;
        sink(Encoder::new(&mut self.buf).str(s))
    }

    /// Emit a definite-length array (major type 4). The closure adds
    /// elements via [`ArrayEncoder::item`]; the length head is written at
    /// close from the actual element count, so a count mismatch cannot
    /// exist.
    pub fn array<F>(&mut self, f: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut ArrayEncoder) -> Result<(), EncodeError>,
    {
        let mut a = ArrayEncoder {
            buf: Vec::new(),
            len: 0,
        };
        f(&mut a)?;
        self.items += 1;
        sink(Encoder::new(&mut self.buf).array(a.len))?;
        self.buf.extend_from_slice(&a.buf);
        Ok(())
    }

    /// Emit a definite-length map (major type 5) with unsigned-integer
    /// keys. The closure adds entries via [`MapEncoder::entry`] in **any**
    /// order; at close the entries are sorted by key (== bytewise order
    /// of the shortest-form key encodings, the module-level equivalence)
    /// and duplicates are rejected, so no API path can emit an unsorted
    /// or duplicate-keyed map.
    pub fn map<F>(&mut self, f: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut MapEncoder) -> Result<(), EncodeError>,
    {
        let mut m = MapEncoder {
            entries: Vec::new(),
        };
        f(&mut m)?;
        let mut entries = m.entries;
        entries.sort_unstable_by_key(|&(key, _)| key);
        for w in entries.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(EncodeError::DuplicateMapKey { key: w[0].0 });
            }
        }
        self.items += 1;
        // usize -> u64 is lossless on all supported targets.
        sink(Encoder::new(&mut self.buf).map(entries.len() as u64))?;
        for (key, value) in &entries {
            sink(Encoder::new(&mut self.buf).u64(*key))?;
            self.buf.extend_from_slice(value);
        }
        Ok(())
    }
}

/// Builder handed to [`CanonicalEncoder::array`] closures.
#[derive(Debug)]
pub struct ArrayEncoder {
    buf: Vec<u8>,
    len: u64,
}

impl ArrayEncoder {
    /// Append one array element. The closure runs in a fresh scope and
    /// must emit exactly one item.
    pub fn item<F>(&mut self, f: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut CanonicalEncoder) -> Result<(), EncodeError>,
    {
        let mut scope = CanonicalEncoder::new_scope();
        f(&mut scope)?;
        let bytes = scope.into_single_item()?;
        self.buf.extend_from_slice(&bytes);
        self.len += 1;
        Ok(())
    }
}

/// Builder handed to [`CanonicalEncoder::map`] closures.
#[derive(Debug)]
pub struct MapEncoder {
    entries: Vec<(u64, Vec<u8>)>,
}

impl MapEncoder {
    /// Add one `key -> value` entry. The value closure runs in a fresh
    /// scope and must emit exactly one item. Entry order at the call
    /// sites is irrelevant: the wire order is sorted at map close, and a
    /// repeated key errors there.
    pub fn entry<F>(&mut self, key: u64, f: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut CanonicalEncoder) -> Result<(), EncodeError>,
    {
        let mut scope = CanonicalEncoder::new_scope();
        f(&mut scope)?;
        let bytes = scope.into_single_item()?;
        self.entries.push((key, bytes));
        Ok(())
    }
}

/// Encode exactly one canonical CBOR item and return its bytes.
///
/// The single entry point of the encode layer: bytes are returned only
/// after the closure completed and the scope closed with exactly one
/// item, so partially written or non-canonical output can never escape
/// to a caller. Every output of this function decodes cleanly under the
/// strict layer ([`super::decode::check_canonical`]) — the F2/F3
/// self-consistency contract, asserted by the integration tests.
pub fn encode_item<F>(f: F) -> Result<Vec<u8>, EncodeError>
where
    F: FnOnce(&mut CanonicalEncoder) -> Result<(), EncodeError>,
{
    let mut scope = CanonicalEncoder::new_scope();
    f(&mut scope)?;
    scope.into_single_item()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **F53.** The gate's table is the cap table, not a copy of it, and
    /// the two artifacts are told apart by code. The *boundary* (at-cap
    /// admitted, cap+1 refused) is proven end-to-end through the real
    /// encoders in `manifest::envelope` and `bundle::schema`, which is
    /// also where the two codes are bound to the decode-side variants
    /// that own them; asserting it here would cost a 256 MiB slice for
    /// nothing.
    #[test]
    fn the_capped_artifacts_read_their_caps_from_the_frozen_table() {
        assert_eq!(
            CappedArtifact::ManifestEnvelope.cap(),
            super::super::caps::MAX_MANIFEST_BYTES
        );
        assert_eq!(
            CappedArtifact::Bundle.cap(),
            super::super::caps::MAX_BUNDLE_BYTES
        );

        let mut codes = std::collections::BTreeSet::new();
        for artifact in CappedArtifact::ALL {
            assert!(
                codes.insert(artifact.decode_code()),
                "{artifact} shares a code with its sibling"
            );
            // Under the cap the gate is silent; `ALL` is what makes this
            // a sweep rather than two hand-written cases.
            assert_eq!(artifact.gate(b"short"), Ok(()));
        }
        assert_eq!(codes.len(), 2);
    }

    /// The three caller-bug variants are deliberately outside the frozen
    /// code universe (D30) and must stay that way: giving one a code would
    /// promise third-party verifiers a string no artifact can ever produce.
    #[test]
    fn only_the_size_gate_carries_a_code() {
        assert_eq!(EncodeError::DuplicateMapKey { key: 3 }.code(), None);
        assert_eq!(EncodeError::NotExactlyOneItem { count: 0 }.code(), None);
        assert_eq!(EncodeError::Sink.code(), None);
        assert_eq!(
            EncodeError::TooLarge {
                artifact: CappedArtifact::Bundle,
                len: 1,
                cap: 0,
            }
            .code(),
            Some("bundle-too-large")
        );
    }

    /// Encode a lone unsigned integer through the public API.
    fn enc_u64(v: u64) -> Vec<u8> {
        encode_item(|e| e.u64(v)).expect("single u64 encodes")
    }

    /// F2 accept: shortest-form heads at every integer width boundary
    /// (0, 23, 24, 255, 256, 2^16−1, 2^16, 2^32−1, 2^32, u64::MAX),
    /// pinned byte-exact through this layer's own API.
    #[test]
    fn shortest_form_integer_heads_at_boundaries() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (23, &[0x17]),
            (24, &[0x18, 24]),
            (255, &[0x18, 0xff]),
            (256, &[0x19, 0x01, 0x00]),
            (65_535, &[0x19, 0xff, 0xff]),
            (65_536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
            (u64::from(u32::MAX), &[0x1a, 0xff, 0xff, 0xff, 0xff]),
            (u64::from(u32::MAX) + 1, &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
            (
                u64::MAX,
                &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];
        for (v, want) in cases {
            assert_eq!(enc_u64(*v).as_slice(), *want, "shortest form for {v}");
        }
    }

    /// Negative integers (major type 1): shortest-form argument heads at
    /// the same width boundaries, argument = −1−v.
    #[test]
    fn shortest_form_negative_integer_heads_at_boundaries() {
        let cases: &[(i64, &[u8])] = &[
            (-1, &[0x20]),
            (-24, &[0x37]),
            (-25, &[0x38, 24]),
            (-256, &[0x38, 0xff]),
            (-257, &[0x39, 0x01, 0x00]),
            (-65_536, &[0x39, 0xff, 0xff]),
            (-65_537, &[0x3a, 0x00, 0x01, 0x00, 0x00]),
            (
                i64::MIN,
                &[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];
        for (v, want) in cases {
            let got = encode_item(|e| e.i64(*v)).expect("single i64 encodes");
            assert_eq!(got.as_slice(), *want, "shortest form for {v}");
        }
        // Non-negative i64 goes out major-type-0, identical to u64.
        assert_eq!(
            encode_item(|e| e.i64(42)).expect("encodes"),
            enc_u64(42),
            "non-negative i64 == u64 encoding"
        );
    }

    /// F2 accept: shortest-form length heads at the bstr and tstr length
    /// boundaries (0, 23, 24, 255, 256, 2^16−1, 2^16), definite lengths
    /// only (head + payload, nothing else).
    #[test]
    fn shortest_form_string_length_heads_at_boundaries() {
        let cases: &[(usize, &[u8])] = &[
            (0, &[0x40]),
            (23, &[0x57]),
            (24, &[0x58, 24]),
            (255, &[0x58, 0xff]),
            (256, &[0x59, 0x01, 0x00]),
            (65_535, &[0x59, 0xff, 0xff]),
            (65_536, &[0x5a, 0x00, 0x01, 0x00, 0x00]),
        ];
        for (len, want_head) in cases {
            let payload = vec![0x61u8; *len]; // 'a' — valid UTF-8 for tstr reuse
            let got = encode_item(|e| e.bytes(&payload)).expect("bstr encodes");
            assert_eq!(&got[..want_head.len()], *want_head, "bstr head, len {len}");
            assert_eq!(got.len(), want_head.len() + len, "bstr definite, len {len}");

            // Same head machinery for tstr: identical bytes except the
            // major type bits (0x40 -> 0x60).
            let text = String::from_utf8(payload).expect("all-'a' is UTF-8");
            let got = encode_item(|e| e.str(&text)).expect("tstr encodes");
            let mut tstr_head = want_head.to_vec();
            tstr_head[0] += 0x20;
            assert_eq!(&got[..tstr_head.len()], tstr_head, "tstr head, len {len}");
            assert_eq!(got.len(), tstr_head.len() + len, "tstr definite, len {len}");
        }
    }

    /// F2 accept: shortest-form length heads at the array and map length
    /// boundaries (0, 23, 24, 255, 256), definite lengths only.
    #[test]
    fn shortest_form_container_length_heads_at_boundaries() {
        let cases: &[(u64, u8, &[u8])] = &[
            (0, 0x80, &[0x80]),
            (23, 0x80, &[0x97]),
            (24, 0x80, &[0x98, 24]),
            (255, 0x80, &[0x98, 0xff]),
            (256, 0x80, &[0x99, 0x01, 0x00]),
            (0, 0xa0, &[0xa0]),
            (23, 0xa0, &[0xb7]),
            (24, 0xa0, &[0xb8, 24]),
            (255, 0xa0, &[0xb8, 0xff]),
            (256, 0xa0, &[0xb9, 0x01, 0x00]),
        ];
        for (len, major, want_head) in cases {
            let got = if *major == 0x80 {
                encode_item(|e| {
                    e.array(|a| {
                        for _ in 0..*len {
                            a.item(|e| e.u64(0))?;
                        }
                        Ok(())
                    })
                })
                .expect("array encodes")
            } else {
                encode_item(|e| {
                    e.map(|m| {
                        for k in 0..*len {
                            m.entry(k, |e| e.u64(0))?;
                        }
                        Ok(())
                    })
                })
                .expect("map encodes")
            };
            assert_eq!(
                &got[..want_head.len()],
                *want_head,
                "container head, major 0x{major:02x}, len {len}"
            );
        }
    }

    /// F2 accept (sorted-key equivalence): for shortest-form unsigned
    /// integer keys, ascending numeric order equals ascending bytewise
    /// order of the encoded forms — the property that lets [`MapEncoder`]
    /// sort by `u64`. Checked over every pair of a boundary-straddling
    /// key set spanning all five head widths.
    #[test]
    fn sorted_key_equivalence_numeric_ascending_is_bytewise_ascending() {
        let keys: &[u64] = &[
            0,
            1,
            22,
            23,
            24,
            25,
            254,
            255,
            256,
            257,
            65_534,
            65_535,
            65_536,
            65_537,
            u64::from(u32::MAX) - 1,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            u64::MAX - 1,
            u64::MAX,
        ];
        for (i, &a) in keys.iter().enumerate() {
            for &b in &keys[i + 1..] {
                let (ea, eb) = (enc_u64(a), enc_u64(b));
                assert!(a < b, "fixture set must be ascending");
                assert!(
                    ea < eb,
                    "numeric {a} < {b} must imply bytewise {ea:02x?} < {eb:02x?}"
                );
            }
        }
    }

    /// Map entries are emitted key-sorted regardless of the order the
    /// caller supplies them, and the output is byte-identical to the
    /// ascending-order emission (determinism across call orders).
    #[test]
    fn map_entries_sorted_regardless_of_call_order() {
        let shuffled = encode_item(|e| {
            e.map(|m| {
                m.entry(24, |e| e.u64(0))?;
                m.entry(1, |e| e.u64(0))?;
                m.entry(10, |e| e.u64(0))?;
                m.entry(2, |e| e.u64(0))?;
                Ok(())
            })
        })
        .expect("map encodes");
        // Same bytes as the D7 evidence vector for {1:0, 2:0, 10:0, 24:0}.
        assert_eq!(
            shuffled,
            vec![0xa4, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x18, 24, 0x00]
        );

        let ascending = encode_item(|e| {
            e.map(|m| {
                for k in [1u64, 2, 10, 24] {
                    m.entry(k, |e| e.u64(0))?;
                }
                Ok(())
            })
        })
        .expect("map encodes");
        assert_eq!(shuffled, ascending, "call order must not affect bytes");
    }

    /// A repeated map key is an error, never a silent overwrite — and it
    /// is detected regardless of insertion order.
    #[test]
    fn duplicate_map_key_is_an_error() {
        let dup = encode_item(|e| {
            e.map(|m| {
                m.entry(5, |e| e.u64(1))?;
                m.entry(3, |e| e.u64(2))?;
                m.entry(5, |e| e.u64(3))?;
                Ok(())
            })
        });
        assert_eq!(dup, Err(EncodeError::DuplicateMapKey { key: 5 }));
    }

    /// Every closure scope must emit exactly one item: zero and two are
    /// rejected at the top level, in array items, and in map values.
    #[test]
    fn scopes_enforce_exactly_one_item() {
        assert_eq!(
            encode_item(|_| Ok(())),
            Err(EncodeError::NotExactlyOneItem { count: 0 })
        );
        assert_eq!(
            encode_item(|e| {
                e.u64(1)?;
                e.u64(2)
            }),
            Err(EncodeError::NotExactlyOneItem { count: 2 })
        );
        assert_eq!(
            encode_item(|e| e.array(|a| a.item(|_| Ok(())))),
            Err(EncodeError::NotExactlyOneItem { count: 0 })
        );
        assert_eq!(
            encode_item(|e| e.map(|m| m.entry(0, |e| {
                e.u64(1)?;
                e.u64(2)
            }))),
            Err(EncodeError::NotExactlyOneItem { count: 2 })
        );
    }

    /// Repeated encodes of the same logical structure are byte-identical
    /// (determinism; the cross-platform half runs under Q's wasm CI).
    #[test]
    fn encoding_is_deterministic_across_runs() {
        let build = || {
            encode_item(|e| {
                e.map(|m| {
                    m.entry(2, |e| e.bytes(&[0xAB; 40]))?;
                    m.entry(0, |e| e.u64(65_536))?;
                    m.entry(1, |e| {
                        e.array(|a| {
                            a.item(|e| e.str("antseal"))?;
                            a.item(|e| e.i64(-257))
                        })
                    })?;
                    Ok(())
                })
            })
            .expect("fixture encodes")
        };
        assert_eq!(build(), build());
    }
}
