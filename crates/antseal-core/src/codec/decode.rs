//! Strict canonical CBOR decode layer (task F3).
//!
//! A canonicality-enforcing reader that hard-errors on **any** input not
//! in the RFC 8949 §4.2.1 profile of MVP-SPEC.md line 73, with one
//! distinct [`DecodeError`] variant per rejection class so the tamper
//! matrix (spec line 168: every mutation fails with a distinct error)
//! can key on exact variants and stable codes.
//!
//! Two entry surfaces over one strictness core:
//!
//! - [`check_canonical`]: schema-agnostic validation that a byte slice is
//!   exactly one canonically-encoded item with nothing trailing. This is
//!   the layer that runs on outer envelopes (manifest, bundle) and on
//!   inner `body` bstr contents alike — an embedded byte string is
//!   opaque payload to the outer pass, so each layer gets its own pass
//!   (spec lines 73–74).
//! - [`CanonicalDecoder`]: the typed pull reader the schema layers
//!   (F5/F6/F8/F9) build manual decode impls on. Every read enforces the
//!   same per-item strictness; map traversal goes through [`MapReader`],
//!   which enforces strictly-ascending unsigned-integer keys (duplicate
//!   and disorder as two distinct variants).
//!
//! # Error precedence (deterministic, uniform per item)
//!
//! Checks run in a fixed order so a multiply-wrong item yields the same
//! error on every platform and every release:
//!
//! 1. initial byte present ([`DecodeError::Truncated`]);
//! 2. item type admitted by the profile
//!    ([`DecodeError::ForbiddenType`]: floats, simple values, tags) —
//!    decided from the initial byte alone, so e.g. a truncated float
//!    still reports the forbidden type;
//! 3. head well-formed ([`DecodeError::Malformed`]: reserved additional
//!    info, stray break) and definite
//!    ([`DecodeError::IndefiniteLength`]);
//! 4. head argument bytes present ([`DecodeError::Truncated`]);
//! 5. shortest-form head argument ([`DecodeError::NonShortestInt`] /
//!    [`DecodeError::NonShortestLength`]);
//! 6. typed expectation, typed reader only
//!    ([`DecodeError::UnexpectedType`], [`DecodeError::IntOutOfRange`]);
//! 7. payload bounds ([`DecodeError::Truncated`]);
//! 8. payload content ([`DecodeError::InvalidUtf8`]).
//!
//! Map-key ordering ([`DecodeError::DuplicateMapKey`] /
//! [`DecodeError::UnsortedMapKeys`]) is checked as keys are read, on the
//! bytewise order of their encoded forms (§4.2.1); for the registry's
//! shortest-form unsigned-integer keys this equals numeric order (the F2
//! equivalence), which is what [`MapReader`] compares.
//!
//! # Implementation notes (decision D7)
//!
//! Built on the exact-pinned `minicbor = "=2.3.0"`: head bytes are
//! inspected through the crate's raw probe surface
//! (`input()`/`position()`), payloads are consumed through its typed
//! calls (`u64`/`int`/`bytes`/`str`/`array`/`map` — `str()` is the native
//! invalid-UTF-8 rejection), and the strict rejections are wrapper logic
//! over those probes, exactly as D7 records. Claimed payload lengths are
//! bounds-checked against the remaining input *before* consumption so a
//! hostile length can neither allocate (decode is zero-copy borrowing)
//! nor produce different error classes on 32-bit (wasm32) versus 64-bit
//! targets. Errors carry positions (as `u64`, platform-independent) and
//! kind discriminants only — **never input byte content**, because
//! decoded inputs include secret-adjacent material (unit plaintexts,
//! salts in bundles) that must not leak through `Display`/`Debug`
//! (project rule 6).
//!
//! No `unsafe`, no panics, no unwraps on any input: every failure is a
//! typed `Err`. Recursion in the generic walker is bounded by
//! [`MAX_CBOR_DEPTH`](super::caps::MAX_CBOR_DEPTH) so hostile nesting
//! cannot overflow the stack.

use core::fmt;

use minicbor::decode::Decoder;

use super::caps::MAX_CBOR_DEPTH;

/// The six item types the deterministic profile admits.
///
/// Floats, simple values, and tags are not item kinds here — the profile
/// bans them outright ([`DecodeError::ForbiddenType`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    /// Major type 0: unsigned integer.
    Unsigned,
    /// Major type 1: negative integer.
    Negative,
    /// Major type 2: definite-length byte string.
    Bytes,
    /// Major type 3: definite-length UTF-8 text string.
    Text,
    /// Major type 4: definite-length array.
    Array,
    /// Major type 5: definite-length map.
    Map,
}

impl fmt::Display for ItemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsigned => "unsigned integer",
            Self::Negative => "negative integer",
            Self::Bytes => "byte string",
            Self::Text => "text string",
            Self::Array => "array",
            Self::Map => "map",
        })
    }
}

/// What a typed read expected to find (payload of
/// [`DecodeError::UnexpectedType`]).
///
/// Distinct from [`ItemKind`] because [`CanonicalDecoder::i64`] accepts
/// either integer major type ([`Self::Integer`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedKind {
    /// An unsigned integer (major type 0).
    Unsigned,
    /// An integer of either sign (major type 0 or 1).
    Integer,
    /// A byte string.
    Bytes,
    /// A text string.
    Text,
    /// An array.
    Array,
    /// A map.
    Map,
}

impl fmt::Display for ExpectedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsigned => "unsigned integer",
            Self::Integer => "integer",
            Self::Bytes => "byte string",
            Self::Text => "text string",
            Self::Array => "array",
            Self::Map => "map",
        })
    }
}

/// Which profile-banned item type was encountered (payload of
/// [`DecodeError::ForbiddenType`]; one stable code per kind, following
/// the R1 per-discriminant convention).
///
/// Spec line 73 names floats; simple values are out of schema everywhere
/// (the v1 registry, F4, admits none); tags are likewise absent from
/// every v1 schema slot and are rejected here so a tagged re-spelling of
/// a value can never alias an untagged one under a single `work_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForbiddenKind {
    /// Major type 7, additional info 25–27 (f16/f32/f64).
    Float,
    /// Major type 7 simple values: false/true/null/undefined and
    /// numbered simples.
    Simple,
    /// Major type 6: any tag.
    Tag,
}

impl fmt::Display for ForbiddenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Float => "float",
            Self::Simple => "simple value",
            Self::Tag => "tag",
        })
    }
}

/// Typed, position-carrying strict-decode failure — one distinct variant
/// per rejection class of MVP-SPEC.md line 73, plus the totality
/// variants (truncation, malformed head, depth, typed-read mismatches)
/// that make the layer panic-free on arbitrary input.
///
/// `position` is the byte offset **within the input slice given to this
/// decoder** of the offending item's head (for key-order violations: of
/// the offending key). Callers running the layer on embedded bytes (an
/// inner `body`, a bundle-embedded manifest) compose their own outer
/// offsets; the layer never sees them. Positions are `u64` so error
/// values — and therefore tamper-matrix expectations — are identical on
/// 32-bit (wasm32) and 64-bit targets.
///
/// Payloads are positions and kind discriminants only, **never** input
/// byte content (module-level policy; asserted by the secret-fixture
/// test in `tests/codec_strict.rs`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The input ends inside an item (missing head bytes or payload).
    #[error("input truncated inside the item at byte {position}")]
    Truncated {
        /// Offset of the truncated item's head.
        position: u64,
    },

    /// A head byte no canonical item can start with: reserved additional
    /// info 28–30, a stray break (0xff) outside any indefinite context,
    /// or indefinite additional info on an integer major type.
    #[error("malformed CBOR head at byte {position}")]
    Malformed {
        /// Offset of the malformed head byte.
        position: u64,
    },

    /// A profile-banned item type: float, simple value, or tag
    /// (spec line 73 "no floats"; simples/tags are out of schema
    /// everywhere in v1 — see [`ForbiddenKind`]).
    #[error("forbidden item type ({kind}) at byte {position}")]
    ForbiddenType {
        /// Which banned type was found.
        kind: ForbiddenKind,
        /// Offset of the item's head.
        position: u64,
    },

    /// An indefinite-length byte string, text string, array, or map
    /// (spec line 73: definite lengths only).
    #[error("indefinite-length item at byte {position}")]
    IndefiniteLength {
        /// Offset of the indefinite item's head.
        position: u64,
    },

    /// An integer (major type 0/1) whose head argument is not in
    /// shortest form (e.g. `18 05` for 5).
    #[error("non-shortest-form integer encoding at byte {position}")]
    NonShortestInt {
        /// Offset of the wide integer's head.
        position: u64,
    },

    /// A length argument (bstr/tstr/array/map head) not in shortest form
    /// (e.g. `59 00 01` for length 1).
    #[error("non-shortest-form length argument at byte {position}")]
    NonShortestLength {
        /// Offset of the wide-length item's head.
        position: u64,
    },

    /// A map key equal to its predecessor (strict ascent violated by
    /// equality — distinct from disorder, [`Self::UnsortedMapKeys`], per
    /// F3's two-variant requirement).
    #[error("duplicate map key at byte {position}")]
    DuplicateMapKey {
        /// Offset of the second (offending) key's head.
        position: u64,
    },

    /// A map key bytewise-smaller than its predecessor (strict ascent
    /// violated by disorder — distinct from [`Self::DuplicateMapKey`]).
    #[error("map keys not in strictly ascending bytewise order at byte {position}")]
    UnsortedMapKeys {
        /// Offset of the out-of-order key's head.
        position: u64,
    },

    /// A text string whose payload is not valid UTF-8 (rejected natively
    /// by the pinned crate's `str()`; surfaced as this distinct class).
    #[error("invalid UTF-8 in text string at byte {position}")]
    InvalidUtf8 {
        /// Offset of the text string's head.
        position: u64,
    },

    /// Bytes remain after the single top-level item (spec line 73).
    #[error("{trailing} trailing byte(s) after the top-level item at byte {position}")]
    TrailingBytes {
        /// Offset of the first trailing byte.
        position: u64,
        /// How many bytes trail the top-level item.
        trailing: u64,
    },

    /// Container nesting exceeds [`MAX_CBOR_DEPTH`](super::caps::MAX_CBOR_DEPTH)
    /// (the D10-frozen walker guard).
    #[error("container nesting exceeds the supported depth at byte {position}")]
    NestingTooDeep {
        /// Offset of the item that would exceed the depth bound.
        position: u64,
    },

    /// Typed reader only: the item is canonical but not the kind the
    /// schema asked for (e.g. a byte string where an unsigned-integer
    /// map key is required). One stable code for the whole variant — the
    /// expected/found pair is debugging context, not a tamper-row axis.
    #[error("expected {expected}, found {found} at byte {position}")]
    UnexpectedType {
        /// What the typed read required.
        expected: ExpectedKind,
        /// What the input actually holds.
        found: ItemKind,
        /// Offset of the found item's head.
        position: u64,
    },

    /// Typed reader only: a canonical integer that does not fit the
    /// requested Rust type (e.g. `2^64 − 1` read as `i64`).
    #[error("integer out of range for the requested type at byte {position}")]
    IntOutOfRange {
        /// Offset of the integer's head.
        position: u64,
    },
}

impl DecodeError {
    /// Stable machine-readable code, pairwise-distinct across every
    /// (variant, discriminant) pair — the F-side leg of Q7's error-code
    /// stability contract, delegated through
    /// `verify::VerifyError::Codec`. Lowercase kebab-case, `cbor-`
    /// prefixed so the global tamper matrix stays distinct across
    /// domains; never changes once a tamper row binds to it.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Truncated { .. } => "cbor-truncated",
            Self::Malformed { .. } => "cbor-malformed",
            Self::ForbiddenType { kind, .. } => match kind {
                ForbiddenKind::Float => "cbor-float",
                ForbiddenKind::Simple => "cbor-simple-value",
                ForbiddenKind::Tag => "cbor-tag",
            },
            Self::IndefiniteLength { .. } => "cbor-indefinite-length",
            Self::NonShortestInt { .. } => "cbor-non-shortest-int",
            Self::NonShortestLength { .. } => "cbor-non-shortest-length",
            Self::DuplicateMapKey { .. } => "cbor-duplicate-map-key",
            Self::UnsortedMapKeys { .. } => "cbor-unsorted-map-keys",
            Self::InvalidUtf8 { .. } => "cbor-invalid-utf8",
            Self::TrailingBytes { .. } => "cbor-trailing-bytes",
            Self::NestingTooDeep { .. } => "cbor-nesting-too-deep",
            Self::UnexpectedType { .. } => "cbor-unexpected-type",
            Self::IntOutOfRange { .. } => "cbor-int-out-of-range",
        }
    }
}

/// A fully validated item head: kind, argument (value for integers,
/// length/count otherwise), and encoded head length. Producing a `Head`
/// *is* the canonicality check for the head (precedence steps 1–4).
struct Head {
    kind: ItemKind,
    arg: u64,
    head_len: usize,
    position: usize,
}

/// Smallest argument value for which each multi-byte additional-info
/// width is the shortest form (RFC 8949 §4.2.1 "as short as possible").
const fn shortest_form_minimum(ai: u8) -> u64 {
    match ai {
        24 => 24,
        25 => 0x100,
        26 => 0x1_0000,
        27 => 0x1_0000_0000,
        // Immediate arguments (0..=23) are always shortest-form.
        _ => 0,
    }
}

/// Strict canonical pull reader over one input slice.
///
/// Wraps the pinned minicbor decoder; see the module docs for the
/// strictness architecture and error precedence. Reads are zero-copy:
/// [`Self::bytes`]/[`Self::str`] borrow from the input slice, which is
/// what lets F6 hand `body` bytes onward without re-encoding.
#[derive(Debug)]
pub struct CanonicalDecoder<'b> {
    d: Decoder<'b>,
}

impl<'b> CanonicalDecoder<'b> {
    /// Reader over `input`. Nothing is validated until something is
    /// read; use [`check_canonical`] for whole-slice validation.
    #[must_use]
    pub fn new(input: &'b [u8]) -> Self {
        Self {
            d: Decoder::new(input),
        }
    }

    /// Current byte offset within the input slice.
    #[must_use]
    pub fn position(&self) -> usize {
        self.d.position()
    }

    /// Bytes remaining after the cursor.
    ///
    /// `u64`, never `usize`, so the F11 clamp
    /// ([`caps::clamped_capacity`](super::caps::clamped_capacity)) behaves
    /// identically on wasm32 and native. Every element of a definite-length
    /// array costs at least one wire byte, so this is an upper bound on how
    /// many elements the rest of the input can still hold — which is what
    /// makes it a legitimate allocation clamp.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        let input = self.d.input();
        input.len().saturating_sub(self.d.position()) as u64
    }

    /// Defensive error for states the head validation has already made
    /// unreachable (the pinned crate disagreeing with the probe layer
    /// would be a codec bug, surfaced as an error — never a panic).
    fn defensive(position: usize) -> DecodeError {
        DecodeError::Malformed {
            position: position as u64,
        }
    }

    /// Validate the head of the next item without consuming anything
    /// (precedence steps 1–4). Every read goes through this.
    fn peek_head(&self) -> Result<Head, DecodeError> {
        let input = self.d.input();
        let position = self.d.position();
        let Some(&initial) = input.get(position) else {
            return Err(DecodeError::Truncated {
                position: position as u64,
            });
        };
        let major = initial >> 5;
        let ai = initial & 0x1f;

        // Step 2: profile-banned types before anything else.
        let kind = match major {
            0 => ItemKind::Unsigned,
            1 => ItemKind::Negative,
            2 => ItemKind::Bytes,
            3 => ItemKind::Text,
            4 => ItemKind::Array,
            5 => ItemKind::Map,
            6 => {
                return Err(DecodeError::ForbiddenType {
                    kind: ForbiddenKind::Tag,
                    position: position as u64,
                });
            }
            _ => {
                // Major type 7: floats, simples, break, reserved.
                return Err(match ai {
                    25..=27 => DecodeError::ForbiddenType {
                        kind: ForbiddenKind::Float,
                        position: position as u64,
                    },
                    // 28–30 reserved; 31 is a break, which never starts
                    // an item.
                    28..=31 => DecodeError::Malformed {
                        position: position as u64,
                    },
                    // 0..=24: false/true/null/undefined and numbered
                    // simple values.
                    _ => DecodeError::ForbiddenType {
                        kind: ForbiddenKind::Simple,
                        position: position as u64,
                    },
                });
            }
        };

        // Steps 1 & 3: reserved / indefinite additional info.
        let arg_width: usize = match ai {
            0..=23 => 0,
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            28..=30 => {
                return Err(DecodeError::Malformed {
                    position: position as u64,
                });
            }
            _ => {
                // ai == 31: indefinite length. Valid heads exist only
                // for strings/containers; on integers it is malformed.
                return Err(match kind {
                    ItemKind::Bytes | ItemKind::Text | ItemKind::Array | ItemKind::Map => {
                        DecodeError::IndefiniteLength {
                            position: position as u64,
                        }
                    }
                    ItemKind::Unsigned | ItemKind::Negative => DecodeError::Malformed {
                        position: position as u64,
                    },
                });
            }
        };

        // Step 1 (argument bytes present) + argument extraction (big
        // endian). `checked_add` keeps the arithmetic total even at the
        // theoretical end of the address space.
        let arg = if arg_width == 0 {
            u64::from(ai)
        } else {
            let start = position
                .checked_add(1)
                .ok_or_else(|| Self::defensive(position))?;
            let end = start
                .checked_add(arg_width)
                .ok_or_else(|| Self::defensive(position))?;
            let Some(arg_bytes) = input.get(start..end) else {
                return Err(DecodeError::Truncated {
                    position: position as u64,
                });
            };
            let mut v: u64 = 0;
            for &b in arg_bytes {
                v = (v << 8) | u64::from(b);
            }
            v
        };

        // Step 4: shortest-form argument.
        if ai >= 24 && arg < shortest_form_minimum(ai) {
            return Err(match kind {
                ItemKind::Unsigned | ItemKind::Negative => DecodeError::NonShortestInt {
                    position: position as u64,
                },
                _ => DecodeError::NonShortestLength {
                    position: position as u64,
                },
            });
        }

        Ok(Head {
            kind,
            arg,
            head_len: 1 + arg_width,
            position,
        })
    }

    /// Classify the next item without consuming it.
    ///
    /// Strict like every read: a head that is truncated, malformed,
    /// forbidden, indefinite, or non-shortest errors here already, so
    /// schema dispatch code never branches on a non-canonical item.
    pub fn peek_kind(&self) -> Result<ItemKind, DecodeError> {
        self.peek_head().map(|h| h.kind)
    }

    /// Typed-expectation check (precedence step 5).
    fn expect(h: &Head, expected: ExpectedKind) -> Result<(), DecodeError> {
        let ok = match expected {
            ExpectedKind::Unsigned => h.kind == ItemKind::Unsigned,
            ExpectedKind::Integer => matches!(h.kind, ItemKind::Unsigned | ItemKind::Negative),
            ExpectedKind::Bytes => h.kind == ItemKind::Bytes,
            ExpectedKind::Text => h.kind == ItemKind::Text,
            ExpectedKind::Array => h.kind == ItemKind::Array,
            ExpectedKind::Map => h.kind == ItemKind::Map,
        };
        if ok {
            Ok(())
        } else {
            Err(DecodeError::UnexpectedType {
                expected,
                found: h.kind,
                position: h.position as u64,
            })
        }
    }

    /// Payload bounds check (precedence step 6): the claimed string
    /// length must fit the remaining input. Checked in `u64` before any
    /// `usize` conversion, so hostile lengths behave identically on
    /// 32-bit (wasm32) and 64-bit targets and can never drive an
    /// allocation (reads are borrowing anyway).
    fn check_payload_bounds(&self, h: &Head) -> Result<(), DecodeError> {
        let input = self.d.input();
        let payload_start = h
            .position
            .checked_add(h.head_len)
            .ok_or_else(|| Self::defensive(h.position))?;
        // `peek_head` consumed exactly the head bytes, so
        // `payload_start <= input.len()` holds here.
        let available = input.len().saturating_sub(payload_start);
        if h.arg > available as u64 {
            return Err(DecodeError::Truncated {
                position: h.position as u64,
            });
        }
        Ok(())
    }

    /// Read an unsigned integer (major type 0), enforcing shortest form.
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let h = self.peek_head()?;
        Self::expect(&h, ExpectedKind::Unsigned)?;
        self.d.u64().map_err(|_| Self::defensive(h.position))
    }

    /// Read an integer of either sign into `i64`, enforcing shortest
    /// form. A canonical integer outside `i64`'s range yields
    /// [`DecodeError::IntOutOfRange`].
    pub fn i64(&mut self) -> Result<i64, DecodeError> {
        let h = self.peek_head()?;
        Self::expect(&h, ExpectedKind::Integer)?;
        // Post-peek the head is complete, so the only residual failure
        // is minicbor's range error (`u64 -> i64` / nint magnitude).
        self.d.i64().map_err(|_| DecodeError::IntOutOfRange {
            position: h.position as u64,
        })
    }

    /// Consume a negative integer of any magnitude (walker use: the
    /// full nint range exceeds `i64`). The value is not needed —
    /// canonicality was established by the head check.
    fn consume_negative(&mut self, h: &Head) -> Result<(), DecodeError> {
        self.d
            .int()
            .map(|_| ())
            .map_err(|_| Self::defensive(h.position))
    }

    /// Read a definite-length byte string, enforcing a shortest-form
    /// length head. Zero-copy: borrows from the input slice.
    pub fn bytes(&mut self) -> Result<&'b [u8], DecodeError> {
        let h = self.peek_head()?;
        Self::expect(&h, ExpectedKind::Bytes)?;
        self.check_payload_bounds(&h)?;
        self.d.bytes().map_err(|_| Self::defensive(h.position))
    }

    /// Read a definite-length text string, enforcing a shortest-form
    /// length head and valid UTF-8 (precedence step 7; UTF-8 validation
    /// is the pinned crate's native `str()` rejection).
    pub fn str(&mut self) -> Result<&'b str, DecodeError> {
        let h = self.peek_head()?;
        Self::expect(&h, ExpectedKind::Text)?;
        self.check_payload_bounds(&h)?;
        self.d.str().map_err(|e| {
            if e.is_end_of_input() {
                // Unreachable after the bounds check; defensive.
                Self::defensive(h.position)
            } else {
                DecodeError::InvalidUtf8 {
                    position: h.position as u64,
                }
            }
        })
    }

    /// Read a definite-length array head, returning the element count.
    /// The caller reads exactly that many items next.
    pub fn array(&mut self) -> Result<u64, DecodeError> {
        let h = self.peek_head()?;
        Self::expect(&h, ExpectedKind::Array)?;
        match self.d.array() {
            Ok(Some(n)) => Ok(n),
            // Indefinite (None) was already rejected by the head check.
            _ => Err(Self::defensive(h.position)),
        }
    }

    /// Read a definite-length map head, returning a [`MapReader`] that
    /// enforces strictly-ascending unsigned-integer keys.
    pub fn map(&mut self) -> Result<MapReader, DecodeError> {
        let h = self.peek_head()?;
        Self::expect(&h, ExpectedKind::Map)?;
        match self.d.map() {
            Ok(Some(n)) => Ok(MapReader {
                remaining: n,
                prev_key: None,
            }),
            _ => Err(Self::defensive(h.position)),
        }
    }

    /// Assert the input is fully consumed (spec line 73: no trailing
    /// bytes after the top-level item).
    pub fn finish(&self) -> Result<(), DecodeError> {
        let position = self.d.position();
        let len = self.d.input().len();
        if position < len {
            return Err(DecodeError::TrailingBytes {
                position: position as u64,
                trailing: (len - position) as u64,
            });
        }
        Ok(())
    }

    /// Generic canonicality walk of one item (any schema), recursing into
    /// containers with the [`MAX_CBOR_DEPTH`] guard. `depth` is the number
    /// of enclosing containers, so an item with exactly `MAX_CBOR_DEPTH`
    /// enclosing containers is accepted and one more is rejected (D10 §2).
    ///
    /// Map keys of *any* item type are compared in bytewise order of
    /// their (already canonically validated) encoded forms — the general
    /// §4.2.1 rule; schema layers additionally restrict keys to unsigned
    /// integers via [`MapReader`].
    fn walk_item(&mut self, depth: u16) -> Result<(), DecodeError> {
        if depth > MAX_CBOR_DEPTH {
            return Err(DecodeError::NestingTooDeep {
                position: self.d.position() as u64,
            });
        }
        let h = self.peek_head()?;
        match h.kind {
            ItemKind::Unsigned => {
                self.d.u64().map_err(|_| Self::defensive(h.position))?;
            }
            ItemKind::Negative => {
                self.consume_negative(&h)?;
            }
            ItemKind::Bytes => {
                self.check_payload_bounds(&h)?;
                self.d.bytes().map_err(|_| Self::defensive(h.position))?;
            }
            ItemKind::Text => {
                self.check_payload_bounds(&h)?;
                self.d.str().map_err(|e| {
                    if e.is_end_of_input() {
                        Self::defensive(h.position)
                    } else {
                        DecodeError::InvalidUtf8 {
                            position: h.position as u64,
                        }
                    }
                })?;
            }
            ItemKind::Array => {
                match self.d.array() {
                    Ok(Some(_)) => {}
                    _ => return Err(Self::defensive(h.position)),
                }
                // Iteration is bounded by input consumption: every
                // element consumes at least one byte or errors, so a
                // hostile huge count fails at its first missing item.
                for _ in 0..h.arg {
                    self.walk_item(depth + 1)?;
                }
            }
            ItemKind::Map => {
                match self.d.map() {
                    Ok(Some(_)) => {}
                    _ => return Err(Self::defensive(h.position)),
                }
                let mut prev_key: Option<(usize, usize)> = None;
                for _ in 0..h.arg {
                    let key_start = self.d.position();
                    self.walk_item(depth + 1)?;
                    let key_end = self.d.position();
                    if let Some((prev_start, prev_end)) = prev_key {
                        let input = self.d.input();
                        let prev_bytes = input
                            .get(prev_start..prev_end)
                            .ok_or_else(|| Self::defensive(key_start))?;
                        let key_bytes = input
                            .get(key_start..key_end)
                            .ok_or_else(|| Self::defensive(key_start))?;
                        match prev_bytes.cmp(key_bytes) {
                            core::cmp::Ordering::Less => {}
                            core::cmp::Ordering::Equal => {
                                return Err(DecodeError::DuplicateMapKey {
                                    position: key_start as u64,
                                });
                            }
                            core::cmp::Ordering::Greater => {
                                return Err(DecodeError::UnsortedMapKeys {
                                    position: key_start as u64,
                                });
                            }
                        }
                    }
                    prev_key = Some((key_start, key_end));
                    self.walk_item(depth + 1)?;
                }
            }
        }
        Ok(())
    }
}

/// Cursor over a map's entries, enforcing the strictly-ascending
/// unsigned-integer key discipline of the v1 wire registry (F4).
///
/// Drive it to completion: call [`Self::next_key`] until it returns
/// `Ok(None)`, reading each entry's value from the decoder in between.
/// Duplicate keys and disorder are two distinct errors (F3); a non-uint
/// key surfaces as [`DecodeError::UnexpectedType`].
#[derive(Debug)]
pub struct MapReader {
    remaining: u64,
    prev_key: Option<u64>,
}

impl MapReader {
    /// Entries not yet read.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Read the next key, or `Ok(None)` when the map is exhausted.
    /// Numeric ascent is enforced — equal to bytewise encoded-form
    /// ascent for shortest-form unsigned keys (the F2 equivalence).
    pub fn next_key(&mut self, d: &mut CanonicalDecoder<'_>) -> Result<Option<u64>, DecodeError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let position = d.position() as u64;
        let key = d.u64()?;
        if let Some(prev) = self.prev_key {
            if key == prev {
                return Err(DecodeError::DuplicateMapKey { position });
            }
            if key < prev {
                return Err(DecodeError::UnsortedMapKeys { position });
            }
        }
        self.prev_key = Some(key);
        self.remaining -= 1;
        Ok(Some(key))
    }
}

/// Validate that `input` is exactly one canonically-encoded item with no
/// trailing bytes — the schema-agnostic strict pass of spec line 73.
///
/// Invoke it on outer envelopes and on embedded byte-string contents
/// alike (outer bundle, outer manifest, inner `body`, bundle-embedded
/// manifest bytes): an embedded bstr is opaque payload to its outer
/// pass, so canonicality of the inner layer is only established by
/// running this on the inner bytes themselves.
pub fn check_canonical(input: &[u8]) -> Result<(), DecodeError> {
    let mut d = CanonicalDecoder::new(input);
    d.walk_item(0)?;
    d.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Per-class minimal probes: exact variant and exact position ──

    #[test]
    fn truncated_inputs_error_with_position() {
        let cases: &[(&[u8], u64)] = &[
            (&[], 0),                                                     // empty input: no head at all
            (&[0x18], 0),          // u8 argument byte missing
            (&[0x19, 0x01], 0),    // u16 argument incomplete
            (&[0x1b, 0, 0, 0], 0), // u64 argument incomplete
            (&[0x42, 0xAA], 0),    // bstr payload short (1 of 2)
            (&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0), // hostile huge claim
            (&[0xa1, 0x01], 2),    // map value missing
        ];
        for (bytes, at) in cases {
            assert_eq!(
                check_canonical(bytes),
                Err(DecodeError::Truncated { position: *at }),
                "input {bytes:02x?}"
            );
        }
    }

    #[test]
    fn malformed_heads_are_rejected() {
        // Reserved additional info 28–30; stray break; indefinite ai on
        // integer major types.
        for bytes in [
            &[0x1c][..],
            &[0x1d],
            &[0x1e],
            &[0x3c],
            &[0xff],
            &[0x1f],
            &[0x3f],
            &[0xfc],
        ] {
            assert_eq!(
                check_canonical(bytes),
                Err(DecodeError::Malformed { position: 0 }),
                "input {bytes:02x?}"
            );
        }
    }

    #[test]
    fn floats_simples_and_tags_are_forbidden_with_distinct_kinds() {
        let float_cases: &[&[u8]] = &[
            &[0xf9, 0x3c, 0x00],
            &[0xfa, 0, 0, 0, 0],
            &[0xfb, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        for bytes in float_cases {
            assert_eq!(
                check_canonical(bytes),
                Err(DecodeError::ForbiddenType {
                    kind: ForbiddenKind::Float,
                    position: 0
                }),
                "input {bytes:02x?}"
            );
        }
        let simple_cases: &[&[u8]] = &[&[0xf4], &[0xf5], &[0xf6], &[0xf7], &[0xf8, 0x20]];
        for bytes in simple_cases {
            assert_eq!(
                check_canonical(bytes),
                Err(DecodeError::ForbiddenType {
                    kind: ForbiddenKind::Simple,
                    position: 0
                }),
                "input {bytes:02x?}"
            );
        }
        // Tag 2 (positive bignum) wrapping a bstr — rejected at the tag.
        assert_eq!(
            check_canonical(&[0xc2, 0x41, 0x01]),
            Err(DecodeError::ForbiddenType {
                kind: ForbiddenKind::Tag,
                position: 0
            })
        );
    }

    #[test]
    fn indefinite_length_items_are_rejected_for_all_four_types() {
        let cases: &[&[u8]] = &[
            &[0x5f, 0x41, 0xAA, 0xff], // bytes
            &[0x7f, 0x61, 0x61, 0xff], // text
            &[0x9f, 0x01, 0xff],       // array
            &[0xbf, 0x01, 0x02, 0xff], // map
        ];
        for bytes in cases {
            assert_eq!(
                check_canonical(bytes),
                Err(DecodeError::IndefiniteLength { position: 0 }),
                "input {bytes:02x?}"
            );
        }
    }

    #[test]
    fn non_shortest_int_encodings_are_rejected() {
        let cases: &[&[u8]] = &[
            &[0x18, 0x05],                               // 5 as u8 arg
            &[0x18, 0x17],                               // 23 as u8 arg
            &[0x19, 0x00, 0x05],                         // 5 as u16 arg
            &[0x19, 0x00, 0xff],                         // 255 as u16 arg
            &[0x1a, 0x00, 0x00, 0xff, 0xff],             // 65535 as u32
            &[0x1b, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x00], // 65536 as u64
            &[0x38, 0x05],                               // -6, wide nint arg
        ];
        for bytes in cases {
            assert_eq!(
                check_canonical(bytes),
                Err(DecodeError::NonShortestInt { position: 0 }),
                "input {bytes:02x?}"
            );
        }
    }

    #[test]
    fn non_shortest_length_heads_are_rejected_for_all_four_types() {
        let cases: &[&[u8]] = &[
            &[0x58, 0x01, 0xAA],       // bstr len 1 as u8 arg
            &[0x59, 0x00, 0x01, 0xAA], // bstr len 1 as u16 arg
            &[0x78, 0x01, 0x61],       // tstr len 1 as u8 arg
            &[0x98, 0x01, 0x00],       // array len 1 as u8 arg
            &[0xb8, 0x01, 0x00, 0x00], // map len 1 as u8 arg
        ];
        for bytes in cases {
            assert_eq!(
                check_canonical(bytes),
                Err(DecodeError::NonShortestLength { position: 0 }),
                "input {bytes:02x?}"
            );
        }
    }

    #[test]
    fn duplicate_and_disorder_are_two_distinct_variants() {
        // {1: 0, 1: 0} — second key at offset 3.
        assert_eq!(
            check_canonical(&[0xa2, 0x01, 0x00, 0x01, 0x00]),
            Err(DecodeError::DuplicateMapKey { position: 3 })
        );
        // {2: 0, 1: 0} — out-of-order key at offset 3.
        assert_eq!(
            check_canonical(&[0xa2, 0x02, 0x00, 0x01, 0x00]),
            Err(DecodeError::UnsortedMapKeys { position: 3 })
        );
    }

    #[test]
    fn walker_orders_non_uint_keys_bytewise_on_encoded_form() {
        // {"a": 0, "b": 0} ascending bytewise — canonical (key *types*
        // are the schema layer's business, not the walker's).
        assert_eq!(
            check_canonical(&[0xa2, 0x61, 0x61, 0x00, 0x61, 0x62, 0x00]),
            Ok(())
        );
        // {"b": 0, "a": 0} — disorder on encoded form.
        assert_eq!(
            check_canonical(&[0xa2, 0x61, 0x62, 0x00, 0x61, 0x61, 0x00]),
            Err(DecodeError::UnsortedMapKeys { position: 4 })
        );
        // {"a": 0, "a": 1} — duplicate on encoded form.
        assert_eq!(
            check_canonical(&[0xa2, 0x61, 0x61, 0x00, 0x61, 0x61, 0x01]),
            Err(DecodeError::DuplicateMapKey { position: 4 })
        );
        // Mixed key types in RFC 8949 bytewise order: 10 (0x0a) < "a"
        // (0x61 0x61) because 0x0a < 0x61 on the first byte.
        assert_eq!(
            check_canonical(&[0xa2, 0x0a, 0x00, 0x61, 0x61, 0x00]),
            Ok(())
        );
    }

    #[test]
    fn invalid_utf8_in_tstr_is_its_own_class() {
        assert_eq!(
            check_canonical(&[0x61, 0xff]),
            Err(DecodeError::InvalidUtf8 { position: 0 })
        );
        // Truncated multi-byte sequence at the end of the payload.
        assert_eq!(
            check_canonical(&[0x62, 0x61, 0xc3]),
            Err(DecodeError::InvalidUtf8 { position: 0 })
        );
    }

    #[test]
    fn trailing_bytes_after_top_level_item_are_rejected() {
        assert_eq!(
            check_canonical(&[0x01, 0x02]),
            Err(DecodeError::TrailingBytes {
                position: 1,
                trailing: 1
            })
        );
        assert_eq!(
            check_canonical(&[0xa1, 0x01, 0x02, 0x00, 0x00]),
            Err(DecodeError::TrailingBytes {
                position: 3,
                trailing: 2
            })
        );
    }

    /// Build `n` nested arrays: `n − 1` heads of `array(1)` around one
    /// empty array. The innermost item has `n − 1` enclosing containers.
    fn nested_arrays(n: usize) -> Vec<u8> {
        let mut v = vec![0x81u8; n - 1];
        v.push(0x80);
        v
    }

    #[test]
    fn nesting_depth_guard_accepts_limit_rejects_beyond() {
        let max = usize::from(MAX_CBOR_DEPTH);
        // Innermost item enclosed by exactly MAX_CBOR_DEPTH containers.
        assert_eq!(check_canonical(&nested_arrays(max + 1)), Ok(()));
        // One level deeper: rejected, never a stack overflow.
        assert_eq!(
            check_canonical(&nested_arrays(max + 2)),
            Err(DecodeError::NestingTooDeep {
                position: (max + 1) as u64
            })
        );
    }

    /// The v1 registry's deepest legal chain is 6 containers (§7.6.3), so a
    /// 6-deep item must always pass. This is the guard against ever lowering
    /// [`MAX_CBOR_DEPTH`] below the schema by accident — a cap under the
    /// schema maximum would reject honest manifests.
    #[test]
    fn depth_guard_admits_the_deepest_v1_schema_chain() {
        const V1_DEEPEST_CHAIN: usize = 6;
        assert!(usize::from(MAX_CBOR_DEPTH) >= V1_DEEPEST_CHAIN);
        assert_eq!(
            check_canonical(&nested_arrays(V1_DEEPEST_CHAIN + 1)),
            Ok(())
        );
    }

    /// `remaining()` is the clamp's right-hand operand (F11/D10 §4): it must
    /// shrink exactly as the cursor advances and never underflow.
    #[test]
    fn remaining_tracks_the_cursor_in_u64() {
        // [1, 2]: head 0x82, then two one-byte uints.
        let input = [0x82u8, 0x01, 0x02];
        let mut d = CanonicalDecoder::new(&input);
        assert_eq!(d.remaining(), 3);
        assert_eq!(d.array(), Ok(2));
        assert_eq!(d.remaining(), 2);
        assert_eq!(d.u64(), Ok(1));
        assert_eq!(d.remaining(), 1);
        assert_eq!(d.u64(), Ok(2));
        assert_eq!(d.remaining(), 0);
    }

    // ── Typed reader ──

    #[test]
    fn typed_reads_report_unexpected_type_with_expected_and_found() {
        let mut d = CanonicalDecoder::new(&[0x41, 0xAA]);
        assert_eq!(
            d.u64(),
            Err(DecodeError::UnexpectedType {
                expected: ExpectedKind::Unsigned,
                found: ItemKind::Bytes,
                position: 0
            })
        );
        // u64 on a negative integer is a type error (distinct from the
        // range error below).
        let mut d = CanonicalDecoder::new(&[0x20]);
        assert_eq!(
            d.u64(),
            Err(DecodeError::UnexpectedType {
                expected: ExpectedKind::Unsigned,
                found: ItemKind::Negative,
                position: 0
            })
        );
        // i64 accepts both integer majors.
        let mut d = CanonicalDecoder::new(&[0x20]);
        assert_eq!(d.i64(), Ok(-1));
        let mut d = CanonicalDecoder::new(&[0x17]);
        assert_eq!(d.i64(), Ok(23));
    }

    #[test]
    fn canonical_integers_outside_i64_are_range_errors() {
        // u64::MAX as i64.
        let mut d = CanonicalDecoder::new(&[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(d.i64(), Err(DecodeError::IntOutOfRange { position: 0 }));
        // −2^64 (nint argument u64::MAX) as i64.
        let mut d = CanonicalDecoder::new(&[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(d.i64(), Err(DecodeError::IntOutOfRange { position: 0 }));
        // i64::MIN itself still fits.
        let mut d = CanonicalDecoder::new(&[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(d.i64(), Ok(i64::MIN));
    }

    #[test]
    fn map_reader_enforces_strict_uint_key_ascent() {
        // {1: 10, 2: 20} in order.
        let bytes = [0xa2, 0x01, 0x0a, 0x02, 0x14];
        let mut d = CanonicalDecoder::new(&bytes);
        let mut m = d.map().expect("map head");
        assert_eq!(m.remaining(), 2);
        assert_eq!(m.next_key(&mut d), Ok(Some(1)));
        assert_eq!(d.u64(), Ok(10));
        assert_eq!(m.next_key(&mut d), Ok(Some(2)));
        assert_eq!(d.u64(), Ok(20));
        assert_eq!(m.next_key(&mut d), Ok(None));
        assert_eq!(d.finish(), Ok(()));

        // Duplicate uint key through the typed path.
        let bytes = [0xa2, 0x01, 0x00, 0x01, 0x00];
        let mut d = CanonicalDecoder::new(&bytes);
        let mut m = d.map().expect("map head");
        assert_eq!(m.next_key(&mut d), Ok(Some(1)));
        d.u64().expect("value");
        assert_eq!(
            m.next_key(&mut d),
            Err(DecodeError::DuplicateMapKey { position: 3 })
        );

        // Disorder through the typed path.
        let bytes = [0xa2, 0x02, 0x00, 0x01, 0x00];
        let mut d = CanonicalDecoder::new(&bytes);
        let mut m = d.map().expect("map head");
        assert_eq!(m.next_key(&mut d), Ok(Some(2)));
        d.u64().expect("value");
        assert_eq!(
            m.next_key(&mut d),
            Err(DecodeError::UnsortedMapKeys { position: 3 })
        );

        // Non-uint key against the uint-only registry discipline.
        let bytes = [0xa1, 0x61, 0x61, 0x00];
        let mut d = CanonicalDecoder::new(&bytes);
        let mut m = d.map().expect("map head");
        assert_eq!(
            m.next_key(&mut d),
            Err(DecodeError::UnexpectedType {
                expected: ExpectedKind::Unsigned,
                found: ItemKind::Text,
                position: 1
            })
        );
    }

    #[test]
    fn peek_kind_classifies_all_six_kinds_and_rejects_the_rest() {
        let kinds: &[(&[u8], ItemKind)] = &[
            (&[0x00], ItemKind::Unsigned),
            (&[0x20], ItemKind::Negative),
            (&[0x40], ItemKind::Bytes),
            (&[0x60], ItemKind::Text),
            (&[0x80], ItemKind::Array),
            (&[0xa0], ItemKind::Map),
        ];
        for (bytes, kind) in kinds {
            assert_eq!(CanonicalDecoder::new(bytes).peek_kind(), Ok(*kind));
        }
        assert_eq!(
            CanonicalDecoder::new(&[0xf6]).peek_kind(),
            Err(DecodeError::ForbiddenType {
                kind: ForbiddenKind::Simple,
                position: 0
            })
        );
        // Peek is already strict: a non-shortest head never classifies.
        assert_eq!(
            CanonicalDecoder::new(&[0x18, 0x05]).peek_kind(),
            Err(DecodeError::NonShortestInt { position: 0 })
        );
    }

    // ── Canonical accepts ──

    #[test]
    fn canonical_items_are_accepted() {
        let cases: &[&[u8]] = &[
            &[0x00],                                                 // 0
            &[0x17],                                                 // 23
            &[0x18, 0x18],                                           // 24
            &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // u64::MAX
            &[0x20],                                                 // -1
            &[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // -2^64
            &[0x40],                                                 // h''
            &[0x41, 0x00],                                           // h'00'
            &[0x60],                                                 // ""
            &[0x63, 0xe2, 0x82, 0xac],                               // "€"
            &[0x80],                                                 // []
            &[0xa0],                                                 // {}
            &[0x82, 0x01, 0x82, 0x02, 0x03],                         // [1, [2, 3]]
            &[0xa2, 0x01, 0x41, 0xAA, 0x02, 0x19, 0x01, 0x00],       // {1: h'AA', 2: 256}
        ];
        for bytes in cases {
            assert_eq!(check_canonical(bytes), Ok(()), "input {bytes:02x?}");
        }
    }

    /// Stable codes: pairwise distinct, kebab-case, `cbor-` prefixed.
    #[test]
    fn codes_are_pairwise_distinct_kebab_case() {
        let exemplars = [
            DecodeError::Truncated { position: 0 },
            DecodeError::Malformed { position: 0 },
            DecodeError::ForbiddenType {
                kind: ForbiddenKind::Float,
                position: 0,
            },
            DecodeError::ForbiddenType {
                kind: ForbiddenKind::Simple,
                position: 0,
            },
            DecodeError::ForbiddenType {
                kind: ForbiddenKind::Tag,
                position: 0,
            },
            DecodeError::IndefiniteLength { position: 0 },
            DecodeError::NonShortestInt { position: 0 },
            DecodeError::NonShortestLength { position: 0 },
            DecodeError::DuplicateMapKey { position: 0 },
            DecodeError::UnsortedMapKeys { position: 0 },
            DecodeError::InvalidUtf8 { position: 0 },
            DecodeError::TrailingBytes {
                position: 0,
                trailing: 1,
            },
            DecodeError::NestingTooDeep { position: 0 },
            DecodeError::UnexpectedType {
                expected: ExpectedKind::Unsigned,
                found: ItemKind::Bytes,
                position: 0,
            },
            DecodeError::IntOutOfRange { position: 0 },
        ];
        let codes: std::collections::BTreeSet<&'static str> =
            exemplars.iter().map(DecodeError::code).collect();
        assert_eq!(codes.len(), exemplars.len(), "codes must be distinct");
        for code in codes {
            assert!(
                code.starts_with("cbor-")
                    && code
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "code {code:?} is not cbor-prefixed kebab-case"
            );
        }
    }
}
