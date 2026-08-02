//! The versioned vault header (U5) — one of the three beside-the-AEAD
//! files (D42).
//!
//! # Format (frozen envelope, versioned body)
//!
//! ```text
//! file := MAGIC                        ("ANTSEAL VAULT HEADER", 20 bytes)
//!       ‖ canonical CBOR array(2):     [ format_version: uint, body: bstr ]
//! body (v1) := canonical CBOR map:     { 0: kdf_block    (bstr, ≤ 512 B),
//!                                        1: wrap_mode     (uint, D50 registry),
//!                                        2: keyfile_path  (bstr, OPTIONAL —
//!                                           present only for wrap mode 1) }
//! ```
//!
//! Key 2 is a **pre-release extension of v1**, not a version bump: nothing
//! has shipped, writer and reader move together, and a body carrying it is
//! produced only by a keyfile vault — which an older build could not open
//! in any case. (Post-release the identical change is a
//! [`VAULT_FORMAT_VERSION`] event. Same rule `vault/export.rs` records for
//! its payload.)
//!
//! Recording the path is optional even for mode 1, and what it costs is
//! stated in `vault/keyfile.rs`: it tells anyone who reaches the vault
//! directory *where* the second factor lives, and it buys a wrap that does
//! not have to be re-declared on every invocation. Because the header is
//! AAD for every record, a tampered path is an authentication failure for
//! the whole vault rather than a silent redirect at an attacker's file.
//!
//! The **envelope** (magic + `[version, body]`) is frozen forever: future
//! versions redefine only the body, so any build can always read the
//! version and answer "created by newer antseal" cleanly (U5 Accept).
//! Deterministic-CBOR discipline comes from `antseal_core::codec`
//! (project rule 5): non-canonical bytes are decode errors, and the
//! decoder is total over adversarial input.
//!
//! The **KDF block is deliberately opaque at this layer** — a byte string
//! whose internal schema U6 owns (D40: algorithm id + full parameters +
//! salt; the D40 §3 pre-auth caps run inside that parse, before any KDF
//! allocation). U5 caps only its size, so a garbled or hostile header is
//! bounded before U6 ever looks at it. The wrap-mode id is the D50
//! registry ([`WRAP_MODE_NONE`], [`WRAP_MODE_KEYFILE`],
//! [`WRAP_MODE_OS_KEYSTORE_RESERVED`]); parse accepts every *registered*
//! id — the distinct "wrap mode not supported" refusal for the reserved
//! id is U8's unlock-time behavior, which requires the header to parse.
//!
//! **AAD contract (D42 rider):** the exact bytes [`VaultHeader::encode`]
//! returns are what U6 binds as AAD into every vault AEAD. Any header
//! edit that survives this parser is therefore still caught at unlock as
//! an authentication failure.

use antseal_core::codec::{CanonicalDecoder, DecodeError, EncodeError, encode_item};
use thiserror::Error;

use crate::error::CliError;

/// Header file magic. Deliberately distinct from the Q2-reserved
/// vault-*export* magic (testdata/README.md §magic registry) so the
/// secret-guard lane's export scan can never confuse the two — that
/// exact literal is what the guard greps for, which is also why this
/// comment names it only indirectly; the header file carries no secrets.
pub const HEADER_MAGIC: &[u8; 20] = b"ANTSEAL VAULT HEADER";

/// Current vault format version. Bumping it is a format event: a new
/// body schema, a migration story, and new tests land together.
pub const VAULT_FORMAT_VERSION: u32 = 1;

/// Parse cap on the whole header file (defensive: D10-caps precedent).
pub const MAX_HEADER_BYTES: usize = 4096;

/// Parse cap on the opaque KDF block (a real block is ~tens of bytes:
/// algorithm id + parameters + 16-B salt; D40).
pub const MAX_KDF_BLOCK_BYTES: usize = 512;

/// Parse cap on the optional recorded keyfile path.
pub const MAX_KEYFILE_PATH_BYTES: usize = 1024;

/// D50 wrap-mode registry: no extra wrap (passphrase-only vault).
pub const WRAP_MODE_NONE: u8 = 0;
/// D50 wrap-mode registry: high-entropy keyfile wrap for `W`.
pub const WRAP_MODE_KEYFILE: u8 = 1;
/// D50 wrap-mode registry: OS keystore — **reserved, no M1
/// implementation**. Parseable so U8 can refuse it distinctly at unlock.
pub const WRAP_MODE_OS_KEYSTORE_RESERVED: u8 = 2;
/// Highest registered wrap-mode id; anything above is unknown.
pub const MAX_REGISTERED_WRAP_MODE: u8 = 2;

/// Everything that can be wrong with header bytes. Total over
/// adversarial input — no panic path.
#[derive(Debug, Error)]
pub enum HeaderError {
    /// File exceeds [`MAX_HEADER_BYTES`].
    #[error("vault header is {len} bytes, over the {MAX_HEADER_BYTES}-byte cap")]
    TooLarge { len: usize },

    /// The magic prefix is absent.
    #[error("not an antseal vault header (bad magic)")]
    BadMagic,

    /// The CBOR after the magic is not canonical / not decodable.
    #[error("vault header is not canonical CBOR: {source}")]
    Codec {
        #[from]
        source: DecodeError,
    },

    /// Canonical CBOR of the wrong shape for the frozen envelope or the
    /// v1 body schema.
    #[error("vault header structure is invalid: {detail}")]
    Schema { detail: &'static str },

    /// KDF block exceeds [`MAX_KDF_BLOCK_BYTES`].
    #[error("vault header KDF block is {len} bytes, over the {MAX_KDF_BLOCK_BYTES}-byte cap")]
    KdfBlockTooLarge { len: usize },

    /// The recorded keyfile path is over [`MAX_KEYFILE_PATH_BYTES`], not
    /// UTF-8, or present on a header whose wrap mode is not the keyfile
    /// mode (constructible ≡ decodable — the F41 rule).
    #[error("vault header keyfile path is invalid: {detail}")]
    KeyfilePath { detail: &'static str },

    /// Wrap-mode id outside the D50 registry.
    #[error(
        "vault header wrap-mode id {found} is not in the registry \
         (0 = none, 1 = keyfile, 2 = os-keystore reserved)"
    )]
    WrapModeUnknown { found: u64 },

    /// Version 0 is never issued.
    #[error("vault header format version 0 is invalid (versions start at 1)")]
    InvalidVersion,

    /// Written by a build newer than this one. For a from-the-future
    /// header the version number is the only field v1 trusts; the body
    /// is not parsed.
    #[error(
        "vault created by a newer antseal (vault format v{found}; this build supports up \
         to v{VAULT_FORMAT_VERSION})"
    )]
    NewerVersion { found: u64 },

    /// Writer-side encode failure (unreachable for the fixed v1 shape;
    /// kept as an error rather than a panic — library discipline).
    #[error("could not encode the vault header: {source}")]
    Encode {
        #[from]
        source: EncodeError,
    },
}

impl From<HeaderError> for CliError {
    fn from(err: HeaderError) -> Self {
        match err {
            // U5 Accept: the clean "created by newer antseal" class.
            HeaderError::NewerVersion { found } => CliError::VaultNewerVersion {
                found,
                supported: VAULT_FORMAT_VERSION,
            },
            // Writer-side encode failure is a bug, not a vault problem.
            HeaderError::Encode { source } => CliError::Internal {
                detail: format!("vault header encode failed: {source}"),
            },
            // Everything else collapses into the vault-auth class — a
            // mangled header is indistinguishable from tamper, and U6
            // keeps that collapse deliberate ("insofar as safe").
            _ => CliError::VaultAuthFailure,
        }
    }
}

/// The parsed (or to-be-written) vault header.
///
/// Constructible only through [`VaultHeader::new`], which enforces the
/// same caps decode enforces — constructible == decodable (the F41
/// lesson: constructors must not be able to mint headers the parser
/// rejects).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    kdf_block: Vec<u8>,
    wrap_mode: u8,
    keyfile_path: Option<String>,
}

impl VaultHeader {
    /// Build a v1 header.
    ///
    /// # Errors
    ///
    /// [`HeaderError::KdfBlockTooLarge`] / [`HeaderError::WrapModeUnknown`]
    /// under exactly the decode-side caps.
    pub fn new(kdf_block: Vec<u8>, wrap_mode: u8) -> Result<Self, HeaderError> {
        Self::new_with_keyfile_path(kdf_block, wrap_mode, None)
    }

    /// Build a v1 header that also records where the keyfile lives (U8).
    ///
    /// # Errors
    ///
    /// The [`Self::new`] caps, plus [`HeaderError::KeyfilePath`] when a
    /// path is given for a non-keyfile wrap mode or is over cap —
    /// constructible ≡ decodable, so no constructor can mint a header the
    /// parser would reject.
    pub fn new_with_keyfile_path(
        kdf_block: Vec<u8>,
        wrap_mode: u8,
        keyfile_path: Option<String>,
    ) -> Result<Self, HeaderError> {
        if kdf_block.len() > MAX_KDF_BLOCK_BYTES {
            return Err(HeaderError::KdfBlockTooLarge {
                len: kdf_block.len(),
            });
        }
        if wrap_mode > MAX_REGISTERED_WRAP_MODE {
            return Err(HeaderError::WrapModeUnknown {
                found: u64::from(wrap_mode),
            });
        }
        if let Some(path) = &keyfile_path {
            if wrap_mode != WRAP_MODE_KEYFILE {
                return Err(HeaderError::KeyfilePath {
                    detail: "a keyfile path may only accompany wrap mode 1",
                });
            }
            if path.is_empty() || path.len() > MAX_KEYFILE_PATH_BYTES {
                return Err(HeaderError::KeyfilePath {
                    detail: "empty or over the recorded-path cap",
                });
            }
        }
        Ok(VaultHeader {
            kdf_block,
            wrap_mode,
            keyfile_path,
        })
    }

    /// The recorded keyfile path, if this vault recorded one (U8).
    #[must_use]
    pub fn keyfile_path(&self) -> Option<&str> {
        self.keyfile_path.as_deref()
    }

    /// The opaque KDF block (schema owned by U6/D40).
    #[must_use]
    pub fn kdf_block(&self) -> &[u8] {
        &self.kdf_block
    }

    /// The D50 wrap-mode id.
    #[must_use]
    pub fn wrap_mode(&self) -> u8 {
        self.wrap_mode
    }

    /// Serialize to the exact on-disk (and AAD) bytes.
    ///
    /// # Errors
    ///
    /// [`HeaderError::Encode`] — unreachable for the fixed v1 shape, but
    /// never a panic.
    pub fn encode(&self) -> Result<Vec<u8>, HeaderError> {
        let body = encode_item(|e| {
            e.map(|m| {
                m.entry(0, |e| e.bytes(&self.kdf_block))?;
                m.entry(1, |e| e.u64(u64::from(self.wrap_mode)))?;
                if let Some(path) = &self.keyfile_path {
                    m.entry(2, |e| e.bytes(path.as_bytes()))?;
                }
                Ok(())
            })
        })?;
        let envelope = encode_item(|e| {
            e.array(|a| {
                a.item(|e| e.u64(u64::from(VAULT_FORMAT_VERSION)))?;
                a.item(|e| e.bytes(&body))
            })
        })?;
        let mut out = Vec::with_capacity(HEADER_MAGIC.len() + envelope.len());
        out.extend_from_slice(HEADER_MAGIC);
        out.extend_from_slice(&envelope);
        Ok(out)
    }

    /// Parse header bytes (defensive; total over adversarial input).
    ///
    /// # Errors
    ///
    /// Every [`HeaderError`] class per its docs; notably
    /// [`HeaderError::NewerVersion`] for any version above
    /// [`VAULT_FORMAT_VERSION`], without parsing the future body.
    pub fn decode(bytes: &[u8]) -> Result<Self, HeaderError> {
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(HeaderError::TooLarge { len: bytes.len() });
        }
        let rest = bytes
            .strip_prefix(HEADER_MAGIC.as_slice())
            .ok_or(HeaderError::BadMagic)?;

        // Frozen envelope: array(2) [version, body-bstr].
        let mut d = CanonicalDecoder::new(rest);
        if d.array()? != 2 {
            return Err(HeaderError::Schema {
                detail: "envelope must be a 2-element array [version, body]",
            });
        }
        let version = d.u64()?;
        if version == 0 {
            return Err(HeaderError::InvalidVersion);
        }
        if version > u64::from(VAULT_FORMAT_VERSION) {
            return Err(HeaderError::NewerVersion { found: version });
        }
        let body = d.bytes()?;
        d.finish()?;

        // v1 body: strict schema over the embedded bytes (each layer runs
        // its own canonical pass — the embedded-bstr house rule).
        let mut b = CanonicalDecoder::new(body);
        let mut map = b.map()?;
        // 2 entries, or 3 when the optional keyfile path (key 2) is
        // recorded — the pre-release v1 extension in the module docs.
        if !matches!(map.remaining(), 2 | 3) {
            return Err(HeaderError::Schema {
                detail: "v1 body must be {0: kdf_block, 1: wrap_mode} with an optional \
                         2: keyfile_path",
            });
        }
        let has_keyfile_path = map.remaining() == 3;
        if map.next_key(&mut b)? != Some(0) {
            return Err(HeaderError::Schema {
                detail: "v1 body key 0 (kdf_block) missing",
            });
        }
        let kdf_block = b.bytes()?;
        if kdf_block.len() > MAX_KDF_BLOCK_BYTES {
            return Err(HeaderError::KdfBlockTooLarge {
                len: kdf_block.len(),
            });
        }
        if map.next_key(&mut b)? != Some(1) {
            return Err(HeaderError::Schema {
                detail: "v1 body key 1 (wrap_mode) missing",
            });
        }
        let wrap_mode = b.u64()?;
        if wrap_mode > u64::from(MAX_REGISTERED_WRAP_MODE) {
            return Err(HeaderError::WrapModeUnknown { found: wrap_mode });
        }
        // Bounded by MAX_REGISTERED_WRAP_MODE (≤ 2) just above.
        let wrap_mode = u8::try_from(wrap_mode).map_err(|_| HeaderError::Schema {
            detail: "wrap_mode exceeds u8 (unreachable: registry-capped)",
        })?;

        let keyfile_path = if has_keyfile_path {
            if map.next_key(&mut b)? != Some(2) {
                return Err(HeaderError::Schema {
                    detail: "v1 body's third entry must be key 2 (keyfile_path)",
                });
            }
            let raw = b.bytes()?;
            if raw.len() > MAX_KEYFILE_PATH_BYTES {
                return Err(HeaderError::KeyfilePath {
                    detail: "over the recorded-path cap",
                });
            }
            let path = std::str::from_utf8(raw).map_err(|_| HeaderError::KeyfilePath {
                detail: "not valid UTF-8 (v1 records paths as UTF-8 text)",
            })?;
            Some(path.to_owned())
        } else {
            None
        };
        b.finish()?;

        // Decodable ≡ constructible: run the constructor's own
        // cross-field rule rather than a second copy of it.
        VaultHeader::new_with_keyfile_path(kdf_block.to_vec(), wrap_mode, keyfile_path)
    }
}
