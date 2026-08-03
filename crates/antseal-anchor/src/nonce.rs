//! The TSA request nonce (decision D59 §4).
//!
//! Eight bytes from the OS CSPRNG, drawn **here** rather than in
//! `antseal-core`, and the split is the point: `build_timestamp_req` is a pure
//! function of a digest and a nonce, which is what makes it deterministic and
//! golden-vectorable, and the constraint that binds `antseal-core` is that no
//! RNG may enter it at all (the `core-dep-graph` lane enforces it
//! mechanically). `antseal-anchor` carries no WASM-safety constraint — it is
//! not in the verifier page's graph — so the CSPRNG lives on this side.
//!
//! # Eight bytes, exactly
//!
//! The property a nonce buys is that *this* response answers *this* request
//! across one HTTP round trip of about a second; 2⁻⁶⁴ per blind attempt inside
//! that window is ample, and against an attacker who can *see* the request it
//! provides nothing at any width. Against that, the value is echoed into a
//! signed token that ships in every bundle forever, so every extra byte is a
//! permanent wire cost. Eight is also the interoperable width — openssl's own
//! default, which is what the project's default TSAs see from everyone else.
//!
//! The **16-byte analogy to `unit_salt`/`path_salt`/`file_salt` does not
//! apply**: those are secret and hiding-critical; this one is published.
//!
//! # Not secret, and deliberately not zeroized
//!
//! A drawn nonce goes into a request that is transmitted, is echoed by the TSA
//! into a signed token, and is then stored in the vault's capture record and
//! shipped in every bundle carrying that token. Project rule 6 governs `W`,
//! unit keys and salts; a value published in every artifact is not that, and
//! treating it as secret here would suggest to a future reader that the copy
//! in the token needs protecting too.

/// The width of a TSA request nonce, in bytes. Consumed by name from
/// `antseal-core` so the drawer and the encoder cannot disagree.
pub use antseal_core::anchor::request::TSA_REQUEST_NONCE_LEN;

/// The OS CSPRNG was unavailable.
///
/// Its own type rather than a string: A10 must be able to distinguish "this
/// machine cannot produce randomness" — under which no TSA request may be
/// sent at all — from a TSA that failed to answer one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the operating system CSPRNG is unavailable, so no timestamp request can be built")]
pub struct NonceUnavailable;

/// Draw a fresh request nonce.
///
/// # Errors
///
/// [`NonceUnavailable`] if the OS CSPRNG fails. **Never fall back** to a
/// weaker source: the failure direction is a missed anchor, and a predictable
/// nonce silently removes the only protection against a replayed token that
/// plain-HTTP RFC 3161 traffic has (D90 §6.6).
pub fn draw_request_nonce() -> Result<[u8; TSA_REQUEST_NONCE_LEN], NonceUnavailable> {
    let mut nonce = [0u8; TSA_REQUEST_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| NonceUnavailable)?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The width is the one D59 ruled, and it comes from `antseal-core`.
    #[test]
    fn the_nonce_is_exactly_eight_bytes() {
        assert_eq!(TSA_REQUEST_NONCE_LEN, 8);
        assert_eq!(
            draw_request_nonce()
                .expect("the OS CSPRNG works in CI")
                .len(),
            8
        );
    }

    /// Successive draws differ.
    ///
    /// Not a randomness test — it cannot be one — but it does catch the two
    /// failure modes that matter here and have both shipped in real code: a
    /// constant, and a buffer that is allocated and never filled. 64 draws
    /// with any repeat is a 1-in-2⁵⁷ event under a working CSPRNG.
    #[test]
    fn successive_draws_differ() {
        let draws: BTreeSet<[u8; TSA_REQUEST_NONCE_LEN]> = (0..64)
            .map(|_| draw_request_nonce().expect("CSPRNG"))
            .collect();
        assert_eq!(draws.len(), 64, "a repeated draw means a constant nonce");
        assert!(
            !draws.contains(&[0u8; TSA_REQUEST_NONCE_LEN]),
            "an all-zero draw is what an unfilled buffer looks like"
        );
    }

    /// A drawn nonce goes through A4's encoder and back, so the two halves of
    /// D59 §4 are exercised together rather than each in isolation.
    #[test]
    fn a_drawn_nonce_builds_a_request() {
        let nonce = draw_request_nonce().expect("CSPRNG");
        let request = antseal_core::anchor::request::build_timestamp_req(&[0x11; 32], &nonce);
        // 61 + the nonce's 1..=9 content octets.
        assert!((62..=70).contains(&request.len()), "{}", request.len());
        let canonical = antseal_core::anchor::request::canonical_request_nonce(&nonce);
        assert!(
            request
                .windows(canonical.len())
                .any(|window| window == canonical.as_slice()),
            "the canonical nonce encoding must appear in the request"
        );
    }
}
