//! A **deterministic** randomness source for fixtures (Q3's determinism
//! principle applied to the one place tests cannot avoid randomness).
//!
//! Some crate APIs draw randomness *internally* and by design admit no
//! caller-supplied value — [`crate::crypto::unit_aead::encrypt_unit`] draws
//! its own 24-byte nonce so the `(k_u, nonce)` single-use invariant has no
//! bypass (MVP-SPEC.md lines 91, 145). Building a *reproducible* encrypted
//! unit for a tamper row or a golden vector therefore means injecting a
//! reproducible generator, not a nonce.
//!
//! Library test infrastructure cannot reach for `rand_chacha`: that is a
//! dev-dependency, available to `cfg(test)` code in this crate but **not**
//! to `test-util` code compiled for downstream test targets. So this module
//! builds a generator from the crate's existing WASM-safe dependency set.
//!
//! # Construction
//!
//! A SHA-256 counter DRBG:
//!
//! ```text
//! block_i = SHA-256(seed ‖ LE64(i)),  i = 0, 1, 2, …
//! ```
//!
//! output = `block_0 ‖ block_1 ‖ …` truncated to the requested length.
//! Modelling SHA-256 as a random oracle — the same assumption the spec's
//! hiding argument already rests on (MVP-SPEC.md line 101) — this is a
//! secure PRG, which is why implementing [`TryCryptoRng`] for it is
//! defensible rather than a lie. It is nonetheless **fixture-only**: it has
//! no forward secrecy, its seed is a committed constant in test code, and no
//! production path can reach it (the `test-util` feature is never enabled in
//! a shipped build).
//!
//! Never use it to generate a real `W`, `seal_id`, or production nonce.

use sha2::{Digest, Sha256};

use rand_core::{Infallible, TryCryptoRng, TryRng};

/// Bytes of output per SHA-256 block.
const BLOCK_LEN: usize = 32;

/// A seeded, reproducible generator for fixture material (module docs).
///
/// Deliberately **not** `Clone`/`Copy`: two copies would produce the same
/// stream, and a repeated nonce is the one failure the AEAD's single-use
/// invariant exists to prevent — even in a fixture, a silently duplicated
/// stream would make a "two encrypts differ" test vacuous.
pub struct FixtureRng {
    seed: [u8; 32],
    counter: u64,
    block: [u8; BLOCK_LEN],
    /// Bytes of `block` already handed out; `BLOCK_LEN` means "exhausted".
    used: usize,
}

impl core::fmt::Debug for FixtureRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The seed is public fixture data, but printing generator state is
        // a habit worth not forming.
        f.write_str("FixtureRng(<deterministic fixture generator>)")
    }
}

impl FixtureRng {
    /// Start a stream from `seed`. Two generators with the same seed produce
    /// the same bytes — that is the point.
    #[must_use]
    pub const fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            block: [0u8; BLOCK_LEN],
            // Force a refill on first use.
            used: BLOCK_LEN,
        }
    }

    /// Start a stream from a `u64` label, widened by repetition — the
    /// convenient form for "give me *a* distinct fixture stream".
    #[must_use]
    pub fn from_label(label: u64) -> Self {
        let mut seed = [0u8; 32];
        for (index, chunk) in seed.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&(label ^ index as u64).to_le_bytes());
        }
        Self::from_seed(seed)
    }

    fn refill(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.seed);
        hasher.update(self.counter.to_le_bytes());
        self.block = hasher.finalize().into();
        self.counter = self.counter.wrapping_add(1);
        self.used = 0;
    }

    fn fill(&mut self, dst: &mut [u8]) {
        for byte in dst {
            if self.used == BLOCK_LEN {
                self.refill();
            }
            *byte = self.block[self.used];
            self.used += 1;
        }
    }
}

impl TryRng for FixtureRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(dst);
        Ok(())
    }
}

/// See the module docs for why the marker is defensible here, and for the
/// standing "fixtures only" restriction that comes with it.
impl TryCryptoRng for FixtureRng {}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(rng: &mut FixtureRng, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        rng.try_fill_bytes(&mut out).expect("infallible");
        out
    }

    /// The whole point: same seed, same bytes, on every OS and every run.
    #[test]
    fn the_stream_is_reproducible_and_seed_dependent() {
        let mut a = FixtureRng::from_seed([7u8; 32]);
        let mut b = FixtureRng::from_seed([7u8; 32]);
        assert_eq!(take(&mut a, 100), take(&mut b, 100));

        let mut c = FixtureRng::from_seed([8u8; 32]);
        assert_ne!(
            take(&mut FixtureRng::from_seed([7u8; 32]), 32),
            take(&mut c, 32)
        );
    }

    /// A single request and several small requests must yield the same
    /// stream — block boundaries are invisible to the caller.
    #[test]
    fn block_boundaries_do_not_shift_the_stream() {
        let one_shot = take(&mut FixtureRng::from_seed([1u8; 32]), 96);

        let mut piecewise = FixtureRng::from_seed([1u8; 32]);
        let mut out = Vec::new();
        for len in [1usize, 30, 1, 32, 32] {
            out.extend(take(&mut piecewise, len));
        }
        assert_eq!(out, one_shot);
    }

    /// The first block is exactly the documented construction, so a second
    /// implementation can reproduce a fixture stream from the module docs
    /// alone.
    #[test]
    fn the_first_block_matches_the_documented_construction() {
        let seed = [0x5Au8; 32];
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(0u64.to_le_bytes());
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(
            take(&mut FixtureRng::from_seed(seed), 32),
            expected.to_vec()
        );
    }

    #[test]
    fn integer_draws_and_labels_work() {
        let mut rng = FixtureRng::from_label(0xC17);
        let a = rng.try_next_u32().expect("infallible");
        let b = rng.try_next_u64().expect("infallible");
        // Distinct labels give distinct streams.
        let mut other = FixtureRng::from_label(0xC18);
        assert_ne!(
            (a, b),
            (
                other.try_next_u32().expect("infallible"),
                other.try_next_u64().expect("infallible")
            )
        );
        // Debug never prints state.
        assert_eq!(
            format!("{rng:?}"),
            "FixtureRng(<deterministic fixture generator>)"
        );
    }
}
