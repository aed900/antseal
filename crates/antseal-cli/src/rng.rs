//! The production OS-CSPRNG (the CLI is the sanctioned caller that
//! injects the OS source — antseal-core and the vault primitives take
//! injected RNGs only, C5 discipline).
//!
//! A 15-line adapter over the exact-pinned `getrandom` rather than a new
//! feature edge: `getrandom 0.4` ships its own `SysRng` behind the
//! `sys_rng` feature, but enabling it means touching the shared workspace
//! declaration and the lock for an adapter this small; the delegation
//! below is byte-equivalent (every method is a direct `getrandom` call)
//! and trivially reviewable. Fallible by design — entropy failure
//! surfaces as a typed error at the call site, never a panic.

use rand_core::{TryCryptoRng, TryRng};

/// The operating system's CSPRNG as a [`TryCryptoRng`]. Zero-sized;
/// construct freely (`&mut OsEntropy`).
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

impl TryRng for OsEntropy {
    type Error = getrandom::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        getrandom::u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        getrandom::u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst)
    }
}

/// CSPRNG marker: `getrandom` draws from the OS entropy source
/// (`getrandom(2)`-class interfaces), which is the definition of the
/// system CSPRNG — the same claim upstream's `SysRng` makes.
impl TryCryptoRng for OsEntropy {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The adapter draws real bytes (smoke — determinism is neither
    /// expected nor asserted; seeded RNG tests use `rand_chacha`).
    #[test]
    fn draws_bytes_from_the_os() {
        let mut rng = OsEntropy;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.try_fill_bytes(&mut a).expect("OS entropy");
        rng.try_fill_bytes(&mut b).expect("OS entropy");
        assert_ne!(a, b, "two 256-bit draws colliding is not a thing");
    }
}
