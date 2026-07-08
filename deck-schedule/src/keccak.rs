//! Keccak-p\[1600, nr\] permutation (draft §8.1, §9.1).
//!
//! `nr = 12` is the permutation of TurboSHAKE256 (Keccak-p\[1600,12\], used by
//! the `TLS13-TURBOSHAKE256` profile); `nr = 24` is Keccak-f\[1600\] (used by
//! the `TLS13-SHAKE256` profile). A reduced-round instance uses the *last*
//! `nr` of the 24 round constants, per the Keccak-p convention and [RFC 9861].
//!
//! Validated indirectly by the SHAKE256 KAT in [`crate::sponge`] (24 rounds);
//! the TurboSHAKE256 KATs in [`crate::sponge`] validate the 12-round path.

const ROUNDS_MAX: usize = 24;

/// Iota round constants (RC\[0..24\]).
const RC: [u64; ROUNDS_MAX] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rho rotation offsets, indexed by lane `x + 5*y`.
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, //
    36, 44, 6, 55, 20, //
    3, 10, 43, 25, 39, //
    41, 45, 15, 21, 8, //
    18, 2, 61, 56, 14,
];

/// Apply Keccak-p\[1600, `rounds`\] in place to a 25-lane state (little-endian
/// lanes). `rounds` must be `<= 24`.
/// Keccak-p\[1600\] permutation-call counter for the Appendix A.1 benchmark
/// (`examples/invocations.rs`). Gated behind the `bench` feature so it is
/// entirely absent — no counter, no branch — from normal builds.
///
/// A process-wide [`AtomicU64`] (not a thread-local): the crate is `#![no_std]`,
/// so `thread_local!` is unavailable, and the benchmark is single-threaded and
/// sequential (`reset()` then measure), so a global counter is exact.
#[cfg(feature = "bench")]
pub mod count {
    use core::sync::atomic::{AtomicU64, Ordering};

    static PERMS: AtomicU64 = AtomicU64::new(0);

    pub(super) fn bump() {
        PERMS.fetch_add(1, Ordering::Relaxed);
    }

    /// Keccak-p\[1600\] permutation calls since the last [`reset`].
    pub fn permutations() -> u64 {
        PERMS.load(Ordering::Relaxed)
    }

    /// Reset the permutation counter to zero.
    pub fn reset() {
        PERMS.store(0, Ordering::Relaxed);
    }
}

/// Apply Keccak-p\[1600, `rounds`\] to `state` in place (draft §8.1, §9.1).
/// `rounds` is 12 for TurboSHAKE256 or 24 for SHAKE256 (Keccak-f\[1600\]); a
/// reduced-round instance uses the *last* `rounds` of the 24 round constants.
pub fn keccak_p(state: &mut [u64; 25], rounds: usize) {
    #[cfg(feature = "bench")]
    count::bump();
    debug_assert!(rounds <= ROUNDS_MAX);
    let first = ROUNDS_MAX - rounds;
    for &rc in RC.iter().skip(first) {
        // θ (theta)
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ρ (rho) + π (pi)
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let src = x + 5 * y;
                let dst = y + 5 * ((2 * x + 3 * y) % 5);
                b[dst] = state[src].rotate_left(RHO[src]);
            }
        }

        // χ (chi)
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // ι (iota)
        state[0] ^= rc;
    }
}
