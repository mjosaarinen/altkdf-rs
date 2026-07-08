#![no_std]
//! # deck-schedule
//!
//! Reference implementation of the TLS 1.3 *deck key schedule* defined in
//! `draft-sullivan-tls-xof-ciphers-00` ("TLS 1.3 Cipher Suites with
//! Alternative Key-Schedule Profiles").
//!
//! The crate is deliberately standalone, with a single dependency — [`zeroize`],
//! to erase live secret state on drop (draft §15.7.2.2). It is **`#![no_std]`**
//! (it needs only [`alloc`] for heap buffers — the draft defines pure compute, no
//! I/O), so it builds for bare-metal targets; `make no-std` compiles it for
//! `thumbv7em-none-eabi` as a regression guard. It implements the
//! Keccak-p\[1600, nr\] permutation, the sponge, the framed deck operations, the
//! MAC, and every derivation of the draft, so the cryptographic core can be
//! validated against public KATs (RFC 9861, FIPS 202, SP 800-185) and, later,
//! against the draft's own Appendix C vectors — *before* any TLS stack is
//! involved. The rustls fork (see `../rustls-integration`) calls into this
//! crate.
//!
//! ## Secret handling (draft §15.7.2.2)
//!
//! Live secret state is zeroized on drop: the [`sponge::Sponge`] state (the
//! withheld capacity), the [`deck::Deck`] accumulator (which holds absorbed
//! secrets in framed form), and every squeezed secret — returned as [`Secret`]
//! ([`zeroize::Zeroizing`]) rather than a bare `Vec<u8>`. Wire values
//! (`verify_data`, ECH confirmations, the serialized identity) stay `Vec<u8>`.
//!
//! ## Module map (→ draft sections)
//!
//! | module        | draft section        | what it is                              |
//! |---------------|----------------------|-----------------------------------------|
//! | [`keccak`]    | §8.1, §9.1           | Keccak-p\[1600, nr\] permutation         |
//! | [`sponge`]    | §8.1, §9.1           | rate-136 / capacity-512 sponge           |
//! | [`frame`]     | §2, §5.2             | `frame()` + the KMAC length encoders     |
//! | [`profile`]   | §3, §8, §9           | profile parameters + `DF(S, L)`          |
//! | [`transcript`]| §2.1                 | `TranscriptHash`                         |
//! | [`deck`]      | §7.1                 | `Init/Absorb/Fork/Squeeze/Ratchet`       |
//! | [`import`]    | §10                  | `ImportedIdentityV2` + external PSK import|
//! | [`mac`]       | §5.2                 | `MAC` (TurboKMAC256 / KMAC256)           |
//! | [`suites`]    | §6                   | cipher suites + Nk/Nn code points        |
//! | [`schedule`]  | §7.3                 | the three-stage E/H/T key schedule       |
//! | [`derive`](mod@derive) | §5             | leaf derivations (keys, MACs, exporters) |
//! | [`fips`]      | Appendix D           | FIPS-component schedule (informative)    |
//! | [`vectors`]   | Appendix C, D        | deterministic test-vector generation     |
//!
//! ## Status
//!
//! The primitives are pinned to public KATs (RFC 9861, FIPS 202, SP 800-185),
//! and the full schedule plus every §5 derivation is emitted as test vectors
//! (see [`vectors`]) and reproduced byte-for-byte by an independent
//! implementation (`vectors/reproduce.py`). The rustls integration in
//! `../rustls-integration` drives this crate for a live TLS 1.3 handshake
//! (Stage 4, done). See `PLAN.md` at the repo root for the staged plan and which
//! pieces are validated.

extern crate alloc;

// The test harness (and integration tests) need `std`; the library itself is
// `no_std` + `alloc` (draft has no I/O — it is pure compute over heap buffers).
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

pub mod deck;
pub mod derive;
pub mod fips;
pub mod frame;
pub mod import;
pub mod keccak;
pub mod mac;
pub mod profile;
pub mod schedule;
pub mod sponge;
pub mod suites;
pub mod transcript;
pub mod vectors;

pub use import::ImportedIdentityV2;
pub use profile::{Profile, SHAKE256, TURBOSHAKE256};
pub use suites::CipherSuite;

/// A heap-allocated key-schedule secret that is **zeroized on drop** (draft
/// §15.7.2.2). Every squeezed secret this crate hands back — stage and traffic
/// secrets, `finished_key` / `binder_key`, record keys, resumption/exporter
/// outputs, the imported `ipsk` — is returned in this wrapper rather than a bare
/// `Vec<u8>`, so callers cannot accidentally leave key material in freed heap.
/// It derefs to `[u8]`, so it is used like any byte slice.
///
/// Non-secret outputs that go on the wire (Finished / binder `verify_data`, ECH
/// confirmations, the `ImportedIdentityV2` identity) stay plain `Vec<u8>`.
///
/// One deliberate exception: [`schedule::run`] is a *reference* implementation
/// used only to generate Appendix C vectors and cross-check the fork (never the
/// production key schedule — the rustls fork drives the deck operations directly).
/// Its [`ScheduleOutputs`](schedule::ScheduleOutputs) keep plain `Vec<u8>` fields
/// so vector generation has stable bytes; those structs are not live secret state.
pub type Secret = zeroize::Zeroizing<Vec<u8>>;

#[cfg(test)]
mod tests {
    /// The live-secret wrappers carry the `ZeroizeOnDrop` marker (draft §15.7.2.2):
    /// the sponge state, the deck accumulator, and every squeezed [`Secret`]. A
    /// compile-time check — memory erasure itself is not testable by reading freed
    /// storage.
    #[test]
    fn live_secret_types_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<crate::sponge::Sponge>();
        assert_zeroize_on_drop::<crate::deck::Deck<'static>>();
        assert_zeroize_on_drop::<crate::Secret>();
    }
}
