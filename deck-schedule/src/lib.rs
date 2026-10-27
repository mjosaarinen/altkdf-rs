#![no_std]
//! Prototype of `draft-sullivan-tls-xof-schedule`. KDF negotiation is
//! independent of the TLS 1.3 AEAD cipher suite.
//!
//! The `no_std` + `alloc` core implements the framed deck interface, both XOFs,
//! the three-stage schedule, retained-secret derivations, and RFC 9258 import.
//! The repository README identifies the specification revision and section anchors.
//!
//! Live accumulators and squeezed secrets are zeroized on drop
//! (`[erasure-boundaries]`). Wire values stay ordinary byte vectors. Only the
//! reference-only [`schedule::run`] and [`vectors`] expose plain vectors of
//! synthetic secrets; applications use the stage API instead.

extern crate alloc;
#[cfg(test)]
extern crate std;
use alloc::vec::Vec;

pub mod deck;
pub mod derive;
pub mod frame;
pub mod hex;
pub mod import;
pub mod kdf;
pub mod keccak;
pub mod labels;
pub mod schedule;
pub mod sponge;
pub mod suites;
pub mod transcript;
pub mod vectors;

pub use import::ImportedIdentity;
pub use kdf::{Kdf, Protocol, SHAKE256, TURBOSHAKE256};
pub use suites::CipherSuite;

/// Live secret bytes, erased on drop. Reference/vector outputs are the sole
/// intentional exception; they must never carry production secrets.
pub type Secret = zeroize::Zeroizing<Vec<u8>>;

/// Invalid input to a bounded draft operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    OutputLength,
    DeriveNCount,
    DuplicateLabel,
    UnregisteredLabel,
    FrameTooLong,
    EmptyContext,
    InvalidPsk,
    IdentityFieldOutOfRange,
    IdentityTooLong,
    WrongTargetProtocol,
    UnknownTargetKdf,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid key-schedule input: {self:?}")
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn live_secret_types_zeroize_on_drop() {
        fn check<T: zeroize::ZeroizeOnDrop>() {}
        check::<crate::sponge::Sponge>();
        check::<crate::deck::Deck>();
        check::<crate::Secret>();
    }
}
