//! The two KDFs of the draft and the protocol's schedule label (draft
//! `[schedule-profiles]`, `[turboshake-profile]`, `[shake-profile]`).
//!
//! A KDF is negotiated in the `schedule_profile` extension, independently of the
//! cipher suite, and names one of the TLS KDF Identifiers of RFC 9258. Both KDFs
//! here instantiate the same deck schedule and differ only in the permutation:
//! 12-round Keccak-p\[1600,12\] (TurboSHAKE256) or 24-round Keccak-f\[1600\]
//! (SHAKE256).

use alloc::vec::Vec;

use crate::sponge::{Sponge, DOMAIN_DECK, RATE};

/// A KDF of this document (draft `[schedule-profiles]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    /// TLS KDF Identifier. TBD in the draft; the values here are the
    /// placeholders of the Test Vectors appendix (0x0100, 0x0101).
    pub id: u16,
    /// Registry name.
    pub name: &'static str,
    /// Keccak-p round count: 12 (TurboSHAKE256) or 24 (SHAKE256).
    pub rounds: usize,
    /// `SecretLen`: length of every stage and traffic secret.
    pub secret_len: usize,
    /// `FLen`: length of Finished and binder verify_data.
    pub flen: usize,
}

/// Length of `TranscriptHash` output in both KDFs (draft `[transcript-hash]`).
pub const HASH_LEN: usize = 64;

impl Kdf {
    /// `DF(S, L)`: `TurboSHAKE256(seq, 0x1F, L)` or `SHAKE256(seq, 8*L)` (draft
    /// `[turboshake-instantiation]`, `[shake-instantiation]`). The length checks
    /// (1..=65535) are made by the deck before this is reached.
    pub fn df(&self, seq: &[u8], l: usize) -> Vec<u8> {
        let mut s = Sponge::new(RATE, DOMAIN_DECK, self.rounds);
        s.absorb(seq);
        s.squeeze_vec(l)
    }

    /// Look up a KDF by its TLS KDF Identifier.
    pub fn from_id(id: u16) -> Option<Kdf> {
        ALL.iter().copied().find(|k| k.id == id)
    }
}

/// `TLS13_TURBOSHAKE256` (draft `[turboshake-profile]`).
pub const TURBOSHAKE256: Kdf = Kdf {
    id: 0x0100,
    name: "TLS13_TURBOSHAKE256",
    rounds: 12,
    secret_len: 64,
    flen: 64,
};

/// `TLS13_SHAKE256` (draft `[shake-profile]`).
pub const SHAKE256: Kdf = Kdf {
    id: 0x0101,
    name: "TLS13_SHAKE256",
    rounds: 24,
    secret_len: 64,
    flen: 64,
};

/// Both KDFs, TurboSHAKE256 first.
pub const ALL: [Kdf; 2] = [TURBOSHAKE256, SHAKE256];

/// TLS KDF Identifiers of RFC 9258 that a `ScheduleProfileList` MUST NOT carry
/// (draft `[cipher-suites]`): absence of the extension is the only signal for the
/// TLS 1.3 schedule.
pub const HKDF_SHA256: u16 = 0x0001;
/// See [`HKDF_SHA256`].
pub const HKDF_SHA384: u16 = 0x0002;

/// TLS 1.3 or DTLS 1.3: selects `schedule_label` (draft `[deck-schedule]`, `[dtls]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// `schedule_label` = `"tls13 "` (with the trailing space).
    Tls13,
    /// `schedule_label` = `"dtls13"`.
    Dtls13,
}

impl Protocol {
    /// The 6-octet `schedule_label`, framed at every `Init`.
    pub fn schedule_label(self) -> &'static [u8; 6] {
        match self {
            Protocol::Tls13 => b"tls13 ",
            Protocol::Dtls13 => b"dtls13",
        }
    }

    /// The RFC 9258 `target_protocol` value (the protocol version code point).
    pub fn version(self) -> u16 {
        match self {
            Protocol::Tls13 => 0x0304,
            Protocol::Dtls13 => 0xfefc,
        }
    }

    /// Inverse of [`Protocol::version`].
    pub fn from_version(v: u16) -> Option<Protocol> {
        match v {
            0x0304 => Some(Protocol::Tls13),
            0xfefc => Some(Protocol::Dtls13),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_lookup() {
        assert_eq!(Kdf::from_id(0x0100), Some(TURBOSHAKE256));
        assert_eq!(Kdf::from_id(0x0101), Some(SHAKE256));
        assert_eq!(Kdf::from_id(HKDF_SHA256), None);
        assert_eq!(Kdf::from_id(HKDF_SHA384), None);
    }

    #[test]
    fn schedule_labels_are_six_octets() {
        assert_eq!(Protocol::Tls13.schedule_label(), b"tls13 ");
        assert_eq!(Protocol::Dtls13.schedule_label(), b"dtls13");
    }
}
