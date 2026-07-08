//! Schedule-profile parameters and the deck function `DF(S, L)` (draft §3, §8, §9).
//!
//! The two profiles differ only in `profile_id` and the permutation round count
//! (draft §9: "the two profiles' decks therefore differ only in the underlying
//! permutation"). `DF(S, L)` and `TranscriptHash` are otherwise identical.

use alloc::vec::Vec;

use crate::sponge::{Sponge, DOMAIN_DECK, RATE};

/// A schedule profile (draft §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    /// `profile_id`, framed first into every derivation (draft §7.1).
    pub profile_id: &'static [u8],
    /// Keccak-p round count: 12 (TurboSHAKE256) or 24 (SHAKE256).
    pub rounds: usize,
    /// `SecretLen`: length of every stage and traffic secret (draft §8, §9).
    pub secret_len: usize,
    /// `FLen`: length of Finished / binder verify_data (draft §8, §9).
    pub flen: usize,
}

impl Profile {
    /// `DF(S, L)` — squeeze `l` octets from the deck sequence `seq` (draft §7.1,
    /// §8.1, §9.1). For TURBOSHAKE256 this is `TurboSHAKE256(seq, 0x1F, l)`; for
    /// SHAKE256 this is `SHAKE256(seq, 8*l)`.
    pub fn df(&self, seq: &[u8], l: usize) -> Vec<u8> {
        let mut s = Sponge::new(RATE, DOMAIN_DECK, self.rounds);
        s.absorb(seq);
        s.squeeze_vec(l)
    }
}

/// `TLS13-TURBOSHAKE256` (draft §8): 12-round Keccak-p\[1600,12\].
pub const TURBOSHAKE256: Profile = Profile {
    profile_id: b"TLS 1.3 DeckSchedule v1", // 23 octets (draft §8)
    rounds: 12,
    secret_len: 64,
    flen: 64,
};

/// `TLS13-SHAKE256` (draft §9): 24-round Keccak-f\[1600\].
pub const SHAKE256: Profile = Profile {
    profile_id: b"TLS 1.3 SHAKESchedule v1", // 24 octets (draft §9)
    rounds: 24,
    secret_len: 64,
    flen: 64,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_id_lengths() {
        assert_eq!(TURBOSHAKE256.profile_id.len(), 23);
        assert_eq!(SHAKE256.profile_id.len(), 24);
    }
}
