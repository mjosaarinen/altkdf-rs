//! The deck `TranscriptHash` as a rustls [`Hash`] provider (draft §2.1).
//!
//! `TranscriptHash(x) = XOF("tls13 hash" || x, 64)` over the profile's
//! permutation (draft §2.1, §8.1, §9.1). rustls drives the handshake transcript
//! through the [`Hash`]/[`Context`] traits — incremental `update`, `fork`/clone
//! for checkpoints, one-shot `hash` — which map directly onto the deck sponge:
//! a `Context` is a sponge pre-seeded with `"tls13 hash"`, `update` absorbs
//! transcript bytes, and finishing squeezes 64 octets. The clone-before-squeeze
//! that `fork_finish` needs is exactly the deck's `Fork` discipline (draft §7.1,
//! §8.1.1), so no absorb-after-squeeze ever occurs.

use deck_schedule::sponge::{Sponge, DOMAIN_DECK, RATE};
use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};

/// A deck transcript-hash provider, parameterized by the profile's Keccak round
/// count (12 for TurboSHAKE256, 24 for SHAKE256).
pub struct DeckHash {
    rounds: usize,
}

/// TLS13-TURBOSHAKE256 transcript hash (12-round Keccak-p\[1600,12\]).
pub static TURBOSHAKE256_HASH: DeckHash = DeckHash { rounds: 12 };

/// TLS13-SHAKE256 transcript hash (24-round Keccak-f\[1600\]).
pub static SHAKE256_HASH: DeckHash = DeckHash { rounds: 24 };

impl DeckHash {
    /// A fresh sponge seeded with the `"tls13 hash"` prefix (draft §2.1). The
    /// prefix begins `0x74 0x6c`, which cannot collide with a keyed deck
    /// sequence's `uint16(len(profile_id))` prefix `0x00 …` (draft §15.7.3).
    fn seeded(&self) -> Sponge {
        let mut s = Sponge::new(RATE, DOMAIN_DECK, self.rounds);
        s.absorb(b"tls13 hash");
        s
    }
}

impl Hash for DeckHash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(DeckHashContext(self.seeded()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        let mut s = self.seeded();
        s.absorb(data);
        Output::new(&s.squeeze_vec(64))
    }

    fn output_len(&self) -> usize {
        64
    }

    fn algorithm(&self) -> HashAlgorithm {
        // The TLS HashAlgorithm registry has no SHAKE/TurboSHAKE code point. The
        // deck TranscriptHash is 64 octets, so we report SHA512 — a value no real
        // TLS 1.3 suite uses, so it never aliases one. This tag is only used by
        // rustls for resumption-hash matching; the schedule fork binds the
        // governing profile explicitly (draft §4), not through this tag.
        HashAlgorithm::SHA512
    }
}

/// An in-progress transcript hash: a sponge that has absorbed `"tls13 hash"`
/// followed by the transcript bytes seen so far.
struct DeckHashContext(Sponge);

impl Context for DeckHashContext {
    fn fork_finish(&self) -> Output {
        // Squeeze a clone so `self` can keep absorbing (draft §7.1.1): the deck
        // forbids absorb-after-squeeze, and only the clone is ever squeezed.
        let mut clone = self.0.clone();
        Output::new(&clone.squeeze_vec(64))
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(DeckHashContext(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        let mut s = self.0;
        Output::new(&s.squeeze_vec(64))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deck_schedule::profile::{SHAKE256, TURBOSHAKE256};
    use deck_schedule::transcript::transcript_hash;

    /// The one-shot provider hash equals the reference `transcript_hash` for both
    /// profiles (draft §2.1).
    #[test]
    fn oneshot_matches_reference() {
        for (h, p) in [
            (&TURBOSHAKE256_HASH, &TURBOSHAKE256),
            (&SHAKE256_HASH, &SHAKE256),
        ] {
            for x in [&b""[..], b"abc", &[0u8; 300]] {
                assert_eq!(h.hash(x).as_ref(), &transcript_hash(p, x)[..]);
            }
        }
    }

    /// Incremental hashing across arbitrary chunk boundaries equals one-shot, and
    /// `finish` equals `fork_finish` (draft §7.1.2 one-shot equivalence).
    #[test]
    fn incremental_matches_oneshot() {
        let h = &TURBOSHAKE256_HASH;
        let msg: Vec<u8> = (0..500u32).map(|i| i as u8).collect();

        let mut ctx = h.start();
        ctx.update(&msg[..7]);
        ctx.update(&msg[7..200]); // crosses the 136-octet rate boundary
        let forked = ctx.fork_finish();
        ctx.update(&msg[200..]);
        let finished = ctx.finish();

        assert_eq!(finished.as_ref(), h.hash(&msg).as_ref());
        assert_eq!(forked.as_ref(), h.hash(&msg[..200]).as_ref());
    }

    /// `fork` yields an independent context sharing the prefix: diverging updates
    /// after a fork produce independent hashes (the TLS checkpoint pattern).
    #[test]
    fn fork_is_independent() {
        let h = &SHAKE256_HASH;
        let mut base = h.start();
        base.update(b"common-prefix");

        let mut branch = base.fork();
        base.update(b"-A");
        branch.update(b"-B");

        assert_eq!(base.finish().as_ref(), h.hash(b"common-prefix-A").as_ref());
        assert_eq!(
            branch.finish().as_ref(),
            h.hash(b"common-prefix-B").as_ref()
        );
    }

    /// Pins the provider against a committed vector value (`th_abc`,
    /// TLS13-TURBOSHAKE256; see deck-schedule/vectors/turboshake256.json).
    #[test]
    fn matches_committed_vector() {
        let expected = "2786c44f877eb4af2d28944cd45cd45a9ba0d336139a449ddbcd4a8e1237e6bc\
                        c1325954ce7b008de2af54f0f0c320ff2026bff301174e456a33afe94da1f12c";
        let got: String = TURBOSHAKE256_HASH
            .hash(b"abc")
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(got, expected);
    }
}
