//! The Keccak sponge shared by both profiles (draft §8.1, §9.1).
//!
//! A single sponge with a 136-octet rate and a 512-bit capacity, parameterized
//! by round count (12 or 24) and the domain-separation byte. This is the one
//! primitive the whole schedule is built on: `DF(S, L)` uses domain `0x1F`
//! (draft §8.1/§9.1), and `MAC` uses domain `0x04` (draft §5.2).
//!
//! Cloning an *unfinalized* state realizes the deck `Fork` (draft §7.1, §8.1.1);
//! `#[derive(Clone)]` gives that. Absorbing after a squeeze is forbidden by the
//! draft and rejected here with a hard `assert!` (enforced in release too).

use alloc::{vec, vec::Vec};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keccak::keccak_p;

/// Sponge rate in octets (draft §5.2, §8.1, §9.1).
pub const RATE: usize = 136;

/// Domain byte for deck / transcript output: `DF` and `TranscriptHash` (draft §8.1, §9.1).
pub const DOMAIN_DECK: u8 = 0x1F;

/// Domain byte for the MAC (draft §5.2).
pub const DOMAIN_MAC: u8 = 0x04;

#[derive(Clone)]
pub struct Sponge {
    state: [u8; 200],
    rate: usize,
    domain: u8,
    rounds: usize,
    pos: usize,
    squeezing: bool,
}

impl Sponge {
    /// New sponge with the given `rate` (octets), `domain` byte, and permutation
    /// `rounds` (12 for TurboSHAKE256, 24 for SHAKE256).
    pub fn new(rate: usize, domain: u8, rounds: usize) -> Self {
        debug_assert!(rate > 0 && rate < 200);
        Self {
            state: [0u8; 200],
            rate,
            domain,
            rounds,
            pos: 0,
            squeezing: false,
        }
    }

    /// Absorb `data`. MUST NOT be called after squeezing has begun (draft §7.1.1).
    /// This is a hard invariant (`assert!`, enforced in release too): `Sponge`
    /// is a public primitive, so the illegal transition must never be reachable.
    pub fn absorb(&mut self, data: &[u8]) {
        assert!(!self.squeezing, "absorb after squeeze (draft §7.1.1)");
        for &b in data {
            self.state[self.pos] ^= b;
            self.pos += 1;
            if self.pos == self.rate {
                self.permute();
                self.pos = 0;
            }
        }
    }

    /// Squeeze `out.len()` octets, applying the pad on first call.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            // pad: append domain byte, then pad10*1 (final rate octet gets 0x80).
            self.state[self.pos] ^= self.domain;
            self.state[self.rate - 1] ^= 0x80;
            self.permute();
            self.pos = 0;
            self.squeezing = true;
        }
        for b in out.iter_mut() {
            if self.pos == self.rate {
                self.permute();
                self.pos = 0;
            }
            *b = self.state[self.pos];
            self.pos += 1;
        }
    }

    /// Squeeze `n` octets into a fresh `Vec`.
    pub fn squeeze_vec(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.squeeze(&mut v);
        v
    }

    fn permute(&mut self) {
        let mut lanes = [0u64; 25];
        let mut buf = [0u8; 8];
        for (i, lane) in lanes.iter_mut().enumerate() {
            buf.copy_from_slice(&self.state[8 * i..8 * i + 8]);
            *lane = u64::from_le_bytes(buf);
        }
        keccak_p(&mut lanes, self.rounds);
        for (i, lane) in lanes.iter().enumerate() {
            self.state[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
        }
        // The lane copy and the byte scratch both transiently hold secret
        // capacity; erase them before they leave the stack frame (draft §15.7.2.2).
        lanes.zeroize();
        buf.zeroize();
    }
}

/// The 200-octet state holds the withheld capacity — the secret the erasure
/// argument of draft §15.7.2.2 relies on — so it is zeroized on drop.
impl Drop for Sponge {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

impl ZeroizeOnDrop for Sponge {}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHAKE256("") — validates keccak-f\[1600\] (24 rounds) + sponge padding.
    /// KAT from FIPS 202 / the eXtended Keccak Code Package.
    #[test]
    fn shake256_empty_kat() {
        let mut s = Sponge::new(RATE, DOMAIN_DECK, 24);
        s.absorb(b"");
        let out = s.squeeze_vec(32);
        let expected = hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
        assert_eq!(out, expected);
    }

    /// TurboSHAKE256(M="", D=0x1F, 64) — validates keccak-p\[1600,12\].
    /// KAT from RFC 9861 Appendix A.3.
    #[test]
    fn turboshake256_empty_kat() {
        let mut s = Sponge::new(RATE, DOMAIN_DECK, 12);
        s.absorb(b"");
        let out = s.squeeze_vec(64);
        let expected = hex(concat!(
            "367a329dafea871c7802ec67f905ae13",
            "c57695dc2c6663c61035f59a18f8e7db",
            "11edc0e12e91ea60eb6b32df06dd7f00",
            "2fbafabb6e13ec1cc20d995547600db0",
        ));
        assert_eq!(out, expected);
    }

    /// `ptn(n)`: the RFC 9861 pattern `00 01 02 .. F9 FA` (251 octets) repeated
    /// and truncated to `n` octets, i.e. `ptn[i] = i mod 251` (RFC 9861 §A).
    fn ptn(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// TurboSHAKE256(M=ptn(17^k), D=0x1F, 64) for k = 2, 3 — multi-block absorb
    /// KATs from RFC 9861 §A.3. `17^2 = 289` octets crosses the 136-octet rate
    /// boundary (three absorbed blocks); `17^3 = 4913` crosses it 36 times.
    /// These pin the 12-round absorb loop, which the empty-input KAT above and
    /// the sub-rate outputs elsewhere never exercise across a permutation.
    #[test]
    fn turboshake256_multiblock_kat() {
        let mut s = Sponge::new(RATE, DOMAIN_DECK, 12);
        s.absorb(&ptn(289)); // 17^2
        assert_eq!(
            s.squeeze_vec(64),
            hex(concat!(
                "66b810db8e90780424c0847372fdc957",
                "10882fde31c6df75beb9d4cd9305cfca",
                "e35e7b83e8b7e6eb4b78605880116316",
                "fe2c078a09b94ad7b8213c0a738b65c0",
            ))
        );

        let mut s = Sponge::new(RATE, DOMAIN_DECK, 12);
        s.absorb(&ptn(4913)); // 17^3
        assert_eq!(
            s.squeeze_vec(64),
            hex(concat!(
                "c74ebc919a5b3b0dd1228185ba02d29e",
                "f442d69d3d4276a93efe0bf9a16a7dc0",
                "cd4eabadab8cd7a5edd96695f5d360ab",
                "e09e2c6511a3ec397da3b76b9e1674fb",
            ))
        );
    }

    /// TurboSHAKE256(M="", D=0x1F, 10032), last 32 octets — long-output KAT from
    /// RFC 9861 §A.3. Squeezing 10032 octets applies the permutation ~74 times
    /// during output, pinning the 12-round squeeze loop (every other test reads
    /// a single output block).
    #[test]
    fn turboshake256_long_output_kat() {
        let mut s = Sponge::new(RATE, DOMAIN_DECK, 12);
        s.absorb(b"");
        let out = s.squeeze_vec(10032);
        let expected = hex(concat!(
            "abefa11630c661269249742685ec082f",
            "207265dccf2f43534e9c61ba0c9d1d75",
        ));
        assert_eq!(&out[out.len() - 32..], &expected[..]);
    }

    /// SHAKE256(ptn(289), 512 bits) — multi-block absorb for the 24-round path.
    /// SHAKE256 has no per-length domain quirks, so no NIST vector at this exact
    /// length is published; the expected value is cross-checked against Python's
    /// `hashlib.shake_256` (a wholly independent Keccak-f\[1600\]).
    #[test]
    fn shake256_multiblock_kat() {
        let mut s = Sponge::new(RATE, DOMAIN_DECK, 24);
        s.absorb(&ptn(289));
        assert_eq!(
            s.squeeze_vec(64),
            hex(concat!(
                "36fd526858bed2ed9fd2d78359797a14",
                "dd0449e13bfe1224b4de70de0ed9db7a",
                "3525d628bcbd8535af34754fee2b4f7b",
                "1e0d8ebfe5640be681832eed416a216e",
            ))
        );
    }

    /// SHAKE256("", 10032 octets), last 32 octets — long-output for the 24-round
    /// squeeze loop, cross-checked against Python's `hashlib.shake_256`.
    #[test]
    fn shake256_long_output_kat() {
        let mut s = Sponge::new(RATE, DOMAIN_DECK, 24);
        s.absorb(b"");
        let out = s.squeeze_vec(10032);
        let expected = hex(concat!(
            "9f61d36cc42fbc919e6c09bf92262171",
            "8f9fe82e825790073653bca1bbb9baa9",
        ));
        assert_eq!(&out[out.len() - 32..], &expected[..]);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
