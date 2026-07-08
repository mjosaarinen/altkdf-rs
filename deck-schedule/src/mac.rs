//! `MAC(key, suite, label, message, L)` (draft §5.2).
//!
//! One keyed function for the PSK binder, both Finished values, and the ECH
//! acceptance confirmation. The layout is KMAC's: over the SHAKE256 profile's
//! 24-round permutation the result is byte-for-byte NIST KMAC256; over the
//! TurboSHAKE256 profile's 12-round permutation the draft names it
//! TurboKMAC256 (draft §5.2, §8.2, §9.2).
//!
//! `right_encode(8*L)` binds the output length into `mac_input` before the
//! permutation runs, so neither profile is `KMACXOF256` and outputs of
//! different lengths are unrelated (draft §5.2).

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::frame::{bytepad, encode_string, frame_into, right_encode, uint16};
use crate::profile::Profile;
use crate::sponge::{Sponge, DOMAIN_MAC, RATE};

/// Fixed customization string `S` (draft §5.2).
const CUSTOMIZATION: &[u8] = b"TLS 1.3 MAC";

/// `MAC(key, suite, label, message, L)` (draft §5.2).
pub fn mac(
    profile: &Profile,
    key: &[u8],
    suite: u16,
    label: &[u8],
    message: &[u8],
    l: usize,
) -> Vec<u8> {
    // X = frame(profile_id) || frame(uint16(suite)) || frame(label) || frame(message)
    let mut x = Vec::new();
    frame_into(&mut x, profile.profile_id);
    frame_into(&mut x, &uint16(suite));
    frame_into(&mut x, label);
    frame_into(&mut x, message);
    kmac(profile, key, &x, CUSTOMIZATION, l)
}

/// NIST `KMAC256(K, X, L, S)` (SP 800-185), with `L` in **octets**.
///
/// This is the deck `MAC`'s KMAC layout over the 24-round Keccak-f\[1600\]
/// permutation, which the draft states is byte-for-byte NIST KMAC256 (draft
/// §5.2, §9.2) — anchored by `mac::tests::kmac256_sample4`. Exposed crate-wide
/// for the FIPS-component schedule of draft Appendix D, which uses KMAC256 as
/// its PRF throughout (Extract and Expand); nothing on the deck path calls it.
pub(crate) fn kmac256(k: &[u8], x: &[u8], s: &[u8], l: usize) -> Vec<u8> {
    kmac(&crate::profile::SHAKE256, k, x, s, l)
}

/// The KMAC layout underlying `MAC` (draft §5.2), with function name `"KMAC"`,
/// key `k`, message `x`, customization string `s`, and output length `l`
/// octets, over the profile's permutation and MAC domain byte `0x04`.
///
/// Over the 24-round permutation this is exactly NIST KMAC256; `mac` fixes
/// `s = "TLS 1.3 MAC"` and builds `x` from the framed tuple.
fn kmac(profile: &Profile, k: &[u8], x: &[u8], s: &[u8], l: usize) -> Vec<u8> {
    // mac_input = bytepad(encode_string("KMAC") || encode_string(S), 136)
    //             || bytepad(encode_string(K), 136)
    //             || X || right_encode(8 * L)
    let mut name_and_s = encode_string(b"KMAC");
    name_and_s.extend_from_slice(&encode_string(s));
    let name_block = bytepad(&name_and_s, RATE);

    // The key blocks hold `k` (a MAC key). Zeroize them on drop, and assemble
    // `mac_input` with capacity reserved up front so the key is never left in a
    // reallocated buffer (draft §15.7.2.2; `encode_string`/`bytepad` reserve
    // exactly for the same reason).
    let key_block = Zeroizing::new(bytepad(&Zeroizing::new(encode_string(k)), RATE));
    let len_enc = right_encode(8 * l as u64);

    let total = name_block.len() + key_block.len() + x.len() + len_enc.len();
    let mut mac_input = Zeroizing::new(Vec::with_capacity(total));
    mac_input.extend_from_slice(&name_block);
    mac_input.extend_from_slice(&key_block);
    mac_input.extend_from_slice(x);
    mac_input.extend_from_slice(&len_enc);

    let mut sp = Sponge::new(RATE, DOMAIN_MAC, profile.rounds);
    sp.absorb(&mac_input);
    sp.squeeze_vec(l)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::SHAKE256;

    /// NIST KMAC256 Sample #4 (SP 800-185 example values, CSRC `KMAC_samples`).
    /// Over the 24-round permutation the draft's MAC layout *is* KMAC256
    /// (draft §5.2, §9.2), so this anchors the sponge + KMAC encoding to a NIST
    /// ground-truth vector. K = 40..5F, X = 00 01 02 03, S = "My Tagged
    /// Application", L = 512 bits.
    #[test]
    fn kmac256_sample4() {
        let k: Vec<u8> = (0x40u8..=0x5F).collect();
        let x = [0x00u8, 0x01, 0x02, 0x03];
        let out = kmac(&SHAKE256, &k, &x, b"My Tagged Application", 64);
        let expected = hex(concat!(
            "20c570c31346f703c9ac36c61c03cb64",
            "c3970d0cfc787e9b79599d273a68d2f7",
            "f69d4cc3de9d104a351689f27cf6f595",
            "1f0103f33f4f24871024d9c27773a8dd",
        ));
        assert_eq!(out, expected);
    }

    /// `mac` assembles the framed `X` and fixed `S` on top of `kmac`.
    #[test]
    fn mac_is_kmac_with_framed_x() {
        let key = [7u8; 64];
        let out = mac(&SHAKE256, &key, 0xFF04, b"finished", b"transcript", 64);
        let mut x = Vec::new();
        frame_into(&mut x, SHAKE256.profile_id);
        frame_into(&mut x, &uint16(0xFF04));
        frame_into(&mut x, b"finished");
        frame_into(&mut x, b"transcript");
        assert_eq!(out, kmac(&SHAKE256, &key, &x, CUSTOMIZATION, 64));
    }

    /// Length binding (draft §5.2): different `L` ⇒ unrelated output, not a prefix.
    #[test]
    fn length_binding() {
        let key = [3u8; 64];
        let a = mac(&SHAKE256, &key, 0xFF04, b"l", b"m", 32);
        let b = mac(&SHAKE256, &key, 0xFF04, b"l", b"m", 64);
        assert_ne!(a[..], b[..32]);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
