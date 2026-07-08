//! The unkeyed transcript hash (draft §2.1, §8.1, §9.1).
//!
//! `TranscriptHash(x)` is a 64-octet hash of `"tls13 hash" || x` under the
//! profile's XOF. It takes no cipher suite input, so a client can compute its
//! checkpoints before the ServerHello (draft §2.1). The `"tls13 hash"` prefix
//! separates transcript hashing from every keyed sequence at the byte level
//! (draft §15.7.3).

use alloc::vec::Vec;

use crate::profile::Profile;
use crate::sponge::{Sponge, DOMAIN_DECK, RATE};

/// `TranscriptHash(x)` = `XOF("tls13 hash" || x, 64)` (draft §2.1, §8.1, §9.1).
pub fn transcript_hash(profile: &Profile, x: &[u8]) -> Vec<u8> {
    let mut s = Sponge::new(RATE, DOMAIN_DECK, profile.rounds);
    s.absorb(b"tls13 hash");
    s.absorb(x);
    s.squeeze_vec(64)
}

/// The RFC 8446 §4.4.1 synthetic `message_hash` message that reinjects the first
/// ClientHello into the transcript after a HelloRetryRequest, with
/// `TranscriptHash` substituted for `Hash` (draft §2.1). It is
///
/// ```text
/// 0xFE || uint24(64) || TranscriptHash(client_hello1)
/// ```
///
/// where `0xFE` is `HandshakeType.message_hash` (RFC 8446 §4.4.1) and `64` is
/// the fixed `TranscriptHash` length of both profiles (§8, §9). Used to build
/// `TH_CH0` and the running transcript after an HRR.
pub fn hrr_message_hash(profile: &Profile, client_hello1: &[u8]) -> Vec<u8> {
    let th1 = transcript_hash(profile, client_hello1);
    debug_assert_eq!(th1.len(), 64);
    let mut m = Vec::with_capacity(4 + th1.len());
    m.push(0xFE); // HandshakeType.message_hash
    m.extend_from_slice(&[0x00, 0x00, th1.len() as u8]); // uint24 length = 0x000040
    m.extend_from_slice(&th1);
    m
}

/// `TranscriptHash` of a transcript in which a HelloRetryRequest intervened
/// (draft §2.1, RFC 8446 §4.4.1): the first ClientHello is replaced by the
/// synthetic `message_hash` of [`hrr_message_hash`], followed by the remaining
/// serialized transcript (`HelloRetryRequest`, `ClientHello2`, …). `rest` is the
/// already-serialized concatenation of those messages.
pub fn transcript_hash_after_hrr(profile: &Profile, client_hello1: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut t = hrr_message_hash(profile, client_hello1);
    t.extend_from_slice(rest);
    transcript_hash(profile, &t)
}

/// The checkpoint values of draft §2.1. Held together for the schedule and the
/// test-vector harness. Each is a `TranscriptHash` over the relevant message
/// range; the caller supplies the already-serialized transcript bytes.
#[derive(Clone, Debug, Default)]
pub struct Checkpoints {
    /// `TH_CH0`: partial ClientHello truncated before the binders (draft §2.1).
    pub th_ch0: Vec<u8>,
    /// `TH_CH`: `TranscriptHash(ClientHello)`.
    pub th_ch: Vec<u8>,
    /// `TH_SH`: through ServerHello.
    pub th_sh: Vec<u8>,
    /// `TH_SF`: through the server Finished.
    pub th_sf: Vec<u8>,
    /// `TH_CF`: through the client Finished.
    pub th_cf: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{frame_into, uint16};
    use crate::profile::{SHAKE256, TURBOSHAKE256};

    /// The synthetic message is `0xFE || 00 00 40 || TranscriptHash(CH1)`
    /// (RFC 8446 §4.4.1, draft §2.1): type `message_hash`, uint24 length 64.
    #[test]
    fn hrr_message_hash_layout() {
        let ch1 = b"ClientHello1 bytes";
        let m = hrr_message_hash(&TURBOSHAKE256, ch1);
        assert_eq!(m.len(), 4 + 64);
        assert_eq!(&m[..4], &[0xFE, 0x00, 0x00, 0x40]);
        assert_eq!(&m[4..], &transcript_hash(&TURBOSHAKE256, ch1)[..]);
    }

    /// The post-HRR transcript hash is `TranscriptHash(message_hash || rest)`.
    #[test]
    fn hrr_transcript_is_hash_of_synthetic_plus_rest() {
        let ch1 = b"first ClientHello";
        let rest = b"HelloRetryRequest||ClientHello2";
        let mut manual = hrr_message_hash(&TURBOSHAKE256, ch1);
        manual.extend_from_slice(rest);
        assert_eq!(
            transcript_hash_after_hrr(&TURBOSHAKE256, ch1, rest),
            transcript_hash(&TURBOSHAKE256, &manual)
        );
        // Reinjection is not the same as hashing CH1 inline: the synthetic
        // construction binds Hash(CH1), not CH1 itself.
        let mut inline = ch1.to_vec();
        inline.extend_from_slice(rest);
        assert_ne!(
            transcript_hash_after_hrr(&TURBOSHAKE256, ch1, rest),
            transcript_hash(&TURBOSHAKE256, &inline)
        );
    }

    /// Draft §15.7.3: a `TranscriptHash` input begins with the octets of
    /// "tls13 hash" (0x74 0x6c …), whereas every keyed deck sequence begins with
    /// `uint16(len(profile_id))` — `0x00 0x17` for the 23-octet TurboSHAKE256
    /// id, `0x00 0x18` for the 24-octet SHAKE256 id. The leading octet alone
    /// (0x74 vs 0x00) separates unkeyed transcript hashing from every keyed
    /// derivation at the byte level, under one shared 0x1F domain.
    #[test]
    fn transcript_prefix_separates_from_keyed_sequences() {
        assert_eq!(&b"tls13 hash"[..2], &[0x74, 0x6c]);
        assert_eq!(uint16(TURBOSHAKE256.profile_id.len() as u16), [0x00, 0x17]);
        assert_eq!(uint16(SHAKE256.profile_id.len() as u16), [0x00, 0x18]);
        for p in [&TURBOSHAKE256, &SHAKE256] {
            let mut keyed_prefix = Vec::new();
            frame_into(&mut keyed_prefix, p.profile_id);
            assert_ne!(keyed_prefix[0], b"tls13 hash"[0]);
        }
    }
}
