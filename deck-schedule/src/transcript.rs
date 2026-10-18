//! The unkeyed transcript hash (draft `[transcript-hash]`).
//!
//! `TranscriptHash(x)` is the 64-octet XOF output over `"tls13 hash" || x`. It
//! takes no cipher suite input, so a client can compute its checkpoints before
//! the ServerHello. The `"tls13 hash"` prefix (first octet 0x74) separates
//! transcript hashing from every keyed sequence (first octet 0x00) at the byte
//! level (draft `[domain-separation]`). DTLS 1.3 uses the same prefix.

use alloc::vec::Vec;

use crate::kdf::{Kdf, HASH_LEN};
use crate::sponge::{Sponge, DOMAIN_DECK, RATE};

/// Prefix absorbed before every transcript-hash input.
pub const PREFIX: &[u8] = b"tls13 hash";

/// An incremental transcript hasher. `Clone` gives a checkpoint: clone, then
/// finish the clone.
#[derive(Clone)]
pub struct TranscriptHasher {
    sponge: Sponge,
}

impl TranscriptHasher {
    /// Start a transcript under `kdf`.
    pub fn new(kdf: &Kdf) -> Self {
        let mut sponge = Sponge::new(RATE, DOMAIN_DECK, kdf.rounds);
        sponge.absorb(PREFIX);
        Self { sponge }
    }

    /// Append serialized handshake messages.
    pub fn update(&mut self, data: &[u8]) {
        self.sponge.absorb(data);
    }

    /// The 64-octet hash of everything absorbed so far, without consuming the
    /// running state.
    pub fn current(&self) -> Vec<u8> {
        self.sponge.clone().squeeze_vec(HASH_LEN)
    }

    /// Finish and return the 64-octet hash.
    pub fn finish(mut self) -> Vec<u8> {
        self.sponge.squeeze_vec(HASH_LEN)
    }
}

/// `TranscriptHash(x)`.
pub fn transcript_hash(kdf: &Kdf, x: &[u8]) -> Vec<u8> {
    let mut h = TranscriptHasher::new(kdf);
    h.update(x);
    h.finish()
}

/// The synthetic `message_hash` message that replaces the first ClientHello
/// after a HelloRetryRequest, with `TranscriptHash` for `Hash`:
/// `0xFE || uint24(64) || TranscriptHash(ClientHello1)`.
pub fn hrr_message_hash(kdf: &Kdf, client_hello1: &[u8]) -> Vec<u8> {
    let th1 = transcript_hash(kdf, client_hello1);
    let mut m = Vec::with_capacity(4 + th1.len());
    m.extend_from_slice(&[0xFE, 0x00, 0x00, HASH_LEN as u8]);
    m.extend_from_slice(&th1);
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{SHAKE256, TURBOSHAKE256};

    #[test]
    fn hrr_message_hash_layout() {
        let m = hrr_message_hash(&TURBOSHAKE256, b"CH1");
        assert_eq!(&m[..4], &[0xFE, 0x00, 0x00, 0x40]);
        assert_eq!(&m[4..], &transcript_hash(&TURBOSHAKE256, b"CH1")[..]);
    }

    #[test]
    fn incremental_equals_one_shot() {
        for k in [TURBOSHAKE256, SHAKE256] {
            let mut h = TranscriptHasher::new(&k);
            h.update(b"Client");
            let mid = h.current();
            h.update(b"Hello");
            assert_eq!(mid, transcript_hash(&k, b"Client"));
            assert_eq!(h.finish(), transcript_hash(&k, b"ClientHello"));
        }
    }

    /// The first octet separates transcript hashing from keyed sequences.
    #[test]
    fn prefix_separates_from_keyed_sequences() {
        assert_eq!(PREFIX[0], 0x74);
        assert_eq!(crate::frame::frame(b"tls13 ")[0], 0x00);
    }
}
