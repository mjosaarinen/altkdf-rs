//! The deck interface: `Init / Absorb / Derive / DeriveN / Ratchet` (draft
//! `[deck-interface]`).
//!
//! A [`Deck`] holds the framed input sequence `seq(S)` of the deck function
//! `DF(S, L)`. The presentation is stateful but the construction is not: every
//! `Derive` or `DeriveN` is one `DF` call over the framed sequence, so this
//! implementation keeps the sequence itself and evaluates `DF` from scratch at
//! each output (the "recompute from path" realization). `derive` and `derive_n`
//! take `&self`, which is the draft's clone: the deck is unchanged and yields
//! all of a stage's leaves. `ratchet` consumes the deck, so a retired deck can
//! neither be absorbed into nor derived from.
//!
//! The context tag is fixed by the kind of deck (draft `[deck-interface]`): a live
//! stage trunk (E, H, T) frames its context under `"th__"`, a deck seeded from a
//! retained secret under `"ctx_"`.

use alloc::vec::Vec;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::frame::{uint16, MAX_FRAME};
use crate::kdf::{Kdf, Protocol};
use crate::labels::{self, Label, Tag};
use crate::{Error, Secret};

/// A running deck: the framed input sequence plus the KDF that evaluates it.
#[derive(Clone)]
pub struct Deck {
    kdf: Kdf,
    proto: Protocol,
    ctag: &'static Tag,
    seq: Vec<u8>,
}

/// The sequence holds every absorbed secret (PSK, seeds, shared-secret
/// components) in the clear, and every clone copies it, so it is zeroized on
/// drop (draft `[erasure-boundaries]`).
impl Drop for Deck {
    fn drop(&mut self) {
        self.seq.zeroize();
    }
}

impl ZeroizeOnDrop for Deck {}

impl Deck {
    /// Capacity a deck sequence typically fits in, so the common case never
    /// grows (and never has to wipe-and-copy below).
    const INITIAL_CAP: usize = 320;

    /// `Init([seed])`: `frame(schedule_label) [|| frame("seed") || frame(seed)]`.
    fn init(kdf: Kdf, proto: Protocol, seed: Option<&[u8]>, ctag: &'static Tag) -> Self {
        let mut d = Deck {
            kdf,
            proto,
            ctag,
            seq: Vec::with_capacity(Self::INITIAL_CAP),
        };
        d.push_frame(proto.schedule_label());
        if let Some(seed) = seed {
            d.push_frame(labels::SEED);
            d.push_frame(seed);
        }
        d
    }

    /// The early-stage trunk `E = Init()` (draft `[key-schedule]`).
    pub fn early(kdf: Kdf, proto: Protocol) -> Self {
        Self::init(kdf, proto, None, labels::TH)
    }

    /// A later stage trunk `Init(residue)`: H after a PSK binder DeriveN, or the
    /// result of a [`Deck::ratchet`] (draft `[key-schedule]`).
    pub fn stage(kdf: Kdf, proto: Protocol, residue: &[u8]) -> Self {
        Self::init(kdf, proto, Some(residue), labels::TH)
    }

    /// A deck seeded from a retained secret, `Init(secret)` (draft `[expand-op]`).
    pub fn keyed(kdf: Kdf, proto: Protocol, secret: &[u8]) -> Self {
        Self::init(kdf, proto, Some(secret), labels::CTX)
    }

    /// The KDF evaluating this deck.
    pub fn kdf(&self) -> Kdf {
        self.kdf
    }

    /// The protocol whose `schedule_label` this deck framed at `Init`.
    pub fn protocol(&self) -> Protocol {
        self.proto
    }

    /// Append raw bytes. If the append would reallocate, grow by hand and wipe
    /// the old (secret-bearing) allocation before it is freed: `Vec`'s own
    /// reallocation would leave PSK or shared-secret bytes in freed heap.
    fn push_bytes(&mut self, bytes: &[u8]) {
        let needed = self.seq.len() + bytes.len();
        if needed > self.seq.capacity() {
            let new_cap = needed.max(self.seq.capacity().saturating_mul(2));
            let mut grown = Vec::with_capacity(new_cap);
            grown.extend_from_slice(&self.seq);
            self.seq.zeroize();
            self.seq = grown;
        }
        self.seq.extend_from_slice(bytes);
    }

    fn push_frame(&mut self, x: &[u8]) {
        assert!(x.len() <= MAX_FRAME, "framed value exceeds 0xFFFF octets");
        self.push_bytes(&uint16(x.len() as u16));
        self.push_bytes(x);
    }

    /// `Absorb(D, tag, v)`: append `frame(tag) || frame(v)`.
    ///
    /// Panics if `v` exceeds 65535 octets; callers bound their inputs first
    /// (see [`crate::schedule::EarlyStage::new`]).
    pub fn absorb(&mut self, tag: &Tag, v: &[u8]) -> &mut Self {
        self.push_frame(tag);
        self.push_frame(v);
        self
    }

    /// Clone the deck and append the optional context. An empty context is
    /// omitted, which is its canonical encoding (draft `[expand-op]`).
    fn with_context(&self, context: Option<&[u8]>) -> Result<Deck, Error> {
        let mut s = self.clone();
        if let Some(c) = context.filter(|c| !c.is_empty()) {
            if c.len() > MAX_FRAME {
                return Err(Error::FrameTooLong);
            }
            s.push_frame(self.ctag);
            s.push_frame(c);
        }
        Ok(s)
    }

    /// `Derive(D, label, [context], L)`: one `DF` call over
    /// `D [|| frame(ctag) || frame(context)] || frame(label) || frame("out_")
    /// || frame(uint16(L))`. `L` must be 1..=65535 (TurboSHAKE256 has no
    /// zero-length output).
    pub fn derive(&self, label: &Label, context: Option<&[u8]>, l: usize) -> Result<Secret, Error> {
        if l == 0 || l > MAX_FRAME {
            return Err(Error::OutputLength);
        }
        let mut s = self.with_context(context)?;
        s.push_frame(label);
        s.push_frame(labels::OUT);
        s.push_frame(&uint16(l as u16));
        Ok(Zeroizing::new(self.kdf.df(&s.seq, l)))
    }

    /// `DeriveN(D, [(label_1, L_1), ..., (label_k, L_k)], [context])`: bind the
    /// count, the ordered labels and each length, squeeze once, and split the
    /// output in order (draft `[deck-interface]`).
    ///
    /// Rejects `k` outside 2..=65535, any `L_i` outside 1..=65535, a sum above
    /// 65535, unregistered labels, and repeated labels.
    pub fn derive_n(
        &self,
        descs: &[(&Label, usize)],
        context: Option<&[u8]>,
    ) -> Result<Vec<Secret>, Error> {
        let k = descs.len();
        if !(2..=MAX_FRAME).contains(&k) {
            return Err(Error::DeriveNCount);
        }
        let mut total: usize = 0;
        for (i, (label, l)) in descs.iter().enumerate() {
            if *l == 0 || *l > MAX_FRAME {
                return Err(Error::OutputLength);
            }
            total += *l; // k and each L_i are bounded, so no overflow
            if !labels::is_registered(label) {
                return Err(Error::UnregisteredLabel);
            }
            if descs[..i].iter().any(|(m, _)| m == label) {
                return Err(Error::DuplicateLabel);
            }
        }
        if total > MAX_FRAME {
            return Err(Error::OutputLength);
        }

        let mut s = self.with_context(context)?;
        s.push_frame(labels::OUTS);
        s.push_frame(&uint16(k as u16));
        for (label, l) in descs {
            s.push_frame(*label);
            s.push_frame(labels::OUT);
            s.push_frame(&uint16(*l as u16));
        }
        let out = Zeroizing::new(self.kdf.df(&s.seq, total));
        let mut slices = Vec::with_capacity(k);
        let mut off = 0;
        for (_, l) in descs {
            slices.push(Zeroizing::new(out[off..off + l].to_vec()));
            off += l;
        }
        Ok(slices)
    }

    /// `Ratchet(D)`: `residue = Derive(D, "drv")`, return `Init(residue)` as the
    /// next stage trunk. Consumes (retires) the old deck; the residue never
    /// leaves this function.
    pub fn ratchet(self) -> Deck {
        let residue = self
            .derive(labels::DRV, None, self.kdf.secret_len)
            .expect("SecretLen is a valid output length");
        Deck::stage(self.kdf, self.proto, &residue)
    }

    /// The framed sequence accumulated so far. Test-only: production code never
    /// inspects, serializes, or compares an accumulator (draft
    /// `[erasure-boundaries]`).
    #[doc(hidden)]
    pub fn seq_for_test(&self) -> &[u8] {
        &self.seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::frame;
    use crate::kdf::{SHAKE256, TURBOSHAKE256};
    use alloc::vec;

    const P: Protocol = Protocol::Tls13;

    #[test]
    fn init_frames_schedule_label() {
        let d = Deck::early(TURBOSHAKE256, P);
        assert_eq!(d.seq_for_test(), &hex("0006746c73313320")[..]);
        let d = Deck::early(TURBOSHAKE256, Protocol::Dtls13);
        assert_eq!(d.seq_for_test(), &hex("000664746c733133")[..]);
    }

    /// The MAC input layout of draft `[mac-op]`: 167 octets, key at 16, message
    /// at 88.
    #[test]
    fn mac_layout_offsets() {
        let key = [0x11u8; 64];
        let msg = [0x22u8; 64];
        let d = Deck::keyed(SHAKE256, P, &key);
        let mut s = d.with_context(Some(&msg)).unwrap();
        s.push_frame(labels::MAC);
        s.push_frame(labels::OUT);
        s.push_frame(&uint16(64));
        let seq = s.seq_for_test();
        assert_eq!(seq.len(), 167);
        assert_eq!(&seq[16..80], &key);
        assert_eq!(&seq[80..86], b"\x00\x04ctx_");
        assert_eq!(&seq[88..152], &msg);
        assert_eq!(&seq[152..157], b"\x00\x03mac");
    }

    /// The DeriveN layout of draft `[labels]` for (cet, ees) over E with a PSK:
    /// 192 octets.
    #[test]
    fn derive_n_layout() {
        let mut e = Deck::early(TURBOSHAKE256, P);
        e.absorb(labels::PSK, &[0u8; 64]);
        let mut s = e.with_context(Some(&[1u8; 64])).unwrap();
        s.push_frame(labels::OUTS);
        s.push_frame(&uint16(2));
        for l in [labels::CET, labels::EES] {
            s.push_frame(l);
            s.push_frame(labels::OUT);
            s.push_frame(&uint16(64));
        }
        let seq = s.seq_for_test();
        assert_eq!(seq.len(), 192);
        assert_eq!(&seq[80..86], b"\x00\x04th__");
        assert_eq!(&seq[152..162], b"\x00\x04outs\x00\x02\x00\x02");
        assert_eq!(&seq[162..167], b"\x00\x03cet");
    }

    /// An empty context is omitted: Derive with `Some("")` equals Derive with
    /// `None` (draft `[expand-op]`).
    #[test]
    fn empty_context_is_omitted() {
        let d = Deck::keyed(TURBOSHAKE256, P, &[7u8; 64]);
        assert_eq!(
            *d.derive(labels::RSP, Some(b""), 64).unwrap(),
            *d.derive(labels::RSP, None, 64).unwrap()
        );
        assert_ne!(
            *d.derive(labels::RSP, Some(b"n"), 64).unwrap(),
            *d.derive(labels::RSP, None, 64).unwrap()
        );
    }

    /// A DeriveN output is not the concatenation of single Derives, and its
    /// slices depend on the whole descriptor list (draft `[deck-interface]`).
    #[test]
    fn derive_n_binds_partition() {
        let d = Deck::keyed(TURBOSHAKE256, P, &[7u8; 64]);
        let a = d
            .derive_n(&[(labels::FIN, 64), (labels::KEY, 28)], None)
            .unwrap();
        let b = d
            .derive_n(&[(labels::FIN, 64), (labels::KEY, 44)], None)
            .unwrap();
        assert_ne!(*a[0], *b[0], "Nk + Nn changes the finished_key slice");
        assert_ne!(*a[0], *d.derive(labels::FIN, None, 64).unwrap());
        assert_eq!(a[1].len(), 28);
    }

    #[test]
    fn derive_n_rejects_bad_descriptors() {
        let d = Deck::keyed(TURBOSHAKE256, P, &[7u8; 64]);
        assert_eq!(
            d.derive_n(&[(labels::FIN, 64)], None).err(),
            Some(Error::DeriveNCount)
        );
        assert_eq!(
            d.derive_n(&[(labels::FIN, 64), (labels::FIN, 28)], None)
                .err(),
            Some(Error::DuplicateLabel)
        );
        assert_eq!(
            d.derive_n(&[(labels::FIN, 0), (labels::KEY, 28)], None)
                .err(),
            Some(Error::OutputLength)
        );
        assert_eq!(
            d.derive_n(&[(labels::FIN, 40000), (labels::KEY, 30000)], None)
                .err(),
            Some(Error::OutputLength)
        );
        assert_eq!(
            d.derive_n(&[(b"zzz", 64), (labels::KEY, 28)], None).err(),
            Some(Error::UnregisteredLabel)
        );
    }

    #[test]
    fn derive_rejects_zero_and_oversize() {
        let d = Deck::keyed(TURBOSHAKE256, P, &[7u8; 64]);
        assert_eq!(
            d.derive(labels::EXP, None, 0).err(),
            Some(Error::OutputLength)
        );
        assert_eq!(
            d.derive(labels::EXP, None, 65536).err(),
            Some(Error::OutputLength)
        );
        assert!(d.derive(labels::EXP, None, 65535).is_ok());
    }

    /// Absent differs from empty: framing an empty PSK changes the sequence.
    #[test]
    fn absent_input_differs_from_empty_input() {
        let mut with_empty = Deck::early(TURBOSHAKE256, P);
        with_empty.absorb(labels::PSK, b"");
        let without = Deck::early(TURBOSHAKE256, P);
        assert_ne!(with_empty.seq_for_test(), without.seq_for_test());
    }

    /// A large absorbed value grows the accumulator through the wipe-and-grow
    /// path without corrupting the framed sequence.
    #[test]
    fn secure_growth_preserves_framed_sequence() {
        let big = vec![0xABu8; 1000];
        let mut d = Deck::early(TURBOSHAKE256, P);
        d.absorb(labels::PSK, &big);
        let mut expected = frame(b"tls13 ");
        expected.extend_from_slice(&frame(b"psk_"));
        expected.extend_from_slice(&frame(&big));
        assert_eq!(d.seq_for_test(), &expected[..]);
    }

    /// Stage and retained-secret decks seeded with the same bytes produce the
    /// same prefix but different context tags.
    #[test]
    fn context_tag_follows_deck_kind() {
        let s = [3u8; 64];
        let th = [4u8; 64];
        let a = Deck::stage(TURBOSHAKE256, P, &s)
            .with_context(Some(&th))
            .unwrap();
        let b = Deck::keyed(TURBOSHAKE256, P, &s)
            .with_context(Some(&th))
            .unwrap();
        assert_eq!(&a.seq_for_test()[..80], &b.seq_for_test()[..80]);
        assert_eq!(&a.seq_for_test()[82..86], b"th__");
        assert_eq!(&b.seq_for_test()[82..86], b"ctx_");
    }

    fn hex(s: &str) -> Vec<u8> {
        crate::hex::decode(s)
    }
}
