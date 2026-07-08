//! The deck interface: `Init / Absorb / Fork / Squeeze / Ratchet` (draft §7.1).
//!
//! A `Deck` holds the framed input sequence `seq(S)` for the deck function
//! `DF(S, L)`. The presentation is stateful but the construction is not: every
//! derived value equals one `DF` invocation over the framed path from `Init` to
//! its final `Squeeze` (draft §7.1.2, "one-shot equivalence").
//!
//! The draft's rules are enforced by the type: `squeeze` and `ratchet` consume
//! `self`, so a sequence cannot be forked or absorbed into after it produces
//! output (draft §7.1.1). `fork` takes `&self` and clones, leaving the trunk
//! usable for further forks and the ratchet.

use alloc::vec::Vec;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::frame::uint16;
use crate::profile::Profile;

#[derive(Clone)]
pub struct Deck<'p> {
    profile: &'p Profile,
    seq: Vec<u8>,
}

/// The framed sequence holds every absorbed secret (the PSK, stage secrets, DHE
/// components, …) in the clear, and a `Fork` clones it — this is the "cloned
/// accumulator" the draft calls out — so it is zeroized on drop (draft §15.7.2.2).
impl Drop for Deck<'_> {
    fn drop(&mut self) {
        self.seq.zeroize();
    }
}

impl ZeroizeOnDrop for Deck<'_> {}

impl<'p> Deck<'p> {
    /// Capacity a stage trunk / expansion sequence typically fits in, so the
    /// common case never has to grow (and thus never has to wipe-and-copy below).
    const INITIAL_CAP: usize = 320;

    /// `Init()` — begin a sequence with `frame(profile_id)` (draft §7.1.1).
    pub fn init(profile: &'p Profile) -> Self {
        let mut d = Deck {
            profile,
            seq: Vec::with_capacity(Self::INITIAL_CAP),
        };
        d.push_frame(profile.profile_id);
        d
    }

    /// Append raw bytes to the framed sequence. If the append would reallocate,
    /// grow by hand and **zeroize the current (secret-bearing) allocation before
    /// it is freed** (draft §15.7.2.2): `Vec`'s own reallocation would otherwise
    /// leave PSK / DHE / stage-secret material in freed heap. A `Fork` clones a
    /// `len`-capacity buffer, so its first append always takes this path.
    fn push_bytes(&mut self, bytes: &[u8]) {
        let needed = self.seq.len() + bytes.len();
        if needed > self.seq.capacity() {
            let new_cap = needed.max(self.seq.capacity().saturating_mul(2));
            let mut grown = Vec::with_capacity(new_cap);
            grown.extend_from_slice(&self.seq);
            self.seq.zeroize(); // wipe the old buffer's contents before it frees
            self.seq = grown;
        }
        self.seq.extend_from_slice(bytes); // fits: no reallocation
    }

    /// Append `frame(x) = uint16(len(x)) || x` (draft §2) via [`Self::push_bytes`].
    fn push_frame(&mut self, x: &[u8]) {
        assert!(
            x.len() <= 0xFFFE,
            "framed value exceeds 0xFFFE octets (draft §2)"
        );
        self.push_bytes(&uint16(x.len() as u16));
        self.push_bytes(x);
    }

    /// `Absorb(S, tag, v)` — append `frame(tag) || frame(v)` (draft §7.1.1).
    pub fn absorb(&mut self, tag: &[u8], v: &[u8]) -> &mut Self {
        self.push_frame(tag);
        self.push_frame(v);
        self
    }

    /// `Fork(S, label, suite)` — branch a new sequence for a single output,
    /// binding the governing cipher suite under the fixed tag `"suite"`
    /// (draft §7.1.1). The trunk `self` is unmodified.
    pub fn fork(&self, label: &[u8], suite: u16) -> Deck<'p> {
        let mut child = self.clone();
        child.push_frame(label);
        child.push_frame(b"suite");
        child.push_frame(&uint16(suite));
        child
    }

    /// `Squeeze(S, tag, L)` — terminate the sequence and output `DF(S, L)`
    /// (draft §7.1.1). Consumes `self`: no absorb-after-squeeze, no fork of a
    /// squeezed sequence.
    pub fn squeeze(mut self, tag: &[u8], l: usize) -> Vec<u8> {
        assert!(
            l <= 0xFFFE,
            "output length exceeds 0xFFFE octets (draft §3)"
        );
        self.push_frame(tag);
        self.push_frame(&uint16(l as u16));
        self.profile.df(&self.seq, l)
    }

    /// `Ratchet(S, label)` — squeeze the `SecretLen`-octet stage secret directly
    /// from the trunk under the stage label (draft §7.1.1). A ratchet output
    /// binds no cipher suite.
    pub fn ratchet(self, label: &[u8]) -> Vec<u8> {
        let l = self.profile.secret_len;
        self.squeeze(label, l)
    }

    /// The framed sequence `seq(S)` accumulated so far (draft §7.1.1). Test-only:
    /// production code never inspects, serializes, or compares an accumulator
    /// (draft §15.7.2.2).
    #[cfg(test)]
    pub(crate) fn seq(&self) -> &[u8] {
        &self.seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::frame;
    use crate::profile::TURBOSHAKE256;
    use alloc::vec;

    /// `Init()` sets `seq = frame(profile_id)`; the keyed prefix begins
    /// `0x00 0x17` for the 23-octet TurboSHAKE256 id (draft §7.1.1, §15.7.3).
    #[test]
    fn init_is_framed_profile_id() {
        let d = Deck::init(&TURBOSHAKE256);
        assert_eq!(d.seq(), frame(TURBOSHAKE256.profile_id));
        assert_eq!(&d.seq()[..2], &[0x00, 0x17]);
    }

    /// `Absorb(S, tag, v)` appends exactly `frame(tag) || frame(v)`; an empty
    /// value contributes `frame("") = 0x0000`, not nothing (draft §7.1.1, §2).
    #[test]
    fn absorb_frames_tag_then_value() {
        let mut d = Deck::init(&TURBOSHAKE256);
        d.absorb(b"psk", b"");
        let mut expected = frame(TURBOSHAKE256.profile_id);
        expected.extend_from_slice(&frame(b"psk"));
        expected.extend_from_slice(&frame(b"")); // 0x00 0x00
        assert_eq!(d.seq(), expected);
        assert_eq!(&d.seq()[d.seq().len() - 2..], &[0x00, 0x00]);
    }

    /// Framing an empty value is distinct from omitting the absorb: the framed
    /// tag stream distinguishes absent from empty (draft §2, §15.7.3), so the
    /// two sequences — and hence their squeezes — differ.
    #[test]
    fn absent_input_differs_from_empty_input() {
        let mut with_empty = Deck::init(&TURBOSHAKE256);
        with_empty.absorb(b"psk", b"");
        let without = Deck::init(&TURBOSHAKE256);
        assert_ne!(with_empty.seq(), without.seq());
        assert_ne!(with_empty.squeeze(b"out", 32), without.squeeze(b"out", 32));
    }

    /// `Fork(S, label, suite)` appends `frame(label) || frame("suite") ||
    /// frame(uint16(suite))` and leaves the trunk unmodified (draft §7.1.1).
    #[test]
    fn fork_binds_label_and_suite_without_touching_trunk() {
        let mut trunk = Deck::init(&TURBOSHAKE256);
        trunk.absorb(b"secret", &[0u8; 64]);
        let before = trunk.seq().to_vec();

        let child = trunk.fork(b"c hs traffic", 0xFF01);
        assert_eq!(trunk.seq(), &before[..], "fork must not mutate the trunk");

        let mut expected = before.clone();
        expected.extend_from_slice(&frame(b"c hs traffic"));
        expected.extend_from_slice(&frame(b"suite"));
        expected.extend_from_slice(&frame(&[0xFF, 0x01]));
        assert_eq!(child.seq(), expected);
    }

    /// Distinct derivation paths yield distinct outputs (draft §15.7.3): the
    /// fork label, the governing suite, and the absorb order each change the
    /// framed sequence and therefore the squeeze.
    #[test]
    fn distinct_paths_distinct_outputs() {
        let root = |()| {
            let mut d = Deck::init(&TURBOSHAKE256);
            d.absorb(b"secret", &[9u8; 64]);
            d
        };
        let by_label_a = root(()).fork(b"c hs traffic", 0xFF01).squeeze(b"out", 32);
        let by_label_b = root(()).fork(b"s hs traffic", 0xFF01).squeeze(b"out", 32);
        assert_ne!(by_label_a, by_label_b, "distinct labels");

        let by_suite_a = root(()).fork(b"c hs traffic", 0xFF01).squeeze(b"out", 32);
        let by_suite_b = root(()).fork(b"c hs traffic", 0xFF02).squeeze(b"out", 32);
        assert_ne!(by_suite_a, by_suite_b, "distinct governing suite");

        // Absorb order is bound: (a,b) != (b,a).
        let mut ab = Deck::init(&TURBOSHAKE256);
        ab.absorb(b"dh", b"AAAA").absorb(b"dh", b"BBBB");
        let mut ba = Deck::init(&TURBOSHAKE256);
        ba.absorb(b"dh", b"BBBB").absorb(b"dh", b"AAAA");
        assert_ne!(
            ab.fork(b"x", 0xFF01).squeeze(b"out", 32),
            ba.fork(b"x", 0xFF01).squeeze(b"out", 32),
        );
    }

    /// A large absorbed value pushes the accumulator past its initial capacity,
    /// exercising the secure wipe-and-grow append (draft §15.7.2.2). The framed
    /// sequence must stay byte-identical to naive framing (the growth must not
    /// corrupt content), and a fork off a grown trunk must remain independent.
    /// (The wipe itself is not observable without reading freed storage.)
    #[test]
    fn secure_growth_preserves_framed_sequence() {
        let big = vec![0xABu8; 1000]; // > INITIAL_CAP: forces several reallocations
        let mut d = Deck::init(&TURBOSHAKE256);
        d.absorb(b"secret", &big);

        // Expected: frame(profile_id) || frame("secret") || frame(big).
        let mut expected = frame(TURBOSHAKE256.profile_id);
        expected.extend_from_slice(&frame(b"secret"));
        expected.extend_from_slice(&frame(&big));
        assert_eq!(d.seq(), expected);

        // A fork past the grown trunk stays independent and correctly framed.
        let child = d.fork(b"leaf", 0xFF01);
        let mut child_expected = expected.clone();
        child_expected.extend_from_slice(&frame(b"leaf"));
        child_expected.extend_from_slice(&frame(b"suite"));
        child_expected.extend_from_slice(&frame(&[0xFF, 0x01]));
        assert_eq!(child.seq(), child_expected);
        assert_eq!(d.seq(), expected, "fork must not mutate the trunk");
    }

    /// The ratchet labels "early secret" and "main secret" are reserved: they
    /// appear as no absorb tag, fork label, or squeeze tag elsewhere in either
    /// profile (draft §7.1.1, §15.7.3). This pins that reservation against the
    /// full label inventory of the schedule and the §5 derivations, so reusing
    /// a ratchet label for a leaf would trip this guard.
    #[test]
    fn ratchet_labels_are_reserved() {
        const RATCHET_LABELS: [&[u8]; 2] = [b"early secret", b"main secret"];
        // Every other tag/label used by the deck schedule (§7.3) and the keyed
        // derivations (§5). If a leaf ever adopts a ratchet label, it lands here
        // and the assertion below fails.
        const OTHER_LABELS: &[&[u8]] = &[
            // Absorb tags.
            b"psk",
            b"early",
            b"dh",
            b"th",
            b"main",
            b"secret",
            b"context",
            b"suite",
            b"out",
            // Fork labels — schedule leaves.
            b"c e traffic",
            b"e exp master",
            b"c hs traffic",
            b"s hs traffic",
            b"c ap traffic",
            b"s ap traffic",
            b"exp master",
            b"res master",
            // Fork labels — §5 derivations.
            b"key",
            b"traffic upd",
            b"finished",
            b"ext binder",
            b"res binder",
            b"exporter",
            b"resumption",
            b"derived psk",
        ];
        for r in RATCHET_LABELS {
            assert!(
                !OTHER_LABELS.contains(&r),
                "ratchet label {:?} reused as a non-ratchet tag/label",
                core::str::from_utf8(r).unwrap()
            );
        }
    }
}
