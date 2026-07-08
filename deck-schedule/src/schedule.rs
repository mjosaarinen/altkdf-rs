//! The three-stage deck key schedule: E, H, T (draft §7.3).
//!
//! Stages are separated by two ratchets (`early secret`, `main secret`); each
//! key-update generation adds a further ratchet (draft §5.4, §7.3). Stage
//! trunks and stage secrets bind no cipher suite (draft §7.3): the governing
//! suite is bound at each leaf `Fork`. `suite` below is the *governing* cipher
//! suite of the leaf — the offered PSK's recorded suite in the early stage,
//! `selected_cipher_suite` thereafter (draft §7.3, §4).
//!
//! This listing is identical for both profiles; only `DF` differs (draft §7.3).

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::deck::Deck;
use crate::profile::Profile;
use crate::Secret;

/// A pre-shared key of this document: exactly 64 octets — an imported or
/// resumption PSK (draft §7.3.1, line 1186). No-PSK is encoded as `None`.
///
/// Enforcing the length by construction means neither the empty/no-PSK
/// ambiguity nor an out-of-spec short PSK can key the early stage: `Some` is
/// always a well-formed 64-octet PSK.
#[derive(Clone, Copy, Debug)]
pub struct Psk<'a>(&'a [u8]);

impl<'a> Psk<'a> {
    /// The fixed PSK length of this document, in octets (draft §7.3.1).
    pub const LEN: usize = 64;

    /// Wrap a `Psk::LEN`-octet PSK; `None` for any other length, including empty
    /// (which is the no-PSK encoding, draft §7.3.1).
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() == Self::LEN {
            Some(Psk(bytes))
        } else {
            None
        }
    }

    /// The PSK octets (always `Psk::LEN`).
    pub fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

/// Inputs to a full 1-RTT schedule trace.
pub struct ScheduleInputs<'a> {
    /// `None` runs the no-PSK path `Absorb(E, "psk", "")` (draft §7.3.1);
    /// `Some` is always a real, non-empty PSK.
    pub psk: Option<Psk<'a>>,
    /// (EC)DHE shared secret, by component in group order; empty for PSK-only,
    /// which omits `Absorb(H, "dh", …)` entirely (draft §7.3, §7.3.1).
    pub dhe_components: &'a [&'a [u8]],
    /// Recorded cipher suite governing early-stage leaves (draft §4).
    pub recorded_suite: u16,
    /// `selected_cipher_suite` governing handshake/application leaves (draft §4).
    pub selected_suite: u16,
    /// `TH_CH` (draft §2.1) — early-stage branch context.
    pub th_ch: &'a [u8],
    /// `TH_SH` (draft §2.1) — handshake-stage branch context.
    pub th_sh: &'a [u8],
    /// `TH_SF` (draft §2.1) — application-stage branch context.
    pub th_sf: &'a [u8],
    /// `TH_CF` (draft §2.1) — resumption branch context.
    pub th_cf: &'a [u8],
}

/// Every secret produced by the schedule (draft §7.3). Early-stage leaves are
/// present only when a PSK is offered (0-RTT); the ratchet stage secrets are
/// always produced.
///
/// Fields are plain `Vec<u8>`, **not** [`Secret`], by design: [`run`] is a
/// reference implementation for vector generation and cross-checking, not the
/// production key schedule (the rustls fork drives the deck operations directly
/// and keeps its live secrets in zeroizing wrappers). Vector generation needs
/// stable bytes here, and these values are not retained live secret state.
pub struct ScheduleOutputs {
    pub early_secret: Vec<u8>,
    pub c_e_traffic: Option<Vec<u8>>,
    pub e_exp_master: Option<Vec<u8>>,
    pub main_secret: Vec<u8>,
    pub c_hs_traffic: Vec<u8>,
    pub s_hs_traffic: Vec<u8>,
    pub c_ap_traffic: Vec<u8>,
    pub s_ap_traffic: Vec<u8>,
    pub exp_master: Vec<u8>,
    pub res_master: Vec<u8>,
}

/// The early-stage secret keyed by `psk` (draft §7.3): `Ratchet(Init();
/// Absorb(E, "psk", psk), "early secret")`. This is the value the PSK binder is
/// keyed on (draft §5.5) and the seed of the handshake stage; a resumption or
/// imported PSK is 64 octets. (For a no-PSK handshake, pass the empty slice —
/// the deterministic public constant of §7.3.1.)
pub fn early_secret(profile: &Profile, psk: &[u8]) -> Secret {
    let mut e = Deck::init(profile);
    e.absorb(b"psk", psk);
    Zeroizing::new(e.ratchet(b"early secret"))
}

/// Run the full schedule of draft §7.3.
///
/// UNVALIDATED against the draft's own vectors (which require assigned code
/// points, draft §14); the interop test of PLAN.md Stage 4 is the end-to-end
/// check that both peers derive identical secrets.
pub fn run(profile: &Profile, inp: &ScheduleInputs) -> ScheduleOutputs {
    let sl = profile.secret_len;
    let has_psk = inp.psk.is_some();

    // -- Early stage E (draft §7.3) ---------------------------------------
    let mut e = Deck::init(profile);
    // Root absorb; no-PSK contributes frame("psk") || frame("") (draft §7.3.1).
    // `Psk` is non-empty by construction, so `Some` is always a real PSK.
    e.absorb(b"psk", inp.psk.map(Psk::as_bytes).unwrap_or(b""));

    // Early-stage leaves (0-RTT only), governing suite = recorded (draft §7.3).
    let (c_e_traffic, e_exp_master) = if has_psk {
        let mut f1 = e.fork(b"c e traffic", inp.recorded_suite);
        f1.absorb(b"th", inp.th_ch);
        let c_e = f1.squeeze(b"out", sl);

        let mut f2 = e.fork(b"e exp master", inp.recorded_suite);
        f2.absorb(b"th", inp.th_ch);
        let e_exp = f2.squeeze(b"out", sl);

        (Some(c_e), Some(e_exp))
    } else {
        (None, None)
    };

    // Ratchet: E is terminally squeezed; destroy early-stage accumulators.
    let early_secret = e.ratchet(b"early secret");

    // -- Handshake stage H (draft §7.3) -----------------------------------
    let mut h = Deck::init(profile);
    h.absorb(b"early", &early_secret);
    for comp in inp.dhe_components {
        // Once per component, in group order; never concatenated (draft §7.3).
        h.absorb(b"dh", comp);
    }
    h.absorb(b"th", inp.th_sh);

    let c_hs_traffic = h
        .fork(b"c hs traffic", inp.selected_suite)
        .squeeze(b"out", sl);
    let s_hs_traffic = h
        .fork(b"s hs traffic", inp.selected_suite)
        .squeeze(b"out", sl);

    let main_secret = h.ratchet(b"main secret");

    // -- Application stage T (draft §7.3) ---------------------------------
    let mut t = Deck::init(profile);
    t.absorb(b"main", &main_secret);
    t.absorb(b"th", inp.th_sf);

    let c_ap_traffic = t
        .fork(b"c ap traffic", inp.selected_suite)
        .squeeze(b"out", sl);
    let s_ap_traffic = t
        .fork(b"s ap traffic", inp.selected_suite)
        .squeeze(b"out", sl);
    let exp_master = t
        .fork(b"exp master", inp.selected_suite)
        .squeeze(b"out", sl);

    t.absorb(b"th", inp.th_cf);
    let res_master = t
        .fork(b"res master", inp.selected_suite)
        .squeeze(b"out", sl);
    // destroy T

    ScheduleOutputs {
        early_secret,
        c_e_traffic,
        e_exp_master,
        main_secret,
        c_hs_traffic,
        s_hs_traffic,
        c_ap_traffic,
        s_ap_traffic,
        exp_master,
        res_master,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{SHAKE256, TURBOSHAKE256};

    fn sample<'a>() -> ScheduleInputs<'a> {
        ScheduleInputs {
            psk: None,
            dhe_components: &[b"\x01\x02\x03\x04"],
            recorded_suite: 0xFF01,
            selected_suite: 0xFF01,
            th_ch: b"th_ch",
            th_sh: b"th_sh",
            th_sf: b"th_sf",
            th_cf: b"th_cf",
        }
    }

    /// One-shot equivalence: recomputing the schedule yields identical octets
    /// (draft §7.1.2). This is a determinism smoke test, not a KAT.
    #[test]
    fn deterministic() {
        let a = run(&TURBOSHAKE256, &sample());
        let b = run(&TURBOSHAKE256, &sample());
        assert_eq!(a.main_secret, b.main_secret);
        assert_eq!(a.c_ap_traffic, b.c_ap_traffic);
        assert_eq!(a.main_secret.len(), 64);
    }

    /// The two profiles must differ (different permutation + profile_id).
    #[test]
    fn profiles_differ() {
        let a = run(&TURBOSHAKE256, &sample());
        let b = run(&SHAKE256, &sample());
        assert_ne!(a.c_ap_traffic, b.c_ap_traffic);
    }

    /// No-PSK path carries no early leaves (draft §7.3.1).
    #[test]
    fn no_psk_has_no_early_leaves() {
        let out = run(&TURBOSHAKE256, &sample());
        assert!(out.c_e_traffic.is_none());
        assert!(out.e_exp_master.is_none());
    }

    /// A PSK of this document is exactly 64 octets; empty (no-PSK), too-short,
    /// and too-long slices are all rejected by construction (draft §7.3.1).
    #[test]
    fn psk_length_is_enforced() {
        assert!(Psk::new(b"").is_none()); // no-PSK is the only empty encoding
        assert!(Psk::new(&[0u8; 1]).is_none());
        assert!(Psk::new(&[0u8; 63]).is_none());
        assert!(Psk::new(&[0u8; 64]).is_some());
        assert!(Psk::new(&[0u8; 65]).is_none());
    }

    /// A real (non-empty) PSK produces early-stage leaves (0-RTT, draft §7.3).
    #[test]
    fn real_psk_enables_early_leaves() {
        let psk = [0x9au8; 64];
        let mut inp = sample();
        inp.psk = Some(Psk::new(&psk).unwrap());
        let out = run(&TURBOSHAKE256, &inp);
        assert!(out.c_e_traffic.is_some());
        assert!(out.e_exp_master.is_some());
    }

    /// Hybrid (EC)DHE: each component is absorbed under its own `Absorb(H,"dh",·)`
    /// in group order and never concatenated, so swapping the component order
    /// changes the handshake-stage sequence and every secret past it (draft §7.3,
    /// "Both peers MUST absorb in that order"). Two components in opposite order
    /// must diverge, and neither may equal the single-secret concatenation.
    #[test]
    fn hybrid_dh_component_order_is_bound() {
        let a: &[u8] = b"componentAAAAAAA";
        let b: &[u8] = b"componentBBBBBBB";

        let ab_comps: [&[u8]; 2] = [a, b];
        let mut ab = sample();
        ab.dhe_components = &ab_comps;
        let out_ab = run(&TURBOSHAKE256, &ab);

        let ba_comps: [&[u8]; 2] = [b, a];
        let mut ba = sample();
        ba.dhe_components = &ba_comps;
        let out_ba = run(&TURBOSHAKE256, &ba);

        assert_ne!(out_ab.c_hs_traffic, out_ba.c_hs_traffic, "order is bound");
        assert_ne!(out_ab.main_secret, out_ba.main_secret);

        // Two components are not the same as one concatenated secret: the middle
        // frame("dh") tag stream distinguishes them (draft §2, §7.3).
        let concat = [a, b].concat();
        let concat_slice: &[u8] = &concat;
        let mut single = sample();
        single.dhe_components = core::slice::from_ref(&concat_slice);
        assert_ne!(
            out_ab.c_hs_traffic,
            run(&TURBOSHAKE256, &single).c_hs_traffic,
            "components are never concatenated first"
        );
    }
}
