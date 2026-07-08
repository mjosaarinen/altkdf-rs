//! A fully FIPS-component key schedule (draft Appendix D, **informative**).
//!
//! Appendix D is non-normative and defines **no profile**: it has no code point,
//! no cipher suite, and no IANA registration (draft Appendix D). It records an
//! extract-and-expand schedule assembled entirely from FIPS-approved components,
//! for deployers who need that property before or instead of the deck schedule
//! of §7. This module is that schedule, kept in the crate purely as a comparison
//! artifact — the rustls fork never calls it.
//!
//! ## Construction (draft Appendix D)
//!
//! It is the RFC 8446 §7.1 extract-and-expand structure with its PRF replaced by
//! KMAC256 [SP800-185] throughout, and its Extract drawn from SP 800-56C:
//!
//! * **Extract** — an SP 800-56C two-step randomness-extraction step,
//!   `PRK = KMAC256(K = salt, X = IKM, L = 512, S = "")`, at each of the three
//!   stage transitions: `Early = Extract(0, PSK)`, `Handshake = Extract(derived,
//!   (EC)DHE)`, `Master = Extract(derived, 0)` (draft Appendix D).
//! * **Expand** — an SP 800-108 KBKDF **counter-mode** expansion with KMAC256 as
//!   the PRF, for every Derive-Secret / HKDF-Expand-Label site (draft Appendix D).
//! * **TranscriptHash** — an approved SHA-3-family function; this module uses
//!   `SHAKE256(·, 64)` (the variable-length, explicit-output option of draft
//!   Appendix D), keeping a 64-octet schedule that lines up with the deck's
//!   `SecretLen = FLen = 64`.
//!
//! ## Interpretation notes (this appendix is a sketch, not a vectored profile)
//!
//! Appendix D gives no test vectors and leaves the byte-level layout of the
//! SP 800-108 counter-mode input, and the mapping of the RFC 8446 `HkdfLabel`
//! onto SP 800-108's *Label*/*Context*, to the implementer. The choices here are
//! the natural, standards-faithful ones and are documented at each site:
//!
//! * **Expand-Label** builds the exact RFC 8446 §7.1 `HkdfLabel`
//!   (`uint16(len) || opaque("tls13 "+label)<7..255> || opaque(context)<0..255>`)
//!   and feeds it as the SP 800-108 *Label*, with an empty *Context* (the
//!   RFC 8446 context already lives inside `HkdfLabel`). This keeps the RFC 8446
//!   labelling verbatim — "structurally RFC 8446 §7.1 with its PRF replaced".
//! * **SP 800-108 counter mode** uses a 32-bit big-endian counter `i`, the
//!   fixed input `be32(i) || Label || 0x00 || Context || be32(L_bits)` (the
//!   `0x00` is SP 800-108's Label/Context separator), a 32-bit big-endian length
//!   field, and 512-bit KMAC256 blocks (`S = ""`).
//!
//! ## Deliberate differences from the deck schedule (§7.3)
//!
//! These are RFC-8446 properties the deck schedule intentionally does *not* have,
//! kept faithful here so the comparison is honest:
//!
//! * **No per-suite binding.** RFC 8446 derivations do not absorb the cipher
//!   suite; only the labels and transcript bind. (The deck binds the governing
//!   suite at every `Fork`.)
//! * **(EC)DHE is concatenated,** as TLS hybrid KEM groups define their shared
//!   secret — a single `IKM` into one Extract. (The deck absorbs each component
//!   under its own frame; see [`crate::schedule`].)
//! * **Record key and IV are two Expand-Label calls** (`"key"`, `"iv"`), not one
//!   split squeeze (draft §5.3 vs RFC 8446 §7.3).
//! * **Finished / PSK-binder MAC is KMAC256** over the finished key (HMAC
//!   replaced by KMAC256), not the deck `MAC` framing of §5.2.
//!
//! ## Validation caveat (draft Appendix D)
//!
//! The draft does not claim this composite is fully FIPS-validated or -validatable
//! today: KMAC256 is approved, SP 800-108 recognises KMAC as a PRF, but whether
//! KMAC256 is an approved SP 800-56C extraction function "is a point a validation
//! would have to establish, and this document does not assert it." Accordingly the
//! primitive anchored to a published KAT here is **KMAC256** (SP 800-185 Sample
//! #4, via [`crate::mac`]); the composite has no published end-to-end KAT, so it
//! is pinned only by these self-generated vectors and their independent
//! reproduction (`vectors/reproduce.py`).

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::mac::kmac256;
use crate::sponge::{Sponge, DOMAIN_DECK, RATE};
use crate::Secret;

/// Schedule secret / hash length, in octets (draft Appendix D: `L = 512` bits).
pub const HLEN: usize = 64;

/// `TranscriptHash` for the FIPS schedule: `SHAKE256(messages, 64)` (draft
/// Appendix D). This is the plain RFC 8446 Transcript-Hash with SHAKE256 as the
/// approved hash — note it has **no** `"tls13 hash"` prefix (that prefix is a
/// deck-schedule construction, [`crate::transcript`]).
pub fn transcript_hash(messages: &[u8]) -> Vec<u8> {
    let mut s = Sponge::new(RATE, DOMAIN_DECK, 24);
    s.absorb(messages);
    s.squeeze_vec(HLEN)
}

/// SP 800-56C two-step extraction with KMAC256 (draft Appendix D):
/// `Extract(salt, IKM) = KMAC256(K = salt, X = IKM, L = 512, S = "")`.
pub fn extract(salt: &[u8], ikm: &[u8]) -> Secret {
    Zeroizing::new(kmac256(salt, ikm, b"", HLEN))
}

/// SP 800-108 KBKDF counter-mode expansion with KMAC256 as the PRF (draft
/// Appendix D). Produces `l` octets from key `ki` and fixed input `info`:
///
/// ```text
/// for i = 1 .. ceil(8*l / 512):
///     K_i = KMAC256(K = ki, X = be32(i) || info || 0x00 || be32(8*l), L = 512, S = "")
/// return (K_1 || K_2 || ...)[..l]
/// ```
///
/// `info` plays SP 800-108's *Label*; the *Context* is empty (folded into
/// `info`), and the `0x00` is the standard Label/Context separator.
pub fn expand(ki: &[u8], info: &[u8], l: usize) -> Secret {
    // SP 800-108 encodes the output length L as a 32-bit big-endian field, so the
    // request must fit it. Check `l` *before* multiplying (a `8 * l` on an enormous
    // `l` could itself wrap in release). Enforced in release like the deck's framing
    // guards (`Deck::squeeze`): a silent `as u32` truncation would bind the wrong
    // length into every block and produce unrelated output.
    assert!(
        l <= u32::MAX as usize / 8,
        "SP 800-108 output length ({l} octets) exceeds the 32-bit L field"
    );
    let l_bits = (8 * l) as u32;
    let blocks = l.div_ceil(HLEN); // ceil(8l/512) = ceil(l/64)
    let mut out = Zeroizing::new(Vec::with_capacity(blocks * HLEN));
    for i in 1..=blocks as u32 {
        // SP 800-108 fixed input: be32(i) || Label || 0x00 || Context(empty) || be32(L).
        let mut x = Zeroizing::new(Vec::with_capacity(4 + info.len() + 1 + 4));
        x.extend_from_slice(&i.to_be_bytes());
        x.extend_from_slice(info);
        x.push(0x00);
        x.extend_from_slice(&l_bits.to_be_bytes());
        out.extend_from_slice(&kmac256(ki, &x, b"", HLEN));
    }
    out.truncate(l);
    out
}

/// The RFC 8446 §7.1 `HkdfLabel` structure (draft Appendix D keeps it verbatim):
/// `uint16(length) || opaque("tls13 " + label)<7..255> || opaque(context)<0..255>`.
fn hkdf_label(length: usize, label: &[u8], context: &[u8]) -> Vec<u8> {
    let full_label: Vec<u8> = [b"tls13 ", label].concat();
    // RFC 8446 §7.1: `uint16 length`, `opaque label<7..255>`, `opaque context<0..255>`.
    // Enforce all three bounds in release (like the deck's framing guards,
    // `Deck::squeeze`/`push_frame`): otherwise `length as u16` / `.len() as u8`
    // would silently truncate an out-of-range field into a malformed HkdfLabel.
    // TLS's fixed short labels never trip these; a caller-supplied exporter
    // `length`/`context` can, so the check is not merely a debug assertion.
    assert!(
        length <= 0xFFFF,
        "HkdfLabel length {length} exceeds uint16 (RFC 8446 §7.1)"
    );
    assert!(
        full_label.len() <= 255,
        "HkdfLabel label exceeds 255 octets (RFC 8446 §7.1)"
    );
    assert!(
        context.len() <= 255,
        "HkdfLabel context exceeds 255 octets (RFC 8446 §7.1)"
    );
    let mut out = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    out.extend_from_slice(&(length as u16).to_be_bytes());
    out.push(full_label.len() as u8);
    out.extend_from_slice(&full_label);
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out
}

/// `HKDF-Expand-Label(secret, label, context, length)` with the SP 800-108 /
/// KMAC256 Expand (draft Appendix D; RFC 8446 §7.1).
pub fn expand_label(secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Secret {
    expand(secret, &hkdf_label(length, label, context), length)
}

/// `Derive-Secret(secret, label, messages)` (RFC 8446 §7.1): Expand-Label over
/// the transcript hash of `messages`, at the full `HLEN` output length.
///
/// Callers that already hold `TranscriptHash(messages)` (the schedule threads the
/// `TH_*` checkpoints) should call [`expand_label`] directly with that value;
/// this helper hashes raw messages for the `"derived"` (empty-transcript) sites.
pub fn derive_secret(secret: &[u8], label: &[u8], messages: &[u8]) -> Secret {
    expand_label(secret, label, &transcript_hash(messages), HLEN)
}

/// Inputs to a full FIPS-component 1-RTT schedule (draft Appendix D). Mirrors
/// [`crate::schedule::ScheduleInputs`] but with **no** recorded/selected cipher
/// suite — the RFC 8446 structure binds no suite into its derivations — and with
/// the `(EC)DHE` shared secret passed already concatenated (`dhe`).
pub struct FipsInputs<'a> {
    /// PSK, or `None` for a full (non-PSK) handshake (RFC 8446: PSK = 0 then).
    pub psk: Option<&'a [u8]>,
    /// The concatenated `(EC)DHE` shared secret; empty for PSK-only.
    pub dhe: &'a [u8],
    /// `TranscriptHash(ClientHello)` — early-stage context.
    pub th_ch: &'a [u8],
    /// `TranscriptHash(...ServerHello)` — handshake-stage context.
    pub th_sh: &'a [u8],
    /// `TranscriptHash(...server Finished)` — application-stage context.
    pub th_sf: &'a [u8],
    /// `TranscriptHash(...client Finished)` — resumption context.
    pub th_cf: &'a [u8],
}

/// Every secret of the FIPS-component schedule (draft Appendix D / RFC 8446
/// §7.1). Field names match [`crate::schedule::ScheduleOutputs`] so the two
/// schedules can be compared secret-for-secret. Plain `Vec<u8>` (not [`Secret`])
/// for the same reason as `ScheduleOutputs`: this is a reference/vector path, not
/// live production key state.
pub struct FipsOutputs {
    pub early_secret: Vec<u8>,
    pub c_e_traffic: Option<Vec<u8>>,
    pub e_exp_master: Option<Vec<u8>>,
    pub handshake_secret: Vec<u8>,
    pub c_hs_traffic: Vec<u8>,
    pub s_hs_traffic: Vec<u8>,
    pub master_secret: Vec<u8>,
    pub c_ap_traffic: Vec<u8>,
    pub s_ap_traffic: Vec<u8>,
    pub exp_master: Vec<u8>,
    pub res_master: Vec<u8>,
}

/// Run the full FIPS-component schedule (draft Appendix D / RFC 8446 §7.1).
pub fn run(inp: &FipsInputs) -> FipsOutputs {
    let zero = [0u8; HLEN];
    let has_psk = inp.psk.is_some();

    // Early = Extract(0, PSK); absent PSK is a zero string of HLEN (RFC 8446).
    let early_secret = extract(&zero, inp.psk.unwrap_or(&zero));

    let (c_e_traffic, e_exp_master) = if has_psk {
        (
            Some(expand_label(&early_secret, b"c e traffic", inp.th_ch, HLEN).to_vec()),
            Some(expand_label(&early_secret, b"e exp master", inp.th_ch, HLEN).to_vec()),
        )
    } else {
        (None, None)
    };

    // Handshake = Extract(Derive-Secret(early, "derived", ""), (EC)DHE).
    let derived_early = derive_secret(&early_secret, b"derived", b"");
    let handshake_secret = extract(&derived_early, inp.dhe);
    let c_hs_traffic = expand_label(&handshake_secret, b"c hs traffic", inp.th_sh, HLEN);
    let s_hs_traffic = expand_label(&handshake_secret, b"s hs traffic", inp.th_sh, HLEN);

    // Master = Extract(Derive-Secret(handshake, "derived", ""), 0).
    let derived_hs = derive_secret(&handshake_secret, b"derived", b"");
    let master_secret = extract(&derived_hs, &zero);
    let c_ap_traffic = expand_label(&master_secret, b"c ap traffic", inp.th_sf, HLEN);
    let s_ap_traffic = expand_label(&master_secret, b"s ap traffic", inp.th_sf, HLEN);
    let exp_master = expand_label(&master_secret, b"exp master", inp.th_sf, HLEN);
    let res_master = expand_label(&master_secret, b"res master", inp.th_cf, HLEN);

    FipsOutputs {
        early_secret: early_secret.to_vec(),
        c_e_traffic,
        e_exp_master,
        handshake_secret: handshake_secret.to_vec(),
        c_hs_traffic: c_hs_traffic.to_vec(),
        s_hs_traffic: s_hs_traffic.to_vec(),
        master_secret: master_secret.to_vec(),
        c_ap_traffic: c_ap_traffic.to_vec(),
        s_ap_traffic: s_ap_traffic.to_vec(),
        exp_master: exp_master.to_vec(),
        res_master: res_master.to_vec(),
    }
}

// -- Leaf derivations (RFC 8446 §7.3 / §4.4.4 / §7.5, KMAC PRF) --------------

/// `finished_key = HKDF-Expand-Label(base, "finished", "", HLEN)` (RFC 8446 §4.4.4).
pub fn finished_key(base_key: &[u8]) -> Secret {
    expand_label(base_key, b"finished", b"", HLEN)
}

/// Finished `verify_data = KMAC256(finished_key, TranscriptHash, 512, "")` — the
/// RFC 8446 §4.4.4 `HMAC(finished_key, TH)` with HMAC replaced by KMAC256 (draft
/// Appendix D). `th` covers the transcript up to (not including) this Finished.
pub fn finished_verify_data(base_key: &[u8], th: &[u8]) -> Vec<u8> {
    let fk = finished_key(base_key);
    kmac256(&fk, th, b"", HLEN)
}

/// Record `write_key` / `write_iv` from a traffic secret, as **two** Expand-Label
/// calls (RFC 8446 §7.3): `"key"` (Nk octets) and `"iv"` (Nn octets).
pub fn record_keys(traffic_secret: &[u8], nk: usize, nn: usize) -> (Secret, Secret) {
    (
        expand_label(traffic_secret, b"key", b"", nk),
        expand_label(traffic_secret, b"iv", b"", nn),
    )
}

/// Next application traffic secret (RFC 8446 §7.2):
/// `HKDF-Expand-Label(secret, "traffic upd", "", HLEN)`.
pub fn key_update(app_traffic_secret_n: &[u8]) -> Secret {
    expand_label(app_traffic_secret_n, b"traffic upd", b"", HLEN)
}

/// `TLS-Exporter(label, context, length)` (RFC 8446 §7.5):
/// `HKDF-Expand-Label(Derive-Secret(exp_master, label, ""), "exporter",
/// TranscriptHash(context), length)`.
pub fn exporter(exp_master: &[u8], label: &[u8], context: &[u8], length: usize) -> Secret {
    let secret = derive_secret(exp_master, label, b"");
    expand_label(&secret, b"exporter", &transcript_hash(context), length)
}

/// Resumption PSK for a NewSessionTicket (RFC 8446 §4.6.1):
/// `HKDF-Expand-Label(res_master, "resumption", ticket_nonce, HLEN)`.
pub fn resumption_psk(res_master: &[u8], ticket_nonce: &[u8]) -> Secret {
    expand_label(res_master, b"resumption", ticket_nonce, HLEN)
}

/// Which PSK binder label applies (RFC 8446 §4.2.11.2): external vs resumption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinderKind {
    /// External PSK: `"ext binder"`.
    External,
    /// Resumption PSK: `"res binder"`.
    Resumption,
}

impl BinderKind {
    fn label(self) -> &'static [u8] {
        match self {
            BinderKind::External => b"ext binder",
            BinderKind::Resumption => b"res binder",
        }
    }
}

/// PSK binder `verify_data` (RFC 8446 §4.2.11.2) with the KMAC PRF:
/// `binder_key = Derive-Secret(early, "ext binder"|"res binder", "")`, then the
/// binder is the Finished MAC (KMAC256) over `th_ch0` keyed by that binder key's
/// finished key.
pub fn binder_verify_data(early_secret: &[u8], kind: BinderKind, th_ch0: &[u8]) -> Vec<u8> {
    let binder_key = derive_secret(early_secret, kind.label(), b"");
    finished_verify_data(&binder_key, th_ch0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `transcript_hash` is plain SHAKE256(·, 64): SHAKE256("") starts with the
    /// FIPS 202 value `46b9dd2b…` and carries **no** `"tls13 hash"` prefix (unlike
    /// [`crate::transcript::transcript_hash`]).
    #[test]
    fn transcript_hash_is_plain_shake256() {
        let th = transcript_hash(b"");
        assert_eq!(th.len(), 64);
        assert_eq!(
            &th[..32],
            &hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")[..]
        );
        // Different from the deck transcript hash, which prefixes "tls13 hash".
        assert_ne!(
            th,
            crate::transcript::transcript_hash(&crate::SHAKE256, b"")
        );
    }

    /// Extract is exactly KMAC256(salt, IKM, 512, "") — anchored transitively to
    /// SP 800-185 KMAC256 Sample #4 (`mac::tests::kmac256_sample4`). Pin it on that
    /// very sample's key/message so the Extract wiring can't silently drift.
    #[test]
    fn extract_is_kmac256_sample4() {
        // Sample #4 uses K = 40..5F, X = 00 01 02 03, S = "My Tagged Application".
        // Extract fixes S = "", so we can't reuse Sample #4's output byte-for-byte,
        // but we CAN pin that Extract equals the crate KMAC256 primitive (S = "")
        // on that same key/message — the Extract wiring then can't silently drift.
        let salt: Vec<u8> = (0x40u8..=0x5F).collect();
        let ikm = [0x00u8, 0x01, 0x02, 0x03];
        let got = extract(&salt, &ikm);
        assert_eq!(got.len(), 64);
        assert_eq!(&got[..], &crate::mac::kmac256(&salt, &ikm, b"", 64)[..]);
    }

    /// SP 800-108 counter-mode Expand: a single ≤64-octet request is one KMAC256
    /// block; a >64-octet request chains two blocks with counters 1 and 2 and the
    /// same `be32(L_bits)`. Pin the block structure explicitly.
    #[test]
    fn expand_counter_mode_block_structure() {
        let ki = [0xABu8; 32];
        let info = b"some info";

        // 64-octet output = one block, counter i=1, L=512.
        let one = expand(&ki, info, 64);
        let mut x1 = Vec::new();
        x1.extend_from_slice(&1u32.to_be_bytes());
        x1.extend_from_slice(info);
        x1.push(0x00);
        x1.extend_from_slice(&512u32.to_be_bytes());
        assert_eq!(&one[..], &kmac256(&ki, &x1, b"", 64)[..]);

        // 100-octet output = two blocks (i=1,2), L=800; truncate to 100.
        let two = expand(&ki, info, 100);
        assert_eq!(two.len(), 100);
        let mut a = Vec::new();
        for i in [1u32, 2] {
            let mut x = Vec::new();
            x.extend_from_slice(&i.to_be_bytes());
            x.extend_from_slice(info);
            x.push(0x00);
            x.extend_from_slice(&800u32.to_be_bytes());
            a.extend_from_slice(&kmac256(&ki, &x, b"", 64));
        }
        a.truncate(100);
        assert_eq!(&two[..], &a[..]);
        // The 100-octet output is NOT a prefix-extension of the 64-octet one:
        // the length field (512 vs 800) is bound into every block.
        assert_ne!(&two[..64], &one[..]);
    }

    /// The RFC 8446 §7.1 field bounds are release-enforced (not `debug_assert!`),
    /// so an out-of-range `length`/`label`/`context` — reachable through
    /// [`exporter`] — is rejected rather than silently truncated by an `as` cast.
    /// Four cases, each tripping a distinct bound.
    #[test]
    #[should_panic(expected = "exceeds uint16")]
    fn expand_label_rejects_length_over_u16() {
        // Reachable via `exporter(.., length)`; uint16(length) would wrap.
        let _ = expand_label(&[0u8; 64], b"x", b"", 0x1_0000);
    }

    #[test]
    #[should_panic(expected = "label exceeds 255")]
    fn hkdf_label_rejects_label_over_255() {
        // "tls13 " (6) + 250 = 256 > 255.
        let _ = expand_label(&[0u8; 64], &[b'a'; 250], b"", 64);
    }

    #[test]
    #[should_panic(expected = "context exceeds 255")]
    fn hkdf_label_rejects_context_over_255() {
        let _ = expand_label(&[0u8; 64], b"x", &[0u8; 256], 64);
    }

    #[test]
    #[should_panic(expected = "32-bit L field")]
    fn expand_rejects_l_bits_over_u32() {
        // 8 * l > u32::MAX. The assert trips before any allocation, so passing a
        // ~500M `l` here is cheap (no half-gigabyte buffer is ever reserved).
        let _ = expand(&[0u8; 64], b"x", u32::MAX as usize / 8 + 1);
    }

    /// Expand-Label wraps the exact RFC 8446 `HkdfLabel`; the "tls13 " prefix and
    /// the 1-byte length framings are present.
    #[test]
    fn hkdf_label_layout() {
        let l = hkdf_label(64, b"c hs traffic", b"");
        // uint16(64) = 00 40; len("tls13 c hs traffic") = 18 = 0x12; ctx len 0.
        assert_eq!(&l[..2], &[0x00, 0x40]);
        assert_eq!(l[2], 18);
        assert_eq!(&l[3..3 + 18], b"tls13 c hs traffic");
        assert_eq!(l[3 + 18], 0x00);
        assert_eq!(l.len(), 2 + 1 + 18 + 1);
    }

    /// The full schedule is deterministic and every secret is 64 octets; the
    /// no-PSK path carries no early leaves, a PSK path does.
    #[test]
    fn schedule_shape() {
        let no_psk = FipsInputs {
            psk: None,
            dhe: b"\x01\x02\x03\x04",
            th_ch: b"th_ch",
            th_sh: b"th_sh",
            th_sf: b"th_sf",
            th_cf: b"th_cf",
        };
        let a = run(&no_psk);
        let b = run(&no_psk);
        assert_eq!(a.master_secret, b.master_secret);
        assert_eq!(a.early_secret.len(), 64);
        assert_eq!(a.c_ap_traffic.len(), 64);
        assert!(a.c_e_traffic.is_none() && a.e_exp_master.is_none());

        let psk = [0x9au8; 64];
        let with_psk = FipsInputs {
            psk: Some(&psk),
            ..no_psk
        };
        let c = run(&with_psk);
        assert!(c.c_e_traffic.is_some() && c.e_exp_master.is_some());
        assert_ne!(a.early_secret, c.early_secret);
    }

    /// The FIPS schedule and the deck schedule (§7.3) are **different**
    /// constructions: on the same inputs they must not agree on any secret. This
    /// is the point of Appendix D — an approved-component alternative, not a
    /// re-encoding of the deck.
    #[test]
    fn fips_schedule_differs_from_deck() {
        use crate::schedule::{self, ScheduleInputs};

        let dhe: &[u8] = b"shared-secret-value!";
        let fips = run(&FipsInputs {
            psk: None,
            dhe,
            th_ch: b"th_ch",
            th_sh: b"th_sh",
            th_sf: b"th_sf",
            th_cf: b"th_cf",
        });

        let comps: [&[u8]; 1] = [dhe];
        let deck = schedule::run(
            &crate::SHAKE256,
            &ScheduleInputs {
                psk: None,
                dhe_components: &comps,
                recorded_suite: 0xFF04,
                selected_suite: 0xFF04,
                th_ch: b"th_ch",
                th_sh: b"th_sh",
                th_sf: b"th_sf",
                th_cf: b"th_cf",
            },
        );

        assert_ne!(fips.c_hs_traffic, deck.c_hs_traffic);
        assert_ne!(fips.c_ap_traffic, deck.c_ap_traffic);
        assert_ne!(fips.exp_master, deck.exp_master);
    }

    /// Record key/iv are two independent Expand-Label calls at the requested
    /// lengths (RFC 8446 §7.3) — not a single split block.
    #[test]
    fn record_keys_are_two_expand_labels() {
        let ts = [7u8; 64];
        let (k, iv) = record_keys(&ts, 16, 12);
        assert_eq!(k.len(), 16);
        assert_eq!(iv.len(), 12);
        assert_eq!(&k[..], &expand_label(&ts, b"key", b"", 16)[..]);
        assert_eq!(&iv[..], &expand_label(&ts, b"iv", b"", 12)[..]);
    }

    /// The binder MACs under the binder-derived finished key over `TH_CH0`, and
    /// external vs resumption binders differ (different binder label).
    #[test]
    fn binder_external_and_resumption_differ() {
        let early = [3u8; 64];
        let ext = binder_verify_data(&early, BinderKind::External, b"TH_CH0");
        let res = binder_verify_data(&early, BinderKind::Resumption, b"TH_CH0");
        assert_eq!(ext.len(), 64);
        assert_ne!(ext, res);
    }
}
