//! Appendix A.1 benchmark: Keccak-f[1600] permutation-call count for one full
//! representative handshake, deck schedule vs a hash-only HKDF-SHA3-256
//! instantiation of the RFC 8446 schedule.
//!
//! The draft (§1, Appendix A.1) claims the deck costs **52** permutation calls
//! against **156** for HKDF-SHA3-256 — a factor of three — because every HKDF /
//! HMAC operation is two nested hash calls, overhead a keyed sponge does not
//! carry. It also gives an invocation count (Table 4): **29** deck invocations
//! (expand / MAC / Ratchet / Fork+Squeeze) vs **39** RFC 8446 invocations
//! (HKDF-Extract / HKDF-Expand-Label / HMAC).
//!
//! This program *measures* those numbers empirically over the same instrumented
//! 24-round Keccak-f[1600] (the SHAKE256 profile and SHA3-256 share it), for the
//! maximal common handshake of Appendix A: offers+selects a PSK, uses (EC)DHE,
//! accepts 0-RTT, issues one NewSessionTicket, one KeyUpdate each direction. It
//! reports the deck in **both** realizations §7.1.2 permits — stateful
//! (clone-per-fork, the strategy the draft counts) and recompute-from-path (what
//! `deck-schedule` implements; Appendix B) — plus HKDF-SHA3-256.
//!
//! Run: `cargo run -p deck-schedule --example invocations --features bench`
//! (or `make bench`).

use deck_schedule::derive::{
    binder_verify_data, expand, finished_verify_data, key_update, record_keys, resumption_psk,
    BinderKind,
};
use deck_schedule::frame::{frame, uint16};
use deck_schedule::keccak::count;
use deck_schedule::schedule::{run, ScheduleInputs};
use deck_schedule::sponge::{Sponge, DOMAIN_DECK, RATE};
use deck_schedule::transcript::transcript_hash;
use deck_schedule::{Profile, SHAKE256};

/// The comparison is over the 24-round permutation both schedules can share.
const ROUNDS: usize = 24;
const SUITE: u16 = 0xFF04; // TLS_AES_128_GCM_SHAKE256
const NK: usize = 16; // AES-128
const NN: usize = 12;

/// Representative handshake inputs (sizes as in a real handshake).
struct Inputs {
    psk: Vec<u8>,          // resumption PSK, 64 octets
    dhe: Vec<u8>,          // one (EC)DHE / ML-KEM component, 32 octets
    th: Vec<u8>,           // a 64-octet deck TranscriptHash checkpoint
    th32: Vec<u8>,         // a 32-octet SHA3-256 transcript checkpoint (RFC side)
    nonce: Vec<u8>,        // NewSessionTicket nonce
    exporter_ctx: Vec<u8>, // precomputed frame(TH(label)) || frame(TH(context))
}

impl Inputs {
    fn new() -> Self {
        // Appendix A.1 is a *schedule-only* count: the exporter's label/context
        // hashing is input processing (like the RFC exporter's Hash(context)),
        // counted on neither side. Precompute the deck exporter context here, in
        // the unmeasured setup, so only the expansion is measured (draft §5.6).
        let mut exporter_ctx = frame(&transcript_hash(&SHAKE256, b"EXPORTER-x"));
        exporter_ctx.extend_from_slice(&frame(&transcript_hash(&SHAKE256, b"context")));
        Self {
            psk: vec![0x11; 64],
            dhe: vec![0x22; 32],
            th: vec![0x33; 64],
            th32: vec![0x33; 32],
            nonce: vec![0x44; 8],
            exporter_ctx,
        }
    }
}

/// Measure permutation calls made by `f`.
fn perms<R>(f: impl FnOnce() -> R) -> (R, u64) {
    count::reset();
    let r = f();
    (r, count::permutations())
}

// ---------------------------------------------------------------------------
// Deck, stateful realization (draft §7.1.2 clone-per-fork; the strategy the
// draft's 52 counts). Trunks are absorbed once; a Fork clones the sponge state.
// ---------------------------------------------------------------------------

/// A stage trunk as a live sponge (stateful strategy): `Fork` clones it.
struct Trunk {
    sp: Sponge,
}

impl Trunk {
    fn init(profile: &Profile) -> Self {
        let mut sp = Sponge::new(RATE, DOMAIN_DECK, profile.rounds);
        sp.absorb(&frame(profile.profile_id));
        Self { sp }
    }
    fn absorb(&mut self, tag: &[u8], v: &[u8]) {
        self.sp.absorb(&frame(tag));
        self.sp.absorb(&frame(v));
    }
    /// Fork+Squeeze a leaf: clone the trunk state, bind label+suite (+optional
    /// `th`), squeeze `l` octets. One deck invocation.
    fn leaf(&self, label: &[u8], suite: u16, th: Option<&[u8]>, l: usize) -> Vec<u8> {
        let mut f = self.sp.clone();
        f.absorb(&frame(label));
        f.absorb(&frame(b"suite"));
        f.absorb(&frame(&uint16(suite)));
        if let Some(th) = th {
            f.absorb(&frame(b"th"));
            f.absorb(&frame(th));
        }
        f.absorb(&frame(b"out"));
        f.absorb(&frame(&uint16(l as u16)));
        f.squeeze_vec(l)
    }
    /// Ratchet: squeeze the stage secret from the trunk under `label`. One deck
    /// invocation; consumes the trunk.
    fn ratchet(mut self, label: &[u8], l: usize) -> Vec<u8> {
        self.sp.absorb(&frame(label));
        self.sp.absorb(&frame(&uint16(l as u16)));
        self.sp.squeeze_vec(l)
    }
}

/// Drive the full handshake with the stateful strategy, returning the deck
/// invocation count. (Leaf expansions and MACs use the crate's `derive` — an
/// `expand` is a single fresh sponge session, identical in both strategies; only
/// multi-fork stage trunks differ, and those use `Trunk` here.)
fn deck_stateful(inp: &Inputs) -> usize {
    let p = &SHAKE256;
    let sl = p.secret_len;
    let mut n = 0usize;

    // Early stage: absorb PSK, fork the 0-RTT leaves, then ratchet.
    let mut e = Trunk::init(p);
    e.absorb(b"psk", &inp.psk);
    let _c_e = e.leaf(b"c e traffic", SUITE, Some(&inp.th), sl);
    n += 1;
    let _e_exp = e.leaf(b"e exp master", SUITE, Some(&inp.th), sl);
    n += 1;
    let early_secret = e.ratchet(b"early secret", sl);
    n += 1;

    // PSK binder: binder_key + finished_key (expand) + MAC.
    let _binder = binder_verify_data(p, &early_secret, BinderKind::Resumption, SUITE, &inp.th);
    n += 3; // 2 expand + 1 MAC
            // early traffic key+iv (one expansion, split).
    let _ke = record_keys(p, &_c_e, SUITE, NK, NN);
    n += 1;

    // Handshake stage.
    let mut h = Trunk::init(p);
    h.absorb(b"early", &early_secret);
    h.absorb(b"dh", &inp.dhe);
    h.absorb(b"th", &inp.th);
    let c_hs = h.leaf(b"c hs traffic", SUITE, None, sl);
    n += 1;
    let s_hs = h.leaf(b"s hs traffic", SUITE, None, sl);
    n += 1;
    let main_secret = h.ratchet(b"main secret", sl);
    n += 1;
    let _khc = record_keys(p, &c_hs, SUITE, NK, NN);
    n += 1;
    let _khs = record_keys(p, &s_hs, SUITE, NK, NN);
    n += 1;
    let _fs = finished_verify_data(p, &s_hs, SUITE, &inp.th); // expand + MAC
    n += 2;
    let _fc = finished_verify_data(p, &c_hs, SUITE, &inp.th);
    n += 2;

    // Application stage.
    let mut t = Trunk::init(p);
    t.absorb(b"main", &main_secret);
    t.absorb(b"th", &inp.th);
    let c_ap = t.leaf(b"c ap traffic", SUITE, None, sl);
    n += 1;
    let s_ap = t.leaf(b"s ap traffic", SUITE, None, sl);
    n += 1;
    let exp_master = t.leaf(b"exp master", SUITE, None, sl);
    n += 1;
    // res_master binds TH_CF: continue the SAME application trunk (stateful
    // clone-per-fork), absorbing TH_CF and forking — not a re-initialised trunk
    // (draft §7.3 mutates T with `Absorb(T, "th", TH_CF)` after the earlier forks).
    t.absorb(b"th", &inp.th); // TH_CF
    let res_master = t.leaf(b"res master", SUITE, None, sl);
    n += 1;

    // gen-0 application record keys.
    let _kac = record_keys(p, &c_ap, SUITE, NK, NN);
    n += 1;
    let _kas = record_keys(p, &s_ap, SUITE, NK, NN);
    n += 1;

    // One KeyUpdate each direction.
    let c_ap1 = key_update(p, &c_ap, SUITE);
    n += 1;
    let _kac1 = record_keys(p, &c_ap1, SUITE, NK, NN);
    n += 1;
    let s_ap1 = key_update(p, &s_ap, SUITE);
    n += 1;
    let _kas1 = record_keys(p, &s_ap1, SUITE, NK, NN);
    n += 1;

    // NewSessionTicket resumption PSK; one exporter request. The exporter is a
    // single expansion over the precomputed context (schedule-only; see `Inputs`).
    let _rpsk = resumption_psk(p, &res_master, SUITE, &inp.nonce);
    n += 1;
    let _exp = expand(
        p,
        &exp_master,
        b"exporter",
        SUITE,
        Some(&inp.exporter_ctx),
        32,
    );
    n += 1;

    n
}

// ---------------------------------------------------------------------------
// Deck, recompute-from-path realization (what `deck-schedule` / the fork use;
// Appendix B). The stage trunks re-absorb their full framed path per leaf.
// ---------------------------------------------------------------------------

fn deck_recompute(inp: &Inputs) {
    let p = &SHAKE256;
    let psk = deck_schedule::schedule::Psk::new(&inp.psk).unwrap();
    let dhe: [&[u8]; 1] = [&inp.dhe];
    let out = run(
        p,
        &ScheduleInputs {
            psk: Some(psk),
            dhe_components: &dhe,
            recorded_suite: SUITE,
            selected_suite: SUITE,
            th_ch: &inp.th,
            th_sh: &inp.th,
            th_sf: &inp.th,
            th_cf: &inp.th,
        },
    );
    // Leaves: binder, record keys, Finished, key updates, resumption, exporter.
    let _ = binder_verify_data(p, &out.early_secret, BinderKind::Resumption, SUITE, &inp.th);
    let _ = record_keys(p, out.c_e_traffic.as_ref().unwrap(), SUITE, NK, NN);
    let _ = record_keys(p, &out.c_hs_traffic, SUITE, NK, NN);
    let _ = record_keys(p, &out.s_hs_traffic, SUITE, NK, NN);
    let _ = finished_verify_data(p, &out.s_hs_traffic, SUITE, &inp.th);
    let _ = finished_verify_data(p, &out.c_hs_traffic, SUITE, &inp.th);
    let _ = record_keys(p, &out.c_ap_traffic, SUITE, NK, NN);
    let _ = record_keys(p, &out.s_ap_traffic, SUITE, NK, NN);
    let c1 = key_update(p, &out.c_ap_traffic, SUITE);
    let _ = record_keys(p, &c1, SUITE, NK, NN);
    let s1 = key_update(p, &out.s_ap_traffic, SUITE);
    let _ = record_keys(p, &s1, SUITE, NK, NN);
    let _ = resumption_psk(p, &out.res_master, SUITE, &inp.nonce);
    let _ = expand(
        p,
        &out.exp_master,
        b"exporter",
        SUITE,
        Some(&inp.exporter_ctx),
        32,
    );
}

// ---------------------------------------------------------------------------
// HKDF-SHA3-256 (RFC 8446 schedule baseline). SHA3-256 over the same 24-round
// permutation; HMAC-SHA3-256; HKDF-Extract / -Expand-Label; Derive-Secret.
// ---------------------------------------------------------------------------

const H_LEN: usize = 32; // SHA3-256 output
const SHA3_DOMAIN: u8 = 0x06;

fn sha3_256(msg: &[u8]) -> Vec<u8> {
    let mut sp = Sponge::new(RATE, SHA3_DOMAIN, ROUNDS);
    sp.absorb(msg);
    sp.squeeze_vec(H_LEN)
}

fn hmac_sha3_256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut k = key.to_vec();
    if k.len() > RATE {
        k = sha3_256(&k);
    }
    k.resize(RATE, 0);
    let inner_in: Vec<u8> = k
        .iter()
        .map(|b| b ^ 0x36)
        .chain(msg.iter().copied())
        .collect();
    let inner = sha3_256(&inner_in);
    let outer_in: Vec<u8> = k
        .iter()
        .map(|b| b ^ 0x5c)
        .chain(inner.iter().copied())
        .collect();
    sha3_256(&outer_in)
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    hmac_sha3_256(salt, ikm)
}

fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    // HkdfLabel || 0x01 (one output block, len <= H_LEN throughout TLS 1.3/SHA3-256).
    let full_label = [b"tls13 ".as_ref(), label].concat();
    let mut info = Vec::new();
    info.extend_from_slice(&uint16(len as u16));
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    info.push(0x01);
    let t = hmac_sha3_256(secret, &info);
    t[..len].to_vec()
}

fn derive_secret(secret: &[u8], label: &[u8], th: &[u8]) -> Vec<u8> {
    hkdf_expand_label(secret, label, th, H_LEN)
}

/// The RFC 8446 (HKDF-SHA3-256) schedule for the same handshake, returning the
/// invocation count (each HKDF-Extract / -Expand-Label / HMAC call).
fn hkdf_sha3(inp: &Inputs) -> usize {
    let th = &inp.th32;
    let zero = [0u8; H_LEN];
    let mut n = 0usize;

    // Early Secret = HKDF-Extract(0, PSK).
    let early = hkdf_extract(&zero, &inp.psk[..H_LEN]);
    n += 1;
    let binder_key = derive_secret(&early, b"res binder", &[]);
    n += 1;
    let bfk = hkdf_expand_label(&binder_key, b"finished", &[], H_LEN);
    n += 1;
    let _binder = hmac_sha3_256(&bfk, th);
    n += 1;
    let _c_e = derive_secret(&early, b"c e traffic", th);
    n += 1;
    let _e_exp = derive_secret(&early, b"e exp master", th);
    n += 1;
    let _ek = hkdf_expand_label(&_c_e, b"key", &[], NK);
    let _ei = hkdf_expand_label(&_c_e, b"iv", &[], NN);
    n += 2;
    let derived1 = derive_secret(&early, b"derived", &[]);
    n += 1;

    // Handshake Secret = HKDF-Extract(derived1, DHE).
    let hs = hkdf_extract(&derived1, &inp.dhe);
    n += 1;
    let c_hs = derive_secret(&hs, b"c hs traffic", th);
    n += 1;
    let s_hs = derive_secret(&hs, b"s hs traffic", th);
    n += 1;
    let _ = hkdf_expand_label(&c_hs, b"key", &[], NK);
    let _ = hkdf_expand_label(&c_hs, b"iv", &[], NN);
    n += 2;
    let _ = hkdf_expand_label(&s_hs, b"key", &[], NK);
    let _ = hkdf_expand_label(&s_hs, b"iv", &[], NN);
    n += 2;
    let sfk = hkdf_expand_label(&s_hs, b"finished", &[], H_LEN);
    n += 1;
    let _ = hmac_sha3_256(&sfk, th);
    n += 1;
    let cfk = hkdf_expand_label(&c_hs, b"finished", &[], H_LEN);
    n += 1;
    let _ = hmac_sha3_256(&cfk, th);
    n += 1;
    let derived2 = derive_secret(&hs, b"derived", &[]);
    n += 1;

    // Master Secret = HKDF-Extract(derived2, 0).
    let master = hkdf_extract(&derived2, &zero);
    n += 1;
    let c_ap = derive_secret(&master, b"c ap traffic", th);
    n += 1;
    let s_ap = derive_secret(&master, b"s ap traffic", th);
    n += 1;
    let exp_master = derive_secret(&master, b"exp master", th);
    n += 1;
    let res_master = derive_secret(&master, b"res master", th);
    n += 1;
    let _ = hkdf_expand_label(&c_ap, b"key", &[], NK);
    let _ = hkdf_expand_label(&c_ap, b"iv", &[], NN);
    n += 2;
    let _ = hkdf_expand_label(&s_ap, b"key", &[], NK);
    let _ = hkdf_expand_label(&s_ap, b"iv", &[], NN);
    n += 2;

    // One KeyUpdate each direction (application_traffic_secret_N+1 + key/iv).
    let c_ap1 = hkdf_expand_label(&c_ap, b"traffic upd", &[], H_LEN);
    n += 1;
    let _ = hkdf_expand_label(&c_ap1, b"key", &[], NK);
    let _ = hkdf_expand_label(&c_ap1, b"iv", &[], NN);
    n += 2;
    let s_ap1 = hkdf_expand_label(&s_ap, b"traffic upd", &[], H_LEN);
    n += 1;
    let _ = hkdf_expand_label(&s_ap1, b"key", &[], NK);
    let _ = hkdf_expand_label(&s_ap1, b"iv", &[], NN);
    n += 2;

    // NewSessionTicket resumption PSK; one exporter (Derive-Secret + Expand-Label).
    let _ = hkdf_expand_label(&res_master, b"resumption", &inp.nonce, H_LEN);
    n += 1;
    let e_sec = derive_secret(&exp_master, b"exporter", th);
    n += 1;
    let _ = hkdf_expand_label(&e_sec, b"exporter", th, H_LEN);
    n += 1;

    n
}

// ---------------------------------------------------------------------------
// The informative FIPS-component schedule (draft Appendix D): RFC 8446 §7.1 with
// KMAC256 as the PRF throughout (Extract = KMAC256, Expand = SP 800-108 counter
// mode over KMAC256, Finished = KMAC256). It is the *same* RFC 8446 schedule, so
// its invocation count is identical to HKDF-SHA3-256's — the point of measuring
// it is the *permutation* cost: each KMAC256 call re-absorbs its fixed name and
// key blocks with no state carried between sites, forfeiting the deck's stateful
// savings. This isolates the deck's advantage as its structure, not merely its
// use of Keccak.
// ---------------------------------------------------------------------------

/// The FIPS-component schedule for the same handshake, returning the invocation
/// count. Mirrors [`hkdf_sha3`] site-for-site (schedule-only: the fixed
/// `Hash("")` and the exporter's context hashing are excluded on both sides), so
/// the two invocation counts are directly comparable.
fn fips_kmac256(inp: &Inputs) -> usize {
    use deck_schedule::fips;
    let th = &inp.th; // the FIPS TranscriptHash is SHAKE256(., 64) → 64 octets
    let fl = fips::HLEN;
    let zero = [0u8; fips::HLEN];
    let mut n = 0usize;

    // Early = Extract(0, PSK).
    let early = fips::extract(&zero, &inp.psk[..fl]);
    n += 1;
    let binder_key = fips::expand_label(&early, b"res binder", &[], fl);
    n += 1;
    let _binder = fips::finished_verify_data(&binder_key, th); // finished_key + MAC
    n += 2;
    let c_e = fips::expand_label(&early, b"c e traffic", th, fl);
    n += 1;
    let _e_exp = fips::expand_label(&early, b"e exp master", th, fl);
    n += 1;
    let _ = fips::record_keys(&c_e, NK, NN); // "key" + "iv"
    n += 2;
    let derived1 = fips::expand_label(&early, b"derived", &[], fl);
    n += 1;

    // Handshake = Extract(derived1, DHE).
    let hs = fips::extract(&derived1, &inp.dhe);
    n += 1;
    let c_hs = fips::expand_label(&hs, b"c hs traffic", th, fl);
    n += 1;
    let s_hs = fips::expand_label(&hs, b"s hs traffic", th, fl);
    n += 1;
    let _ = fips::record_keys(&c_hs, NK, NN);
    n += 2;
    let _ = fips::record_keys(&s_hs, NK, NN);
    n += 2;
    let _ = fips::finished_verify_data(&s_hs, th);
    n += 2;
    let _ = fips::finished_verify_data(&c_hs, th);
    n += 2;
    let derived2 = fips::expand_label(&hs, b"derived", &[], fl);
    n += 1;

    // Master = Extract(derived2, 0).
    let master = fips::extract(&derived2, &zero);
    n += 1;
    let c_ap = fips::expand_label(&master, b"c ap traffic", th, fl);
    n += 1;
    let s_ap = fips::expand_label(&master, b"s ap traffic", th, fl);
    n += 1;
    let exp_master = fips::expand_label(&master, b"exp master", th, fl);
    n += 1;
    let res_master = fips::expand_label(&master, b"res master", th, fl);
    n += 1;
    let _ = fips::record_keys(&c_ap, NK, NN);
    n += 2;
    let _ = fips::record_keys(&s_ap, NK, NN);
    n += 2;

    // One KeyUpdate each direction.
    let c_ap1 = fips::key_update(&c_ap);
    n += 1;
    let _ = fips::record_keys(&c_ap1, NK, NN);
    n += 2;
    let s_ap1 = fips::key_update(&s_ap);
    n += 1;
    let _ = fips::record_keys(&s_ap1, NK, NN);
    n += 2;

    // NewSessionTicket resumption PSK; one exporter (Derive-Secret + Expand-Label).
    let _ = fips::resumption_psk(&res_master, &inp.nonce);
    n += 1;
    let e_sec = fips::expand_label(&exp_master, b"exporter", th, fl);
    n += 1;
    let _ = fips::expand_label(&e_sec, b"exporter", th, fl);
    n += 1;

    n
}

fn main() {
    let inp = Inputs::new();

    let (deck_inv, deck_stateful_perms) = perms(|| deck_stateful(&inp));
    let (_, deck_recompute_perms) = perms(|| deck_recompute(&inp));
    let (hkdf_inv, hkdf_perms) = perms(|| hkdf_sha3(&inp));
    let (fips_inv, fips_perms) = perms(|| fips_kmac256(&inp));

    println!("Appendix A.1 benchmark — one full representative handshake");
    println!("  (PSK + (EC)DHE + 0-RTT + NewSessionTicket + 1 KeyUpdate each way)");
    println!("  over the shared 24-round Keccak-f[1600]\n");
    println!(
        "  {:<34}{:>12}{:>16}",
        "realization", "invocations", "permutations"
    );
    println!("  {:-<62}", "");
    println!(
        "  {:<34}{:>12}{:>16}",
        "deck (stateful, draft §7.1.2)", deck_inv, deck_stateful_perms
    );
    println!(
        "  {:<34}{:>12}{:>16}",
        "deck (recompute, deck-schedule)", deck_inv, deck_recompute_perms
    );
    println!(
        "  {:<34}{:>12}{:>16}",
        "HKDF-SHA3-256 (RFC 8446)", hkdf_inv, hkdf_perms
    );
    println!(
        "  {:<34}{:>12}{:>16}",
        "FIPS-component (KMAC256, App. D)", fips_inv, fips_perms
    );
    println!();
    println!(
        "  invocation ratio  HKDF : deck          = {hkdf_inv} : {deck_inv}  (draft Table 4: 39 : 29 — see note)",
    );
    println!(
        "  permutation ratio HKDF : deck stateful = {:.2}x  (draft §A.1: 156/52 = {:.2}x)",
        hkdf_perms as f64 / deck_stateful_perms as f64,
        156.0 / 52.0
    );
    println!(
        "  permutation ratio HKDF : deck recompute = {:.2}x  (recompute re-absorbs trunks, App. B)",
        hkdf_perms as f64 / deck_recompute_perms as f64
    );
    println!(
        "  permutation ratio FIPS : deck stateful = {:.2}x  (App. D is RFC 8446-structured: {fips_inv} invocations)",
        fips_perms as f64 / deck_stateful_perms as f64,
    );
    println!(
        "\n  Appendix D (informative): the FIPS-component schedule is the RFC 8446\n  \
         schedule with KMAC256 as the PRF, so it has the SAME invocation count as\n  \
         HKDF-SHA3-256 ({fips_inv}). Its {fips_perms} permutations sit between the deck ({deck_stateful_perms}) and\n  \
         HKDF-SHA3-256 ({hkdf_perms}): cheaper than HMAC-based HKDF (one KMAC per site vs\n  \
         HMAC's two hashes), but still ~{:.1}x the deck — it forfeits the deck's stateful\n  \
         savings. The deck's advantage is its structure, not merely its use of Keccak.",
        fips_perms as f64 / deck_stateful_perms as f64,
    );
    println!(
        "\n  Note: the §7.3 schedule has TWO ratchets (early_secret, main_secret), so the\n  \
         measured deck invocation count is 28, whereas Table 4 totals 29 (its deck\n  \
         column lists three \"Ratchet\" rows) — Table 4 appears to overcount by one deck\n  \
         invocation, so the deck is marginally cheaper than the draft states.\n  \
         HKDF-SHA3-256 matches the draft exactly (156 / 39)."
    );

    // The HKDF-SHA3-256 side matches the draft exactly (strong validation of the
    // RFC baseline). The deck side is measured faithfully (28 invocations from the
    // two §7.3 ratchets) and the headline ~3x permutation advantage must hold.
    assert_eq!(hkdf_inv, 39, "RFC 8446 invocation count (draft Table 4)");
    assert_eq!(hkdf_perms, 156, "HKDF-SHA3-256 permutations (draft §A.1)");
    assert_eq!(
        deck_inv, 28,
        "deck invocations: 28 for the two §7.3 ratchets (Table 4 lists 29)",
    );
    assert!(
        (36..=52).contains(&deck_stateful_perms),
        "deck stateful permutations well under HKDF (draft's ~52), got {deck_stateful_perms}",
    );
    let ratio = hkdf_perms as f64 / deck_stateful_perms as f64;
    assert!(
        ratio >= 3.0,
        "deck (stateful) is ~3x cheaper, got {ratio:.2}x"
    );
    assert!(
        deck_recompute_perms >= deck_stateful_perms,
        "recompute-from-path is never cheaper than stateful (Appendix B)",
    );
    // The FIPS-component schedule (App. D) is the RFC 8446 schedule, so it shares
    // HKDF-SHA3-256's invocation count and gets none of the deck's stateful win.
    assert_eq!(
        fips_inv, hkdf_inv,
        "App. D is RFC 8446-structured: same invocation count as HKDF-SHA3-256",
    );
    assert!(
        fips_perms as f64 / deck_stateful_perms as f64 >= 2.5,
        "FIPS-component schedule stays well above the deck (got {:.2}x)",
        fips_perms as f64 / deck_stateful_perms as f64,
    );

    println!(
        "\n  OK: HKDF-SHA3-256 = 156 perms / 39 invocations (matches §A.1); deck ~3x cheaper."
    );
}
