//! Measured schedule-only handshake costs ([invocation-count], [permutation-method]).
use deck_schedule::{
    deck::Deck,
    derive,
    frame::uint16,
    kdf::{Protocol, SHAKE256},
    keccak::count,
    labels,
    sponge::{Sponge, RATE},
};
const ROUNDS: usize = 24;
const NK: usize = 16;
const NN: usize = 12;
struct Inputs {
    psk: Vec<u8>,
    dhe: Vec<u8>,
    th: Vec<u8>,
    th32: Vec<u8>,
    empty_hash: Vec<u8>,
}
fn measure(f: impl FnOnce() -> usize) -> (usize, u64) {
    count::reset();
    let n = f();
    (n, count::permutations())
}
fn deck(inp: &Inputs) -> usize {
    let k = SHAKE256;
    let p = Protocol::Tls13;
    let mut n = 0;
    let mut e = Deck::early(k, p);
    e.absorb(labels::PSK, &inp.psk);
    let v = e
        .derive_n(&[(labels::RBK, 64), (labels::DRV, 64)], None)
        .unwrap();
    n += 1;
    let fk = derive::finished_key(k, p, &v[0]);
    n += 1;
    let _ = derive::finished_verify_data(k, p, &fk, &inp.th);
    n += 1;
    let early = e
        .derive_n(&[(labels::CET, 64), (labels::EES, 64)], Some(&inp.th))
        .unwrap();
    n += 1;
    let _ = derive::early_record_keys(k, p, &early[0], NK, NN);
    n += 1;
    let mut h = Deck::stage(k, p, &v[1]);
    h.absorb(labels::SHS, &inp.dhe);
    let hs = h
        .derive_n(&[(labels::CHT, 64), (labels::SHT, 64)], Some(&inp.th))
        .unwrap();
    n += 1;
    for secret in &hs {
        let (fk, _) = derive::handshake_record(k, p, secret, NK, NN);
        n += 1;
        let _ = derive::finished_verify_data(k, p, &fk, &inp.th);
        n += 1;
    }
    let app = h.ratchet();
    n += 1;
    let ap = app
        .derive_n(
            &[(labels::CAT, 64), (labels::SAT, 64), (labels::EXS, 64)],
            Some(&inp.th),
        )
        .unwrap();
    n += 1;
    let _ = app.derive(labels::RSS, Some(&inp.th), 64).unwrap();
    n += 1;
    for secret in &ap[..2] {
        let _ = derive::application_record(k, p, secret, NK, NN);
        n += 1;
    }
    n
}
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
    let binder_key = derive_secret(&early, b"res binder", &inp.empty_hash);
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
    let derived1 = derive_secret(&early, b"derived", &inp.empty_hash);
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
    let derived2 = derive_secret(&hs, b"derived", &inp.empty_hash);
    n += 1;

    // Master Secret = HKDF-Extract(derived2, 0).
    let master = hkdf_extract(&derived2, &zero);
    n += 1;
    let c_ap = derive_secret(&master, b"c ap traffic", th);
    n += 1;
    let s_ap = derive_secret(&master, b"s ap traffic", th);
    n += 1;
    let _exp_master = derive_secret(&master, b"exp master", th);
    n += 1;
    let _res_master = derive_secret(&master, b"res master", th);
    n += 1;
    let _ = hkdf_expand_label(&c_ap, b"key", &[], NK);
    let _ = hkdf_expand_label(&c_ap, b"iv", &[], NN);
    n += 2;
    let _ = hkdf_expand_label(&s_ap, b"key", &[], NK);
    let _ = hkdf_expand_label(&s_ap, b"iv", &[], NN);
    n += 2;

    n
}

fn main() {
    let inp = Inputs {
        psk: vec![0x11; 64],
        dhe: vec![0x22; 32],
        th: vec![0x33; 64],
        th32: vec![0x33; 32],
        empty_hash: sha3_256(b""),
    };
    let (dn, dp) = measure(|| deck(&inp));
    let (hn, hp) = measure(|| hkdf_sha3(&inp));
    println!("schedule-only PSK + DHE + 0-RTT handshake; transcript hashing excluded");
    println!("XOF schedule: {dn} invocations / {dp} permutations");
    println!("HKDF-SHA3-256: {hn} invocations / {hp} permutations");
    assert_eq!((dn, dp), (15, 23));
    assert_eq!((hn, hp), (30, 120));
}
