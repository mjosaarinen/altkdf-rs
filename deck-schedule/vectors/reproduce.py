#!/usr/bin/env python3
"""Independent reproduction of the deck-schedule test vectors (draft App. C).

This is a *second implementation*, written from the draft text alone
(draft-sullivan-tls-xof-ciphers-00), used to reproduce the vectors that the
Rust `deck-schedule` crate generates. It shares no code with that crate.

Independence and anchoring:

  * The Keccak-p[1600, nr] permutation and the sponge are re-implemented here in
    Python (Section 8.1, Section 9.1) — a distinct implementation from the Rust
    one.

  * That Python primitive is validated at startup against three published
    ground-truth sources before any vector is checked:
      - RFC 9861 App. A.3  TurboSHAKE256 (nr=12, domain 0x1F),
      - FIPS 202 / hashlib SHAKE256      (nr=24, domain 0x1F),
      - SP 800-185 KMAC256 Sample #4     (nr=24, domain 0x04) — anchors the MAC
        byte layout (Section 5.2) to NIST ground truth.
    It is additionally cross-checked, on multi-block inputs, against the
    independent Keccak implementations in `pycryptodome` (TurboSHAKE256) and the
    Python standard library (`hashlib.shake_256`), when those are available.

  * Every deck operation (Section 7.1), the schedule (Section 7.3), and every
    Section 5 derivation is then re-expressed here from the draft, and used to
    reproduce each vector's `expected` field. A mismatch aborts with a diff.

Usage:
    python3 deck-schedule/vectors/reproduce.py      # from workspace root
    python3 vectors/reproduce.py -v                 # from deck-schedule/
"""

from __future__ import annotations

import json
import os
import sys

# ---------------------------------------------------------------------------
# Keccak-p[1600, nr] permutation (draft Section 8.1 / 9.1; FIPS 202).
# ---------------------------------------------------------------------------

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_RHO = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
    41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
]
_MASK = (1 << 64) - 1


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def keccak_p(lanes: list[int], nr: int) -> None:
    """In-place Keccak-p[1600, nr] on 25 little-endian lanes.

    A reduced-round instance uses the *last* nr of the 24 round constants
    (draft Section 8.1; RFC 9861), i.e. round indices 24-nr .. 23.
    """
    for ir in range(24 - nr, 24):
        # theta
        c = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20]
             for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                lanes[x + 5 * y] ^= d[x]
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(lanes[x + 5 * y], _RHO[x + 5 * y])
        # chi
        for y in range(5):
            for x in range(5):
                lanes[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        # iota
        lanes[0] ^= _RC[ir]
        lanes[0] &= _MASK


RATE = 136  # octets (draft Section 5.2, 8.1, 9.1)


def sponge(data: bytes, domain: int, nr: int, outlen: int) -> bytes:
    """Rate-136 / capacity-512 sponge with pad10*1 (draft Section 8.1 / 9.1).

    For nr=12, domain=0x1F this is TurboSHAKE256(data, 0x1F, outlen); for nr=24,
    domain=0x1F it is SHAKE256(data, 8*outlen); domain=0x04 gives the MAC's
    permutation (Section 5.2).
    """
    state = bytearray(200)
    pos = 0
    for byte in data:
        state[pos] ^= byte
        pos += 1
        if pos == RATE:
            _permute(state, nr)
            pos = 0
    # pad: domain byte then pad10*1 (final rate octet's MSB).
    state[pos] ^= domain
    state[RATE - 1] ^= 0x80
    _permute(state, nr)
    out = bytearray()
    pos = 0
    while len(out) < outlen:
        if pos == RATE:
            _permute(state, nr)
            pos = 0
        out.append(state[pos])
        pos += 1
    return bytes(out)


def _permute(state: bytearray, nr: int) -> None:
    lanes = [int.from_bytes(state[8 * i:8 * i + 8], "little") for i in range(25)]
    keccak_p(lanes, nr)
    for i in range(25):
        state[8 * i:8 * i + 8] = lanes[i].to_bytes(8, "little")


# ---------------------------------------------------------------------------
# Framing (draft Section 2) and the KMAC encoders (draft Section 5.2).
# ---------------------------------------------------------------------------

def frame(x: bytes) -> bytes:
    assert len(x) <= 0xFFFE
    return len(x).to_bytes(2, "big") + x


def uint16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def _min_be(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def left_encode(n: int) -> bytes:
    b = _min_be(n)
    return bytes([len(b)]) + b


def right_encode(n: int) -> bytes:
    b = _min_be(n)
    return b + bytes([len(b)])


def encode_string(s: bytes) -> bytes:
    return left_encode(8 * len(s)) + s


def bytepad(s: bytes, w: int) -> bytes:
    out = bytearray(left_encode(w) + s)
    while len(out) % w != 0:
        out.append(0)
    return bytes(out)


# ---------------------------------------------------------------------------
# Profiles (draft Section 8, 9) and DF / TranscriptHash (Section 7.1, 2.1).
# ---------------------------------------------------------------------------

class Profile:
    def __init__(self, profile_id: bytes, nr: int):
        self.profile_id = profile_id
        self.nr = nr
        self.secret_len = 64
        self.flen = 64

    def df(self, seq: bytes, outlen: int) -> bytes:
        return sponge(seq, 0x1F, self.nr, outlen)

    def transcript_hash(self, x: bytes) -> bytes:
        return sponge(b"tls13 hash" + x, 0x1F, self.nr, 64)


TURBOSHAKE256 = Profile(b"TLS 1.3 DeckSchedule v1", 12)
SHAKE256 = Profile(b"TLS 1.3 SHAKESchedule v1", 24)


def profile_for(name: str) -> Profile:
    return {"TLS13-TURBOSHAKE256": TURBOSHAKE256, "TLS13-SHAKE256": SHAKE256}[name]


# ---------------------------------------------------------------------------
# Deck operations (draft Section 7.1.1). A Deck holds seq(S).
# ---------------------------------------------------------------------------

class Deck:
    def __init__(self, profile: Profile):
        self.p = profile
        self.seq = frame(profile.profile_id)  # Init()

    def absorb(self, tag: bytes, v: bytes) -> "Deck":
        self.seq += frame(tag) + frame(v)
        return self

    def fork(self, label: bytes, suite: int) -> "Deck":
        child = Deck.__new__(Deck)
        child.p = self.p
        child.seq = self.seq + frame(label) + frame(b"suite") + frame(uint16(suite))
        return child

    def squeeze(self, tag: bytes, outlen: int) -> bytes:
        assert outlen <= 0xFFFE
        seq = self.seq + frame(tag) + frame(uint16(outlen))
        return self.p.df(seq, outlen)

    def ratchet(self, label: bytes) -> bytes:
        return self.squeeze(label, self.p.secret_len)


# ---------------------------------------------------------------------------
# MAC (draft Section 5.2): the KMAC byte layout over the profile's permutation.
# ---------------------------------------------------------------------------

def mac(profile: Profile, key: bytes, suite: int, label: bytes, message: bytes, outlen: int) -> bytes:
    X = frame(profile.profile_id) + frame(uint16(suite)) + frame(label) + frame(message)
    S = b"TLS 1.3 MAC"
    name_and_s = encode_string(b"KMAC") + encode_string(S)
    mac_input = bytepad(name_and_s, RATE) + bytepad(encode_string(key), RATE) + X + right_encode(8 * outlen)
    return sponge(mac_input, 0x04, profile.nr, outlen)


# ---------------------------------------------------------------------------
# Keyed derivations (draft Section 5) and the schedule (Section 7.3).
# ---------------------------------------------------------------------------

def expand(profile, secret, label, suite, context, outlen):
    d = Deck(profile).absorb(b"secret", secret)
    fk = d.fork(label, suite)
    if context:  # empty/None context omits its Absorb (draft Section 5.1)
        fk.absorb(b"context", context)
    return fk.squeeze(b"out", outlen)


def record_keys(profile, traffic_secret, suite, nk, nn):
    block = Deck(profile).absorb(b"secret", traffic_secret).fork(b"key", suite).squeeze(b"out", nk + nn)
    return block[:nk], block[nk:nk + nn]


def key_update(profile, secret, suite):
    return expand(profile, secret, b"traffic upd", suite, None, profile.secret_len)


def finished_verify_data(profile, base_key, suite, th):
    fk = expand(profile, base_key, b"finished", suite, None, profile.secret_len)
    return mac(profile, fk, suite, b"finished", th, profile.flen)


def binder_verify_data(profile, early_secret, label, suite, th_ch0):
    binder_key = expand(profile, early_secret, label, suite, None, 64)
    fk = expand(profile, binder_key, b"finished", suite, None, profile.secret_len)
    return mac(profile, fk, suite, label, th_ch0, profile.flen)


def exporter(profile, exp_master, suite, label, context, length):
    assert length <= 0xFFFE
    ctx = frame(profile.transcript_hash(label)) + frame(profile.transcript_hash(context))
    d = Deck(profile).absorb(b"secret", exp_master)
    return d.fork(b"exporter", suite).absorb(b"context", ctx).squeeze(b"out", length)


def resumption_psk(profile, res_master, suite, ticket_nonce):
    d = Deck(profile).absorb(b"secret", res_master)
    return d.fork(b"resumption", suite).absorb(b"context", ticket_nonce).squeeze(b"out", 64)


def ech_confirmation(profile, random, suite, label, conf_messages):
    return mac(profile, random, suite, label, profile.transcript_hash(conf_messages), 8)


def imported_identity_v2(external_identity, context, target_protocol, target_ciphersuite):
    # draft Section 10 presentation language: opaque external_identity<1..2^16-1>,
    # opaque context<0..2^16-1>, uint16 target_protocol, uint16 target_ciphersuite.
    assert 1 <= len(external_identity) <= 0xFFFF and len(context) <= 0xFFFF
    return (uint16(len(external_identity)) + external_identity
            + uint16(len(context)) + context
            + uint16(target_protocol) + uint16(target_ciphersuite))


def psk_import(profile, target_suite, epsk, iid_bytes):
    assert len(epsk) <= 0xFFFE
    ctx = profile.transcript_hash(iid_bytes)
    d = Deck(profile).absorb(b"secret", epsk)
    return d.fork(b"derived psk", target_suite).absorb(b"context", ctx).squeeze(b"out", profile.secret_len)


# ---------------------------------------------------------------------------
# The informative FIPS-component schedule (draft Appendix D).
#
# RFC 8446 Section 7.1 extract-and-expand with the PRF replaced by KMAC256
# throughout, Extract drawn from SP 800-56C, TranscriptHash = SHAKE256(.,64).
# Re-derived here from the draft alone, sharing only the Keccak primitive (which
# is itself anchored to RFC/FIPS/NIST KATs at startup). See crate::fips for the
# documented interpretation of the byte-level layout this reproduces.
# ---------------------------------------------------------------------------

FIPS_HLEN = 64  # octets (draft App. D: L = 512 bits)


def kmac256(key: bytes, x: bytes, outlen_bits: int, S: bytes = b"") -> bytes:
    """NIST KMAC256(K, X, L, S) — nr=24, domain 0x04 (SP 800-185)."""
    name_and_s = encode_string(b"KMAC") + encode_string(S)
    mac_input = bytepad(name_and_s, RATE) + bytepad(encode_string(key), RATE) + x + right_encode(outlen_bits)
    return sponge(mac_input, 0x04, 24, outlen_bits // 8)


def fips_transcript_hash(messages: bytes) -> bytes:
    """SHAKE256(messages, 64) — plain, no "tls13 hash" prefix (draft App. D)."""
    return sponge(messages, 0x1F, 24, FIPS_HLEN)


def fips_extract(salt: bytes, ikm: bytes) -> bytes:
    """SP 800-56C two-step extraction: KMAC256(K=salt, X=ikm, L=512, S="")."""
    return kmac256(salt, ikm, 8 * FIPS_HLEN)


def fips_expand(ki: bytes, info: bytes, l: int) -> bytes:
    """SP 800-108 counter-mode expansion, PRF=KMAC256, 512-bit blocks.

    K_i = KMAC256(ki, be32(i) || info || 0x00 || be32(8l), 512, "").
    """
    l_bits = (8 * l).to_bytes(4, "big")
    out = bytearray()
    i = 1
    while len(out) < l:
        x = i.to_bytes(4, "big") + info + b"\x00" + l_bits
        out += kmac256(ki, x, 8 * FIPS_HLEN)
        i += 1
    return bytes(out[:l])


def fips_hkdf_label(length: int, label: bytes, context: bytes) -> bytes:
    full = b"tls13 " + label
    assert len(full) <= 255 and len(context) <= 255
    return uint16(length) + bytes([len(full)]) + full + bytes([len(context)]) + context


def fips_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    return fips_expand(secret, fips_hkdf_label(length, label, context), length)


def fips_derive_secret(secret: bytes, label: bytes, messages: bytes) -> bytes:
    return fips_expand_label(secret, label, fips_transcript_hash(messages), FIPS_HLEN)


def fips_schedule(psk, dhe, th_ch, th_sh, th_sf, th_cf):
    zero = b"\x00" * FIPS_HLEN
    has_psk = psk is not None
    out = {}
    early = fips_extract(zero, psk if has_psk else zero)
    out["early_secret"] = early
    if has_psk:
        out["c_e_traffic"] = fips_expand_label(early, b"c e traffic", th_ch, FIPS_HLEN)
        out["e_exp_master"] = fips_expand_label(early, b"e exp master", th_ch, FIPS_HLEN)
    else:
        out["c_e_traffic"] = None
        out["e_exp_master"] = None
    # Absent (EC)DHE (PSK-only) is the HLEN zero string, like the absent PSK
    # above (RFC 8446 §7.1) — mirrors deck_schedule::fips::run.
    dhe_ikm = dhe if dhe else zero
    handshake = fips_extract(fips_derive_secret(early, b"derived", b""), dhe_ikm)
    out["handshake_secret"] = handshake
    out["c_hs_traffic"] = fips_expand_label(handshake, b"c hs traffic", th_sh, FIPS_HLEN)
    out["s_hs_traffic"] = fips_expand_label(handshake, b"s hs traffic", th_sh, FIPS_HLEN)
    master = fips_extract(fips_derive_secret(handshake, b"derived", b""), zero)
    out["master_secret"] = master
    out["c_ap_traffic"] = fips_expand_label(master, b"c ap traffic", th_sf, FIPS_HLEN)
    out["s_ap_traffic"] = fips_expand_label(master, b"s ap traffic", th_sf, FIPS_HLEN)
    out["exp_master"] = fips_expand_label(master, b"exp master", th_sf, FIPS_HLEN)
    out["res_master"] = fips_expand_label(master, b"res master", th_cf, FIPS_HLEN)
    return out


def fips_finished_verify_data(base_key: bytes, th: bytes) -> bytes:
    fk = fips_expand_label(base_key, b"finished", b"", FIPS_HLEN)
    return kmac256(fk, th, 8 * FIPS_HLEN)


def fips_record_keys(traffic_secret: bytes, nk: int, nn: int):
    return (fips_expand_label(traffic_secret, b"key", b"", nk),
            fips_expand_label(traffic_secret, b"iv", b"", nn))


def fips_key_update(secret: bytes) -> bytes:
    return fips_expand_label(secret, b"traffic upd", b"", FIPS_HLEN)


def fips_exporter(exp_master: bytes, label: bytes, context: bytes, length: int) -> bytes:
    secret = fips_derive_secret(exp_master, label, b"")
    return fips_expand_label(secret, b"exporter", fips_transcript_hash(context), length)


def fips_resumption_psk(res_master: bytes, ticket_nonce: bytes) -> bytes:
    return fips_expand_label(res_master, b"resumption", ticket_nonce, FIPS_HLEN)


def fips_binder_verify_data(early_secret: bytes, label: bytes, th_ch0: bytes) -> bytes:
    binder_key = fips_derive_secret(early_secret, label, b"")
    return fips_finished_verify_data(binder_key, th_ch0)


def hrr_message_hash(profile, ch1):
    th1 = profile.transcript_hash(ch1)
    return b"\xfe" + b"\x00\x00" + bytes([len(th1)]) + th1  # message_hash || uint24(64) || TH(CH1)


def transcript_hash_after_hrr(profile, ch1, rest):
    return profile.transcript_hash(hrr_message_hash(profile, ch1) + rest)


def schedule(profile, psk, dhe_components, recorded_suite, selected_suite, th_ch, th_sh, th_sf, th_cf):
    sl = profile.secret_len
    has_psk = psk is not None
    out = {}

    # Early stage E (draft Section 7.3). No-PSK contributes frame("psk")||frame("").
    e = Deck(profile).absorb(b"psk", psk if has_psk else b"")
    if has_psk:
        out["c_e_traffic"] = e.fork(b"c e traffic", recorded_suite).absorb(b"th", th_ch).squeeze(b"out", sl)
        out["e_exp_master"] = e.fork(b"e exp master", recorded_suite).absorb(b"th", th_ch).squeeze(b"out", sl)
    else:
        out["c_e_traffic"] = None
        out["e_exp_master"] = None
    early_secret = e.ratchet(b"early secret")
    out["early_secret"] = early_secret

    # Handshake stage H.
    h = Deck(profile).absorb(b"early", early_secret)
    for comp in dhe_components:
        h.absorb(b"dh", comp)  # once per component, in order (never concatenated)
    h.absorb(b"th", th_sh)
    out["c_hs_traffic"] = h.fork(b"c hs traffic", selected_suite).squeeze(b"out", sl)
    out["s_hs_traffic"] = h.fork(b"s hs traffic", selected_suite).squeeze(b"out", sl)
    main_secret = h.ratchet(b"main secret")
    out["main_secret"] = main_secret

    # Application stage T.
    t = Deck(profile).absorb(b"main", main_secret).absorb(b"th", th_sf)
    out["c_ap_traffic"] = t.fork(b"c ap traffic", selected_suite).squeeze(b"out", sl)
    out["s_ap_traffic"] = t.fork(b"s ap traffic", selected_suite).squeeze(b"out", sl)
    out["exp_master"] = t.fork(b"exp master", selected_suite).squeeze(b"out", sl)
    t.absorb(b"th", th_cf)
    out["res_master"] = t.fork(b"res master", selected_suite).squeeze(b"out", sl)
    return out


# ---------------------------------------------------------------------------
# Startup self-validation of the Python primitive against published KATs.
# ---------------------------------------------------------------------------

def _h(s: str) -> bytes:
    return bytes.fromhex(s)


def _ptn(n: int) -> bytes:
    return bytes(i % 251 for i in range(n))


def self_validate() -> None:
    # RFC 9861 App. A.3 — TurboSHAKE256 (nr=12, 0x1F).
    assert sponge(b"", 0x1F, 12, 64) == _h(
        "367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db"
        "11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0")
    assert sponge(_ptn(289), 0x1F, 12, 64) == _h(
        "66b810db8e90780424c0847372fdc95710882fde31c6df75beb9d4cd9305cfca"
        "e35e7b83e8b7e6eb4b78605880116316fe2c078a09b94ad7b8213c0a738b65c0")
    assert sponge(b"", 0x1F, 12, 10032)[-32:] == _h(
        "abefa11630c661269249742685ec082f207265dccf2f43534e9c61ba0c9d1d75")

    # FIPS 202 — SHAKE256 (nr=24, 0x1F), cross-checked against hashlib.
    import hashlib
    assert sponge(b"", 0x1F, 24, 32) == _h(
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
    for msg in (b"", _ptn(289), _ptn(1000)):
        assert sponge(msg, 0x1F, 24, 137) == hashlib.shake_256(msg).digest(137), "SHAKE256 vs hashlib"

    # SP 800-185 KMAC256 Sample #4 (nr=24, 0x04) — anchors the MAC layout.
    class _P:
        profile_id = b""
        nr = 24
    k = bytes(range(0x40, 0x60))
    x = _h("00010203")
    S = b"My Tagged Application"
    name_and_s = encode_string(b"KMAC") + encode_string(S)
    mac_input = bytepad(name_and_s, RATE) + bytepad(encode_string(k), RATE) + x + right_encode(8 * 64)
    sample4 = _h(
        "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7"
        "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd")
    assert sponge(mac_input, 0x04, 24, 64) == sample4, "KMAC256 Sample #4"
    # Anchor the raw KMAC256 helper used by the FIPS-component schedule (App. D)
    # directly to the same NIST ground-truth output.
    assert kmac256(k, x, 8 * 64, S) == sample4, "kmac256 helper vs KMAC256 Sample #4"

    # Optional cross-checks against pycryptodome's independent Keccak.
    try:
        from Crypto.Hash import TurboSHAKE256 as _TS, KMAC256 as _KMAC
        # nr=12 for both the deck domain (0x1F) and the MAC domain (0x04): anchors
        # the TurboKMAC256 permutation path, which no published KAT covers (only
        # nr=24 / 0x04 is, via KMAC256 Sample #4 above).
        for dom in (0x1F, 0x04):
            for msg in (b"", _ptn(289), _ptn(4913)):
                assert sponge(msg, dom, 12, 96) == _TS.new(data=msg, domain=dom).read(96), \
                    f"TurboSHAKE(nr=12, D={dom:#x}) vs pycryptodome"
        # SHAKE-profile MAC == NIST KMAC256 (draft Section 5.2, 9.2), via pycryptodome.
        got = mac(SHAKE256, bytes(range(64)), 0xFF04, b"finished", _ptn(32), 64)
        km = _KMAC.new(key=bytes(range(64)), mac_len=64, custom=b"TLS 1.3 MAC")
        km.update(frame(SHAKE256.profile_id) + frame(uint16(0xFF04)) + frame(b"finished") + frame(_ptn(32)))
        assert got == km.digest(), "deck MAC (SHAKE256) vs pycryptodome KMAC256"
        pyc = True
    except ImportError:
        pyc = False
    return pyc


# ---------------------------------------------------------------------------
# Vector reproduction.
# ---------------------------------------------------------------------------

def _dispatch(profile: Profile, v: dict) -> dict:
    """Recompute a vector's expected outputs from its args. Returns {field: hex}."""
    op = v["op"]
    a = v["args"]
    hx = lambda s: bytes.fromhex(s)

    if op == "transcript_hash":
        return {"hash": profile.transcript_hash(hx(a["x"])).hex()}
    if op == "transcript_hash_after_hrr":
        return {"hash": transcript_hash_after_hrr(profile, hx(a["client_hello1"]), hx(a["rest"])).hex()}
    if op == "schedule":
        psk = None if a["psk"] is None else hx(a["psk"])
        dhe = [hx(c) for c in a["dhe_components"]]
        out = schedule(profile, psk, dhe, a["recorded_suite"], a["selected_suite"],
                       hx(a["th_ch"]), hx(a["th_sh"]), hx(a["th_sf"]), hx(a["th_cf"]))
        return {k: (None if val is None else val.hex()) for k, val in out.items()}
    if op == "binder_verify_data":
        label = {"ext binder": b"ext binder", "res binder": b"res binder"}[a["kind"]]
        return {"verify_data": binder_verify_data(profile, hx(a["early_secret"]), label, a["suite"], hx(a["th_ch0"])).hex()}
    if op == "record_keys":
        k, iv = record_keys(profile, hx(a["traffic_secret"]), a["suite"], a["nk"], a["nn"])
        return {"write_key": k.hex(), "write_iv": iv.hex()}
    if op == "finished_verify_data":
        return {"verify_data": finished_verify_data(profile, hx(a["base_key"]), a["suite"], hx(a["th"])).hex()}
    if op == "key_update":
        return {"next": key_update(profile, hx(a["app_traffic_secret"]), a["suite"]).hex()}
    if op == "resumption_psk":
        return {"resumption_psk": resumption_psk(profile, hx(a["res_master"]), a["suite"], hx(a["ticket_nonce"])).hex()}
    if op == "exporter":
        return {"out": exporter(profile, hx(a["exp_master"]), a["suite"], a["label"].encode(), hx(a["context"]), a["length"]).hex()}
    if op == "ech_accept_confirmation":
        return {"confirmation": ech_confirmation(profile, hx(a["client_hello_inner_random"]), a["selected_suite"],
                                                 b"ech accept confirmation", hx(a["ech_conf_messages"])).hex()}
    if op == "hrr_ech_accept_confirmation":
        return {"confirmation": ech_confirmation(profile, hx(a["client_hello_inner_random"]), a["selected_suite"],
                                                 b"hrr ech accept confirmation", hx(a["hrr_ech_conf_messages"])).hex()}
    if op == "mac":
        return {"tag": mac(profile, hx(a["key"]), a["suite"], a["label"].encode(), hx(a["message"]), a["l"]).hex()}
    if op == "psk_import":
        # Independently serialize ImportedIdentityV2 (draft Section 10) from the
        # structured fields, then derive the ipsk from it (draft Section 5.9). Both
        # the encoding and the derivation are checked against the vector.
        iid = imported_identity_v2(hx(a["external_identity"]), hx(a["context"]),
                                   a["target_protocol"], a["target_ciphersuite"])
        ipsk = psk_import(profile, a["target_ciphersuite"], hx(a["epsk"]), iid)
        return {"imported_identity_v2": iid.hex(), "ipsk": ipsk.hex()}
    if op == "expand":
        ctx = None if a["context"] is None else hx(a["context"])
        return {"out": expand(profile, hx(a["secret"]), a["label"].encode(), a["suite"], ctx, a["l"]).hex()}
    raise ValueError(f"unknown op {op!r}")


def _dispatch_fips(v: dict) -> dict:
    """Recompute a FIPS-component (draft App. D) vector. No profile: the FIPS
    schedule binds no cipher suite and fixes nr=24 (KMAC256 / SHAKE256)."""
    op = v["op"]
    a = v["args"]
    hx = lambda s: bytes.fromhex(s)

    if op == "fips_transcript_hash":
        return {"hash": fips_transcript_hash(hx(a["messages"])).hex()}
    if op == "fips_extract":
        return {"prk": fips_extract(hx(a["salt"]), hx(a["ikm"])).hex()}
    if op == "fips_expand_label":
        return {"out": fips_expand_label(hx(a["secret"]), a["label"].encode(),
                                         hx(a["context"]), a["length"]).hex()}
    if op == "fips_schedule":
        psk = None if a["psk"] is None else hx(a["psk"])
        out = fips_schedule(psk, hx(a["dhe"]), hx(a["th_ch"]), hx(a["th_sh"]),
                            hx(a["th_sf"]), hx(a["th_cf"]))
        return {k: (None if val is None else val.hex()) for k, val in out.items()}
    if op == "fips_finished_verify_data":
        return {"verify_data": fips_finished_verify_data(hx(a["base_key"]), hx(a["th"])).hex()}
    if op == "fips_record_keys":
        k, iv = fips_record_keys(hx(a["traffic_secret"]), a["nk"], a["nn"])
        return {"write_key": k.hex(), "write_iv": iv.hex()}
    if op == "fips_key_update":
        return {"next": fips_key_update(hx(a["app_traffic_secret"])).hex()}
    if op == "fips_exporter":
        return {"out": fips_exporter(hx(a["exp_master"]), a["label"].encode(),
                                     hx(a["context"]), a["length"]).hex()}
    if op == "fips_resumption_psk":
        return {"resumption_psk": fips_resumption_psk(hx(a["res_master"]), hx(a["ticket_nonce"])).hex()}
    if op == "fips_binder_verify_data":
        label = {"ext binder": b"ext binder", "res binder": b"res binder"}[a["kind"]]
        return {"verify_data": fips_binder_verify_data(hx(a["early_secret"]), label, hx(a["th_ch0"])).hex()}
    raise ValueError(f"unknown FIPS op {op!r}")


def _compare(got: dict, v: dict) -> int:
    """Compare a recomputed vector against its `expected` fields. Raise SystemExit
    on any mismatch. Returns the number of expected fields checked."""
    exp = v["expected"]
    if set(got) != set(exp):
        raise SystemExit(f"{v['name']}: field set {sorted(got)} != {sorted(exp)}")
    for key, val in exp.items():
        if got[key] != val:
            raise SystemExit(
                f"MISMATCH {v['name']}.{key}\n  expected {val}\n  got      {got[key]}")
    return len(exp)


def check_vector(profile: Profile, v: dict) -> int:
    """Reproduce one deck (App. C) vector and compare every field."""
    return _compare(_dispatch(profile, v), v)


def check_fips_vector(v: dict) -> int:
    """Reproduce one FIPS-component (App. D) vector and compare every field."""
    return _compare(_dispatch_fips(v), v)


def negative_control() -> None:
    """Prove the field comparison in check_vector is non-vacuous: a deliberately
    corrupted `expected` MUST be detected. Guards against a checker that silently
    passes everything (e.g. an op that returns the wrong field set)."""
    v = {"name": "neg_ctrl", "op": "transcript_hash", "args": {"x": "616263"}, "expected": {}}
    correct = _dispatch(TURBOSHAKE256, v)["hash"]
    corrupted = ("0" if correct[0] != "0" else "1") + correct[1:]  # flip first nibble
    v["expected"] = {"hash": corrupted}
    try:
        check_vector(TURBOSHAKE256, v)
    except SystemExit:
        return
    raise SystemExit("negative control FAILED: a corrupted vector was not detected")


def reproduce_file(path: str, verbose: bool) -> tuple[int, int]:
    with open(path) as fh:
        doc = json.load(fh)
    profile = profile_for(doc["profile"])
    assert profile.profile_id.hex() == doc["profile_id_hex"], "profile_id mismatch"
    assert profile.nr == doc["rounds"], "round count mismatch"

    fields = 0
    per_op: dict[str, int] = {}
    for v in doc["vectors"]:
        fields += check_vector(profile, v)
        per_op[v["op"]] = per_op.get(v["op"], 0) + 1
    if verbose:
        print(f"    {os.path.basename(path)}: {per_op}")
    return len(doc["vectors"]), fields


def reproduce_fips_file(path: str, verbose: bool) -> tuple[int, int]:
    """Reproduce the informative FIPS-component schedule set (draft App. D)."""
    with open(path) as fh:
        doc = json.load(fh)
    assert doc.get("schedule") == "FIPS-component (Appendix D)", "not the FIPS set"
    fields = 0
    per_op: dict[str, int] = {}
    for v in doc["vectors"]:
        fields += check_fips_vector(v)
        per_op[v["op"]] = per_op.get(v["op"], 0) + 1
    if verbose:
        print(f"    {os.path.basename(path)}: {per_op}")
    return len(doc["vectors"]), fields


def fips_negative_control() -> None:
    """The FIPS checker is non-vacuous too: a corrupted expected value is caught."""
    v = {"name": "fips_neg_ctrl", "op": "fips_transcript_hash",
         "args": {"messages": "616263"}, "expected": {}}
    correct = _dispatch_fips(v)["hash"]
    v["expected"] = {"hash": ("0" if correct[0] != "0" else "1") + correct[1:]}
    try:
        check_fips_vector(v)
    except SystemExit:
        return
    raise SystemExit("FIPS negative control FAILED: a corrupted vector was not detected")


def main() -> int:
    verbose = "-v" in sys.argv[1:]
    here = os.path.dirname(os.path.abspath(__file__))
    pyc = self_validate()
    src = ("hand-rolled Keccak vs RFC/FIPS/NIST KATs, cross-checked vs pycryptodome + hashlib"
           if pyc else "hand-rolled Keccak validated vs RFC/FIPS/NIST KATs (pycryptodome not installed)")
    print(f"[ok] Python primitive self-validated ({src}).")

    negative_control()
    print("[ok] negative control: a corrupted vector is detected (checker is non-vacuous).")

    total_vectors = total_fields = 0
    for fn in ("turboshake256.json", "shake256.json"):
        path = os.path.join(here, fn)
        vecs, fields = reproduce_file(path, verbose)
        print(f"[ok] {fn}: reproduced {vecs} vectors ({fields} expected fields).")
        total_vectors += vecs
        total_fields += fields
    print(f"[ok] Appendix C: {total_vectors} deck vectors reproduced ({total_fields} expected fields match).")

    # Appendix D (informative): the FIPS-component schedule.
    fips_negative_control()
    fvecs, ffields = reproduce_fips_file(os.path.join(here, "fips.json"), verbose)
    print(f"[ok] Appendix D (informative): reproduced {fvecs} FIPS-component vectors ({ffields} expected fields).")

    total_vectors += fvecs
    total_fields += ffields
    print(f"[ok] ALL {total_vectors} vectors reproduced independently ({total_fields} expected fields match).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
