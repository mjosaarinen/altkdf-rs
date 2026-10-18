//! Keyed derivations from retained secrets (draft `[derived-outputs]`).
//!
//! Every value keyed by a retained octet-string secret, rather than by a live
//! stage trunk, is a `Derive` or `DeriveN` over `Init(secret)` (draft
//! `[expand-op]`): record keys, key update, Finished and binder keys, the MAC,
//! exporters, the resumption PSK, the ECH confirmations, the DTLS 1.3 `sn_key`,
//! and any companion protocol's `HKDF-Expand-Label` replacement.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::deck::Deck;
use crate::frame::MAX_FRAME;
use crate::kdf::{Kdf, Protocol};
use crate::labels::{self, Label};
use crate::transcript::transcript_hash;
use crate::{Error, Secret};

/// An AEAD write key and IV, sliced from one `key_block`.
pub struct TrafficKeys {
    /// `write_key = key_block[0..Nk]`.
    pub key: Secret,
    /// `write_iv = key_block[Nk..Nk+Nn]`.
    pub iv: Secret,
}

impl TrafficKeys {
    fn split(key_block: &[u8], nk: usize) -> Self {
        TrafficKeys {
            key: Zeroizing::new(key_block[..nk].to_vec()),
            iv: Zeroizing::new(key_block[nk..].to_vec()),
        }
    }
}

fn fixed(r: Result<Secret, Error>) -> Secret {
    r.expect("fixed derivation site has valid lengths")
}

fn fixed_n(r: Result<Vec<Secret>, Error>) -> (Secret, Secret) {
    let mut v = r.expect("fixed DeriveN site has valid descriptors");
    let b = v.pop().unwrap();
    let a = v.pop().unwrap();
    (a, b)
}

/// Early record keys: `Derive(Init(c_e_traffic), "key", Nk + Nn)` (draft
/// `[record-keys-generic]`). `nk`/`nn` are those of the PSK's associated suite.
pub fn early_record_keys(
    kdf: Kdf,
    proto: Protocol,
    c_e_traffic: &[u8],
    nk: usize,
    nn: usize,
) -> TrafficKeys {
    let kb = fixed(Deck::keyed(kdf, proto, c_e_traffic).derive(labels::KEY, None, nk + nn));
    TrafficKeys::split(&kb, nk)
}

/// Handshake record keys and that sender's Finished key, in one DeriveN:
/// `(finished_key, key_block) = DeriveN(Init(hs_traffic), [("fin",
/// SecretLen), ("key", Nk + Nn)])`.
pub fn handshake_record(
    kdf: Kdf,
    proto: Protocol,
    hs_traffic: &[u8],
    nk: usize,
    nn: usize,
) -> (Secret, TrafficKeys) {
    let (fk, kb) = fixed_n(Deck::keyed(kdf, proto, hs_traffic).derive_n(
        &[(labels::FIN, kdf.secret_len), (labels::KEY, nk + nn)],
        None,
    ));
    (fk, TrafficKeys::split(&kb, nk))
}

/// Application record keys of generation N and the next generation's secret:
/// `(app_traffic_{N+1}, key_block_N) = DeriveN(Init(app_traffic_N), [("upd",
/// SecretLen), ("key", Nk + Nn)])` (draft `[record-keys-generic]`,
/// `[key-update-generic]`). A key update installs the returned successor and
/// calls this again.
pub fn application_record(
    kdf: Kdf,
    proto: Protocol,
    app_traffic: &[u8],
    nk: usize,
    nn: usize,
) -> (Secret, TrafficKeys) {
    let (next, kb) = fixed_n(Deck::keyed(kdf, proto, app_traffic).derive_n(
        &[(labels::UPD, kdf.secret_len), (labels::KEY, nk + nn)],
        None,
    ));
    (next, TrafficKeys::split(&kb, nk))
}

/// Standalone `finished_key = Derive(Init(base_key), "fin")`: the binder's
/// (base `binder_key`) and post-handshake authentication's (base: the sender's
/// current application traffic secret). Handshake Finished keys come from
/// [`handshake_record`] instead.
pub fn finished_key(kdf: Kdf, proto: Protocol, base_key: &[u8]) -> Secret {
    fixed(Deck::keyed(kdf, proto, base_key).derive(labels::FIN, None, kdf.secret_len))
}

/// `MAC(key, message, L) = Derive(Init(key), "mac", message, L)` (draft
/// `[mac-op]`). Every MAC of the draft is `L = FLen` over a 64-octet transcript
/// hash; the result is a wire value, not a secret.
pub fn mac(
    kdf: Kdf,
    proto: Protocol,
    key: &[u8],
    message: &[u8],
    l: usize,
) -> Result<Vec<u8>, Error> {
    let t = Deck::keyed(kdf, proto, key).derive(labels::MAC, Some(message), l)?;
    Ok(t.to_vec())
}

/// Finished `verify_data = MAC(finished_key, th, FLen)`.
pub fn finished_verify_data(kdf: Kdf, proto: Protocol, finished_key: &[u8], th: &[u8]) -> Vec<u8> {
    mac(kdf, proto, finished_key, th, kdf.flen).expect("valid Finished input and output lengths")
}

/// PSK binder `verify_data`: `finished_key = Derive(Init(binder_key),
/// "fin")`, then `MAC(finished_key, TH_CH0, FLen)` (draft
/// `[finished-and-binder-mac]`). The binder key itself comes from the early
/// stage ([`crate::schedule::EarlyStage::binder_key`]).
pub fn binder_verify_data(kdf: Kdf, proto: Protocol, binder_key: &[u8], th_ch0: &[u8]) -> Vec<u8> {
    let fk = finished_key(kdf, proto, binder_key);
    finished_verify_data(kdf, proto, &fk, th_ch0)
}

/// The first exporter step: `Derive(Init(exporter_secret), "exl", label,
/// SecretLen)`. The raw label is the context; an empty label is omitted.
pub fn exporter_label_secret(
    kdf: Kdf,
    proto: Protocol,
    exporter_secret: &[u8],
    label: &[u8],
) -> Result<Secret, Error> {
    if label.len() > MAX_FRAME {
        return Err(Error::FrameTooLong);
    }
    Deck::keyed(kdf, proto, exporter_secret).derive(labels::EXL, Some(label), kdf.secret_len)
}

/// `TLS-Exporter(label, context, length)` (draft `[exporters-generic]`):
/// the label secret, then `Derive(Init(exporter_label_secret), "exp",
/// TranscriptHash(context), length)`. Rejects labels over 65535 octets and
/// lengths of 0 or over 65535. The early exporter is the same call keyed by
/// `early_exporter_secret`.
pub fn exporter(
    kdf: Kdf,
    proto: Protocol,
    exporter_secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Secret, Error> {
    if length == 0 || length > MAX_FRAME {
        return Err(Error::OutputLength);
    }
    let els = exporter_label_secret(kdf, proto, exporter_secret, label)?;
    let ch = transcript_hash(&kdf, context);
    Deck::keyed(kdf, proto, &els).derive(labels::EXP, Some(&ch), length)
}

/// `resumption_psk = Derive(Init(resumption_secret), "rsp", ticket_nonce,
/// SecretLen)`; an empty nonce is omitted (draft `[expand-op]`).
pub fn resumption_psk(
    kdf: Kdf,
    proto: Protocol,
    resumption_secret: &[u8],
    ticket_nonce: &[u8],
) -> Secret {
    fixed(Deck::keyed(kdf, proto, resumption_secret).derive(
        labels::RSP,
        Some(ticket_nonce),
        kdf.secret_len,
    ))
}

/// ECH `accept_confirmation = Derive(Init(ClientHelloInner.random), "eca",
/// TranscriptHash(ech_conf_messages), 8)` (draft `[ech-generic]`). `th` is the
/// transcript hash already computed by the caller.
pub fn ech_accept_confirmation(
    kdf: Kdf,
    proto: Protocol,
    inner_random: &[u8],
    th: &[u8],
) -> [u8; 8] {
    ech_confirmation(kdf, proto, labels::ECA, inner_random, th)
}

/// ECH `hrr_accept_confirmation`, as [`ech_accept_confirmation`] under "hca".
pub fn hrr_ech_accept_confirmation(
    kdf: Kdf,
    proto: Protocol,
    inner_random: &[u8],
    th: &[u8],
) -> [u8; 8] {
    ech_confirmation(kdf, proto, labels::HCA, inner_random, th)
}

fn ech_confirmation(
    kdf: Kdf,
    proto: Protocol,
    label: &Label,
    inner_random: &[u8],
    th: &[u8],
) -> [u8; 8] {
    let c = fixed(Deck::keyed(kdf, proto, inner_random).derive(label, Some(th), 8));
    let mut out = [0u8; 8];
    out.copy_from_slice(&c);
    out
}

/// DTLS 1.3 record sequence-number key: `sn_key = Derive(Init(traffic_secret),
/// "snk", Nk)` (draft `[dtls]`). Call with [`Protocol::Dtls13`].
pub fn sn_key(kdf: Kdf, proto: Protocol, traffic_secret: &[u8], nk: usize) -> Secret {
    fixed(Deck::keyed(kdf, proto, traffic_secret).derive(labels::SNK, None, nk))
}

/// The companion-protocol rule (draft `[companion-mechanisms]`): a protocol built
/// on TLS 1.3 that would call `HKDF-Expand-Label(Secret, Label, Context,
/// Length)` instead calls `Derive(Init(Secret), label, Context, Length)` under
/// its own registered 3-octet label, single-output form only.
pub fn expand_label(
    kdf: Kdf,
    proto: Protocol,
    secret: &[u8],
    label: &Label,
    context: &[u8],
    length: usize,
) -> Result<Secret, Error> {
    Deck::keyed(kdf, proto, secret).derive(label, Some(context), length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::TURBOSHAKE256;

    const K: Kdf = TURBOSHAKE256;
    const P: Protocol = Protocol::Tls13;

    #[test]
    fn exporter_rejects_bad_lengths() {
        let es = [5u8; 64];
        assert_eq!(
            exporter(K, P, &es, b"l", b"", 0).err(),
            Some(Error::OutputLength)
        );
        assert_eq!(
            exporter(K, P, &es, b"l", b"", 65536).err(),
            Some(Error::OutputLength)
        );
        let long = alloc::vec![b'x'; 65536];
        assert_eq!(
            exporter(K, P, &es, &long, b"", 32).err(),
            Some(Error::FrameTooLong)
        );
        assert!(exporter(K, P, &es, &long[..65535], b"", 32).is_ok());
    }

    /// The binder MAC key comes from binder_key under "fin", not the Finished
    /// path's DeriveN; flattening the two gives a different key.
    #[test]
    fn binder_finished_key_differs_from_handshake_finished_key() {
        let base = [9u8; 64];
        let (hs_fk, _) = handshake_record(K, P, &base, 16, 12);
        assert_ne!(*finished_key(K, P, &base), *hs_fk);
    }

    #[test]
    fn traffic_keys_split() {
        let (_, tk) = application_record(K, P, &[1u8; 64], 32, 12);
        assert_eq!(tk.key.len(), 32);
        assert_eq!(tk.iv.len(), 12);
    }

    #[test]
    fn mac_empty_message_uses_canonical_context_omission() {
        let key = [1; 64];
        let expected = Deck::keyed(K, P, &key)
            .derive(labels::MAC, None, 64)
            .unwrap();
        assert_eq!(mac(K, P, &key, b"", 64).unwrap(), *expected);
    }
}
