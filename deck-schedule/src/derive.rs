//! Leaf derivations keyed by a retained octet-string secret (draft §5).
//!
//! Every function here is a deck session (draft §5.1) or a `MAC` (draft §5.2)
//! rooted at a retained secret — the analogue of RFC 8446's HKDF-Expand-Label
//! and HMAC-based MACs, carrying the same labels.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::deck::Deck;
use crate::mac::mac;
use crate::profile::Profile;
use crate::suites::{self, CipherSuite};
use crate::transcript::transcript_hash;
use crate::Secret;

/// Expand a retained secret (draft §5.1): the analogue of HKDF-Expand-Label.
///
/// `D = Init(); Absorb(D,"secret",secret); F = Fork(D,label,suite);`
/// `[Absorb(F,"context",context);] out = Squeeze(F,"out",L)`.
/// An empty `context` (encoded here as `None`) omits its `Absorb` (draft §5.1).
pub fn expand(
    profile: &Profile,
    secret: &[u8],
    label: &[u8],
    suite: u16,
    context: Option<&[u8]>,
    l: usize,
) -> Secret {
    let mut d = Deck::init(profile);
    d.absorb(b"secret", secret);
    let mut f = d.fork(label, suite);
    // §5.1: an empty context omits its Absorb rather than framing an empty
    // value, so `None` and `Some(b"")` are normalized to the same omission.
    if let Some(ctx) = context.filter(|c| !c.is_empty()) {
        f.absorb(b"context", ctx);
    }
    Zeroizing::new(f.squeeze(b"out", l))
}

/// Record write_key / write_iv from a traffic secret, in one call (draft §5.3).
pub fn record_keys(
    profile: &Profile,
    traffic_secret: &[u8],
    suite: u16,
    nk: usize,
    nn: usize,
) -> (Secret, Secret) {
    let mut d = Deck::init(profile);
    d.absorb(b"secret", traffic_secret);
    // Wrap the full key block so it is erased once split (draft §15.7.2.2).
    let block = Zeroizing::new(d.fork(b"key", suite).squeeze(b"out", nk + nn));
    (
        Zeroizing::new(block[..nk].to_vec()),
        Zeroizing::new(block[nk..nk + nn].to_vec()),
    )
}

/// Next traffic-secret generation from the current one (draft §5.4).
pub fn key_update(profile: &Profile, app_traffic_secret_n: &[u8], suite: u16) -> Secret {
    expand(
        profile,
        app_traffic_secret_n,
        b"traffic upd",
        suite,
        None,
        profile.secret_len,
    )
}

/// `finished_key` from a base (handshake traffic) secret (draft §5.5).
pub fn finished_key(profile: &Profile, base_key: &[u8], suite: u16) -> Secret {
    expand(
        profile,
        base_key,
        b"finished",
        suite,
        None,
        profile.secret_len,
    )
}

/// Finished `verify_data` (draft §5.5). `th` covers the transcript up to but
/// not including the Finished being computed (draft §2.1).
pub fn finished_verify_data(profile: &Profile, base_key: &[u8], suite: u16, th: &[u8]) -> Vec<u8> {
    let fk = finished_key(profile, base_key, suite);
    mac(profile, &fk, suite, b"finished", th, profile.flen)
}

/// Which binder label applies (draft §5.5).
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

/// PSK binder `verify_data` (draft §5.5), derived in two steps from the
/// early-stage secret keyed by that PSK. `suite` is the PSK's recorded suite;
/// `th_ch0` is `TH_CH0` (draft §2.1, §5.5).
///
/// NB — do not "simplify" this into the Finished path
/// ([`finished_verify_data`]). The two are deliberately different: the
/// `finished_key` is *expanded* under the `"finished"` label (like Finished),
/// but the `MAC` is taken under the **binder** label (`"ext binder"` /
/// `"res binder"`, from `kind`), whereas Finished MACs under `"finished"`. The
/// draft §5.5 listing has `verify_data = MAC(finished_key, suite, label, TH_CH0,
/// FLen)` with `label` = the binder label. Flattening the MAC label to
/// `"finished"` would silently produce a different, wrong binder; the test
/// `binder_mac_label_is_binder_not_finished` pins the distinction.
pub fn binder_verify_data(
    profile: &Profile,
    early_secret: &[u8],
    kind: BinderKind,
    suite: u16,
    th_ch0: &[u8],
) -> Vec<u8> {
    let label = kind.label();
    // Expand the finished_key under "finished" (as RFC 8446 / §5.5 do)…
    let binder_key = expand(profile, early_secret, label, suite, None, 64);
    let finished_key = expand(
        profile,
        &binder_key,
        b"finished",
        suite,
        None,
        profile.secret_len,
    );
    // …but MAC under the *binder* label `label`, NOT "finished" (draft §5.5).
    mac(profile, &finished_key, suite, label, th_ch0, profile.flen)
}

/// `TLS-Exporter(label, context, length)` (draft §5.6). Rejects requests longer
/// than `0xFFFE` octets (draft §3).
pub fn exporter(
    profile: &Profile,
    exp_master: &[u8],
    suite: u16,
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Secret, ExporterTooLong> {
    if length > 0xFFFE {
        return Err(ExporterTooLong);
    }
    let mut ctx = Vec::new();
    crate::frame::frame_into(&mut ctx, &transcript_hash(profile, label));
    crate::frame::frame_into(&mut ctx, &transcript_hash(profile, context));

    let mut d = Deck::init(profile);
    d.absorb(b"secret", exp_master);
    let mut f = d.fork(b"exporter", suite);
    f.absorb(b"context", &ctx);
    Ok(Zeroizing::new(f.squeeze(b"out", length)))
}

/// A `TLS-Exporter` request exceeded `0xFFFE` octets (draft §3, §5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExporterTooLong;

/// Resumption PSK for a NewSessionTicket (draft §5.7).
pub fn resumption_psk(
    profile: &Profile,
    res_master: &[u8],
    suite: u16,
    ticket_nonce: &[u8],
) -> Secret {
    let mut d = Deck::init(profile);
    d.absorb(b"secret", res_master);
    let mut f = d.fork(b"resumption", suite);
    f.absorb(b"context", ticket_nonce);
    Zeroizing::new(f.squeeze(b"out", 64))
}

/// ECH acceptance confirmation (draft §5.8). Pass the raw `ech_conf_messages`
/// range; this reduces it with `TranscriptHash` (RFC 9849's `transcript_ech_conf`).
pub fn ech_accept_confirmation(
    profile: &Profile,
    client_hello_inner_random: &[u8],
    selected_suite: u16,
    ech_conf_messages: &[u8],
) -> Vec<u8> {
    let th = transcript_hash(profile, ech_conf_messages);
    mac(
        profile,
        client_hello_inner_random,
        selected_suite,
        b"ech accept confirmation",
        &th,
        8,
    )
}

/// HRR ECH acceptance confirmation (draft §5.8).
pub fn hrr_ech_accept_confirmation(
    profile: &Profile,
    client_hello_inner_random: &[u8],
    selected_suite: u16,
    hrr_ech_conf_messages: &[u8],
) -> Vec<u8> {
    let th = transcript_hash(profile, hrr_ech_conf_messages);
    mac(
        profile,
        client_hello_inner_random,
        selected_suite,
        b"hrr ech accept confirmation",
        &th,
        8,
    )
}

/// Why a PSK import was rejected (draft §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PskImportError {
    /// `epsk` longer than `0xFFFE` octets — cannot be framed (draft §10, line 1421).
    EpskTooLong,
    /// `target_ciphersuite` is not a cipher suite of this document (draft §6, §10).
    UnknownTargetSuite,
    /// `external_identity` is empty, violating `opaque external_identity<1..2^16-1>`
    /// (draft §10).
    IdentityFieldOutOfRange,
    /// The serialized `ImportedIdentityV2` exceeds `0xFFFF` octets, so it would not
    /// fit `PskIdentity.identity<1..2^16-1>` — the whole serialization is offered
    /// as that identity (draft §10). This bounds `external_identity` + `context`
    /// together, not just each field.
    IdentityTooLong,
    /// `target_protocol` is not TLS 1.3 (`0x0304`) — the only value this document
    /// defines (draft §10).
    WrongTargetProtocol,
}

/// PSK import: derive `ipsk` from an external PSK for a `target` cipher suite
/// (draft §5.9, §10). `imported_identity_v2` is the serialized
/// `ImportedIdentityV2`.
///
/// Taking the whole `CipherSuite` (not a `Profile` plus a separate code point)
/// means the schedule profile is *derived from the suite*, so a profile/suite
/// mismatch is unrepresentable — matching the draft's rule that the profile is
/// selected solely by the cipher suite (draft §3, §4).
///
/// Enforces the §10 input checks: `target` must be one of the five suites of
/// this document, and `epsk` MUST NOT exceed `0xFFFE` octets (draft §10).
pub fn psk_import(
    target: &CipherSuite,
    epsk: &[u8],
    imported_identity_v2: &[u8],
) -> Result<Secret, PskImportError> {
    if epsk.len() > 0xFFFE {
        return Err(PskImportError::EpskTooLong);
    }
    if !suites::ALL.iter().any(|s| s == target) {
        return Err(PskImportError::UnknownTargetSuite);
    }
    let profile = &target.profile;
    let ctx = transcript_hash(profile, imported_identity_v2);
    let mut d = Deck::init(profile);
    d.absorb(b"secret", epsk);
    let mut f = d.fork(b"derived psk", target.code_point);
    f.absorb(b"context", &ctx);
    Ok(Zeroizing::new(f.squeeze(b"out", profile.secret_len)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::TURBOSHAKE256;
    use alloc::vec;

    #[test]
    fn record_key_split_lengths() {
        let ts = [7u8; 64];
        let (k, iv) = record_keys(&TURBOSHAKE256, &ts, 0xFF01, 16, 12);
        assert_eq!(k.len(), 16);
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn exporter_rejects_overlong() {
        let em = [0u8; 64];
        assert_eq!(
            exporter(&TURBOSHAKE256, &em, 0xFF01, b"l", b"c", 0xFFFF),
            Err(ExporterTooLong)
        );
    }

    #[test]
    fn finished_len_is_flen() {
        let vd = finished_verify_data(&TURBOSHAKE256, &[1u8; 64], 0xFF01, b"th");
        assert_eq!(vd.len(), TURBOSHAKE256.flen);
    }

    /// Draft §5.5: the binder MACs under the **binder** label (`"res binder"` /
    /// `"ext binder"`), NOT under `"finished"`. This pins the distinction so a
    /// future refactor can't quietly flatten `binder_verify_data` onto the
    /// Finished path — that would change the value (see the doc-comment warning).
    #[test]
    fn binder_mac_label_is_binder_not_finished() {
        let profile = &TURBOSHAKE256;
        let early = [7u8; 64];
        let suite = 0xFF01;
        let th_ch0 = b"TH_CH0";

        for (kind, binder_label) in [
            (BinderKind::Resumption, &b"res binder"[..]),
            (BinderKind::External, &b"ext binder"[..]),
        ] {
            let got = binder_verify_data(profile, &early, kind, suite, th_ch0);

            // Rebuild by hand: finished_key expanded under "finished", MAC under
            // the binder label. Must match `binder_verify_data`.
            let binder_key = expand(profile, &early, binder_label, suite, None, 64);
            let finished_key = expand(
                profile,
                &binder_key,
                b"finished",
                suite,
                None,
                profile.secret_len,
            );
            let under_binder_label = mac(
                profile,
                &finished_key,
                suite,
                binder_label,
                th_ch0,
                profile.flen,
            );
            assert_eq!(
                got, under_binder_label,
                "binder MACs under the binder label"
            );

            // The tempting "cleanup" — MAC under "finished" (the Finished label) —
            // must produce a DIFFERENT value.
            let under_finished_label = mac(
                profile,
                &finished_key,
                suite,
                b"finished",
                th_ch0,
                profile.flen,
            );
            assert_ne!(
                got, under_finished_label,
                "binder MAC label must not be flattened to \"finished\" (draft §5.5)",
            );
        }
    }

    /// §5.1: `None` and `Some(b"")` both omit the context Absorb, so they yield
    /// the same output; a non-empty context differs.
    #[test]
    fn expand_empty_context_omits() {
        let secret = [4u8; 64];
        let none = expand(&TURBOSHAKE256, &secret, b"lbl", 0xFF01, None, 64);
        let empty = expand(&TURBOSHAKE256, &secret, b"lbl", 0xFF01, Some(b""), 64);
        let some = expand(&TURBOSHAKE256, &secret, b"lbl", 0xFF01, Some(b"x"), 64);
        assert_eq!(none, empty);
        assert_ne!(none, some);
    }

    #[test]
    fn psk_import_checks() {
        let ts_suite = crate::suites::TLS_AES_128_GCM_TURBOSHAKE256;
        let epsk = [1u8; 32];

        // Overlong epsk is rejected rather than panicking in `frame` (draft §10).
        let huge = vec![0u8; 0xFFFF];
        assert_eq!(
            psk_import(&ts_suite, &huge, b"id"),
            Err(PskImportError::EpskTooLong)
        );

        // A fabricated / unregistered suite is rejected (draft §10). Because the
        // profile now comes from the suite, a profile/suite mismatch (e.g. a
        // SHAKE suite under the TurboSHAKE profile) is unrepresentable.
        let bogus = CipherSuite {
            code_point: 0x1301,
            name: "bogus",
            nk: 16,
            nn: 12,
            profile: TURBOSHAKE256,
        };
        assert_eq!(
            psk_import(&bogus, &epsk, b"id"),
            Err(PskImportError::UnknownTargetSuite)
        );

        // A valid import yields a SecretLen ipsk.
        let ok = psk_import(&ts_suite, &epsk, b"id").unwrap();
        assert_eq!(ok.len(), ts_suite.profile.secret_len);
    }
}
