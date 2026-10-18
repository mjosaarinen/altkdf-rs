//! Wire negotiation, downgrade policy, HRR pinning and KDF-bound PSKs.
use rustls::crypto::{aws_lc_rs, CryptoProvider};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{
    AlertDescription, ClientConfig, ClientConnection, Error, HandshakeKind, ServerConfig,
    ServerConnection,
};
use rustls_integration::{danger::accept_any_server_cert, deck_provider};
use std::{
    io::{Read, Write},
    sync::Arc,
};

fn provider(kdfs: &[u16], fallback: bool) -> CryptoProvider {
    let mut p = deck_provider();
    p.cipher_suites.retain(|s| {
        kdfs.contains(
            &s.tls13()
                .unwrap()
                .common
                .hash_provider
                .schedule_profile()
                .unwrap(),
        )
    });
    if fallback {
        p.cipher_suites
            .extend(aws_lc_rs::default_provider().cipher_suites);
    }
    p
}
fn client(p: CryptoProvider) -> ClientConfig {
    let verifier = accept_any_server_cert(Arc::new(p.clone()));
    ClientConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}
fn server(p: CryptoProvider) -> ServerConfig {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    ServerConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
        )
        .unwrap()
}
fn connections(c: Arc<ClientConfig>, s: Arc<ServerConfig>) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(c, ServerName::try_from("localhost").unwrap()).unwrap(),
        ServerConnection::new(s).unwrap(),
    )
}
macro_rules! wire {
    ($c:expr) => {{
        let mut b = Vec::new();
        while $c.wants_write() {
            $c.write_tls(&mut b).unwrap();
        }
        b
    }};
}
macro_rules! deliver {
    ($b:expr,$c:expr) => {{
        (|| -> Result<(), Error> {
            let mut rd = $b.as_slice();
            while !rd.is_empty() {
                $c.read_tls(&mut rd).unwrap();
                $c.process_new_packets()?;
            }
            Ok(())
        })()
    }};
}
fn finish(c: &mut ClientConnection, s: &mut ServerConnection) -> Result<(), Error> {
    for _ in 0..16 {
        let b = wire!(c);
        deliver!(b, s)?;
        let b = wire!(s);
        deliver!(b, c)?;
        if !c.is_handshaking() && !s.is_handshaking() {
            let b = wire!(s);
            deliver!(b, c)?;
            return Ok(());
        }
    }
    panic!("handshake stalled");
}
fn exchange(c: &mut ClientConnection, s: &mut ServerConnection) {
    c.writer().write_all(b"negotiated keys").unwrap();
    let b = wire!(c);
    deliver!(b, s).unwrap();
    let mut got = [0; 15];
    s.reader().read_exact(&mut got).unwrap();
    assert_eq!(&got, b"negotiated keys");
    let mut a = [0; 32];
    let mut b = [0; 32];
    c.export_keying_material(&mut a, b"test", Some(b"context"))
        .unwrap();
    s.export_keying_material(&mut b, b"test", Some(b"context"))
        .unwrap();
    assert_eq!(a, b);
}
fn retry_server(mut p: CryptoProvider) -> CryptoProvider {
    p.kx_groups = vec![aws_lc_rs::kx_group::X25519];
    p
}

fn assert_fatal_alert(records: &[u8], expected: AlertDescription) {
    let mut remaining = records;
    let mut alerts = 0;
    while !remaining.is_empty() {
        let len = u16::from_be_bytes([remaining[3], remaining[4]]) as usize;
        let payload = &remaining[5..5 + len];
        if remaining[0] == 21 {
            assert_eq!(payload, &[2, u8::from(expected)], "fatal alert");
            alerts += 1;
        }
        remaining = &remaining[5 + len..];
    }
    assert_eq!(alerts, 1, "expected one {expected:?} alert");
}

// CH2 can follow a compatibility CCS, so find its plaintext handshake record.
fn psk_identities(mut records: &[u8]) -> Vec<Vec<u8>> {
    while records[0] != 22 {
        let len = u16::from_be_bytes([records[3], records[4]]) as usize;
        records = &records[5 + len..];
    }
    let (mut pos, end) = extensions(records);
    while pos < end {
        let id = u16::from_be_bytes([records[pos], records[pos + 1]]);
        let len = u16::from_be_bytes([records[pos + 2], records[pos + 3]]) as usize;
        if id == 41 {
            let mut pos = pos + 4;
            let end = pos + 2 + u16::from_be_bytes([records[pos], records[pos + 1]]) as usize;
            pos += 2;
            let mut identities = Vec::new();
            while pos < end {
                let len = u16::from_be_bytes([records[pos], records[pos + 1]]) as usize;
                pos += 2;
                identities.push(records[pos..pos + len].to_vec());
                pos += len + 4; // obfuscated_ticket_age is not part of the identity.
            }
            assert_eq!(pos, end);
            return identities;
        }
        pos += 4 + len;
    }
    Vec::new()
}

#[test]
fn fallback_and_required_schedule_policy() {
    for (client_kdfs, server_kdfs) in [(&[0x100][..], &[][..]), (&[][..], &[0x101][..])] {
        let (mut c, mut s) = connections(
            Arc::new(client(provider(client_kdfs, true))),
            Arc::new(server(provider(server_kdfs, true))),
        );
        finish(&mut c, &mut s).unwrap();
        assert_eq!(c.negotiated_schedule_profile(), None);
        assert_eq!(s.negotiated_schedule_profile(), None);
        exchange(&mut c, &mut s);
    }
    let (mut c, mut s) = connections(
        Arc::new(client(provider(&[0x100], false))),
        Arc::new(server(provider(&[], true))),
    );
    assert!(
        finish(&mut c, &mut s).is_err(),
        "XOF-only provider requires negotiation"
    );
    assert_fatal_alert(&wire!(c), AlertDescription::HandshakeFailure);
}

#[test]
fn hrr_negotiates_and_pins_each_schedule() {
    for k in [0x100, 0x101] {
        let (mut c, mut s) = connections(
            Arc::new(client(provider(&[k], false))),
            Arc::new(server(retry_server(provider(&[k], false)))),
        );
        finish(&mut c, &mut s).unwrap();
        assert_eq!(
            c.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
        assert_eq!(c.negotiated_schedule_profile(), Some(k));
        assert_eq!(s.negotiated_schedule_profile(), Some(k));
        exchange(&mut c, &mut s);
    }
}

// Locate extensions in the first plaintext ServerHello/HRR record.
fn extensions(b: &[u8]) -> (usize, usize) {
    assert_eq!(b[0], 22);
    let mut pos = 44 + b[43] as usize;
    match b[5] {
        1 => {
            let suites = u16::from_be_bytes([b[pos], b[pos + 1]]) as usize;
            pos += 2 + suites;
            pos += 1 + b[pos] as usize;
        }
        2 => pos += 3,
        other => panic!("unexpected hello type {other}"),
    }
    let len = u16::from_be_bytes([b[pos], b[pos + 1]]) as usize;
    (pos + 2, pos + 2 + len)
}
fn rewrite_profile(b: &mut Vec<u8>, profile: Option<u16>) {
    let (start, end) = extensions(b);
    let mut pos = start;
    while pos < end {
        let id = u16::from_be_bytes([b[pos], b[pos + 1]]);
        let len = u16::from_be_bytes([b[pos + 2], b[pos + 3]]) as usize;
        if id == rustls::schedule_profile::EXTENSION_ID {
            if let Some(k) = profile {
                b[pos + 4..pos + 6].copy_from_slice(&k.to_be_bytes());
            } else {
                let removed = 4 + len;
                b.drain(pos..pos + removed);
                let extlen = (end - start - removed) as u16;
                b[start - 2..start].copy_from_slice(&extlen.to_be_bytes());
                let record_len = u16::from_be_bytes([b[3], b[4]]) - removed as u16;
                b[3..5].copy_from_slice(&record_len.to_be_bytes());
                let hslen = ((b[6] as usize) << 16) | ((b[7] as usize) << 8) | b[8] as usize;
                let hslen = (hslen - removed) as u32;
                b[6..9].copy_from_slice(&hslen.to_be_bytes()[1..]);
            }
            return;
        }
        pos += 4 + len;
    }
    if let Some(k) = profile {
        b.splice(
            end..end,
            [
                &rustls::schedule_profile::EXTENSION_ID.to_be_bytes()[..],
                &[0, 2],
                &k.to_be_bytes(),
            ]
            .concat(),
        );
        b[start - 2..start].copy_from_slice(&((end - start + 6) as u16).to_be_bytes());
        let record_len = u16::from_be_bytes([b[3], b[4]]) + 6;
        b[3..5].copy_from_slice(&record_len.to_be_bytes());
        let hslen = ((b[6] as u32) << 16) | ((b[7] as u32) << 8) | b[8] as u32;
        b[6..9].copy_from_slice(&(hslen + 6).to_be_bytes()[1..]);
    } else {
        panic!("profile extension missing");
    }
}

#[test]
fn unoffered_or_missing_profile_rejected_in_sh_and_hrr() {
    for retry in [false, true] {
        for replacement in [Some(0x9999), None] {
            let p = provider(&[0x100], false);
            let sp = if retry {
                retry_server(p.clone())
            } else {
                p.clone()
            };
            let (mut c, mut s) = connections(Arc::new(client(p)), Arc::new(server(sp)));
            let b = wire!(c);
            deliver!(b, s).unwrap();
            let mut b = wire!(s);
            rewrite_profile(&mut b, replacement);
            assert!(
                deliver!(b, c).is_err(),
                "must reject {replacement:?}, retry={retry}"
            );
            assert_fatal_alert(
                &wire!(c),
                if replacement.is_some() {
                    AlertDescription::IllegalParameter
                } else {
                    AlertDescription::HandshakeFailure
                },
            );
        }
    }
}

#[test]
fn server_cannot_change_kdf_after_hrr() {
    let (mut c, mut s) = connections(
        Arc::new(client(provider(&[0x100, 0x101], false))),
        Arc::new(server(retry_server(provider(&[0x100, 0x101], false)))),
    );
    let b = wire!(c);
    deliver!(b, s).unwrap();
    let b = wire!(s);
    deliver!(b, c).unwrap();
    let b = wire!(c);
    deliver!(b, s).unwrap();
    let mut b = wire!(s);
    rewrite_profile(&mut b, Some(0x101));
    assert!(
        deliver!(b, c).is_err(),
        "both offered, but HRR pinned 0x100"
    );
    assert_fatal_alert(&wire!(c), AlertDescription::IllegalParameter);
}

#[test]
fn server_cannot_omit_profile_after_hrr_even_when_client_requires_it() {
    for fallback in [false, true] {
        let (mut c, mut s) = connections(
            Arc::new(client(provider(&[0x100], fallback))),
            Arc::new(server(retry_server(provider(&[0x100], false)))),
        );
        let b = wire!(c);
        deliver!(b, s).unwrap();
        let b = wire!(s);
        deliver!(b, c).unwrap();
        let b = wire!(c);
        deliver!(b, s).unwrap();
        let mut b = wire!(s);
        rewrite_profile(&mut b, None);
        assert!(deliver!(b, c).is_err());
        assert_fatal_alert(&wire!(c), AlertDescription::IllegalParameter);
    }
}

#[test]
fn server_cannot_add_profile_after_hkdf_hrr() {
    let (mut c, mut s) = connections(
        Arc::new(client(provider(&[0x100], true))),
        Arc::new(server(retry_server(provider(&[], true)))),
    );
    let b = wire!(c);
    deliver!(b, s).unwrap();
    let b = wire!(s);
    deliver!(b, c).unwrap();
    let b = wire!(c);
    deliver!(b, s).unwrap();
    let mut b = wire!(s);
    rewrite_profile(&mut b, Some(0x100));
    assert!(deliver!(b, c).is_err());
    assert_fatal_alert(&wire!(c), AlertDescription::IllegalParameter);
}

#[test]
fn hrr_without_extension_pins_hkdf_and_required_client_aborts() {
    let (mut c, mut s) = connections(
        Arc::new(client(provider(&[0x100], true))),
        Arc::new(server(retry_server(provider(&[], true)))),
    );
    finish(&mut c, &mut s).unwrap();
    assert_eq!(
        c.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(c.negotiated_schedule_profile(), None);
    exchange(&mut c, &mut s);
    let (mut c, mut s) = connections(
        Arc::new(client(provider(&[0x100], false))),
        Arc::new(server(retry_server(provider(&[], true)))),
    );
    assert!(finish(&mut c, &mut s).is_err());
    assert_fatal_alert(&wire!(c), AlertDescription::HandshakeFailure);
}

fn only_aead(mut p: CryptoProvider, cp: u16) -> CryptoProvider {
    p.cipher_suites.retain(|s| u16::from(s.suite()) == cp);
    p
}

#[test]
fn resumption_can_change_aead_but_not_kdf() {
    for k in [0x100, 0x101] {
        let cfg = Arc::new(client(provider(&[k], false)));
        let first = server(only_aead(provider(&[k], false), 0x1301));
        let next_provider = only_aead(provider(&[k], false), 0x1303);
        // Config exposes no provider mutation; build with the alternate AEAD,
        // then explicitly share stateful ticket storage.
        let mut second = server(next_provider.clone());
        second.session_storage = first.session_storage.clone();
        let (mut c, mut s) = connections(cfg.clone(), Arc::new(first.clone()));
        finish(&mut c, &mut s).unwrap();
        assert!(c.tls13_tickets_received() > 0);
        let (mut c, mut s) = connections(cfg.clone(), Arc::new(second));
        finish(&mut c, &mut s).unwrap();
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Resumed));
        assert_eq!(
            u16::from(c.negotiated_cipher_suite().unwrap().suite()),
            0x1303
        );
        assert_eq!(c.negotiated_schedule_profile(), Some(k));
        exchange(&mut c, &mut s);
        let other = if k == 0x100 { 0x101 } else { 0x100 };
        let both = Arc::new(client(provider(&[k, other], false)));
        let (mut c, mut s) = connections(both.clone(), Arc::new(first.clone()));
        finish(&mut c, &mut s).unwrap();
        let mut second = server(provider(&[other], false));
        second.session_storage = first.session_storage.clone();
        let (mut c, mut s) = connections(both, Arc::new(second));
        finish(&mut c, &mut s).unwrap();
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(c.negotiated_schedule_profile(), Some(other));
    }
}

#[test]
fn hkdf_resumption_keeps_upstream_exact_suite_policy() {
    for early_data in [false, true] {
        let mut cc = client(provider(&[], true));
        cc.enable_early_data = early_data;
        let cc = Arc::new(cc);
        let mut first = server(only_aead(provider(&[], true), 0x1301));
        first.max_early_data_size = 1024;
        let first = Arc::new(first);
        let (mut c, mut s) = connections(cc.clone(), first.clone());
        finish(&mut c, &mut s).unwrap();
        assert!(c.tls13_tickets_received() > 0);

        let (mut c, mut s) = connections(cc.clone(), first.clone());
        finish(&mut c, &mut s).unwrap();
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Resumed));

        let mut second = server(only_aead(provider(&[], true), 0x1303));
        second.session_storage = first.session_storage.clone();
        second.max_early_data_size = 1024;
        let (mut c, mut s) = connections(cc, Arc::new(second));
        if early_data {
            c.early_data().unwrap().write_all(b"early data").unwrap();
        }
        finish(&mut c, &mut s).unwrap();
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(s.handshake_kind(), Some(HandshakeKind::Full));
        assert!(!c.is_early_data_accepted());
        assert_eq!(c.negotiated_schedule_profile(), None);
        assert_eq!(
            u16::from(c.negotiated_cipher_suite().unwrap().suite()),
            0x1303
        );
        exchange(&mut c, &mut s);
    }
}

#[test]
fn hrr_drops_incompatible_import_without_replacing_identity() {
    for original in [0x100, 0x101] {
        for selected in [None, Some(if original == 0x100 { 0x101 } else { 0x100 })] {
            let psk = Arc::new(rustls::DeckExternalPsk::new(
                b"provisioned identity".to_vec(),
                vec![7; 32],
            ));
            let mut p = provider(&[0x100, 0x101], selected.is_none());
            p.cipher_suites.sort_by_key(|s| {
                s.tls13().unwrap().common.hash_provider.schedule_profile() != Some(original)
            });
            let mut cc = client(p);
            cc.deck_external_psk = Some(psk.clone());
            let kdfs: Vec<_> = selected.into_iter().collect();
            let mut sc = server(retry_server(provider(&kdfs, selected.is_none())));
            sc.deck_external_psks = vec![psk];
            let (mut c, mut s) = connections(Arc::new(cc), Arc::new(sc));
            let ch1 = wire!(c);
            let identities = psk_identities(&ch1);
            assert_eq!(identities.len(), 1);
            assert_eq!(
                &identities[0][identities[0].len() - 2..],
                &original.to_be_bytes()
            );
            deliver!(ch1, s).unwrap();
            let hrr = wire!(s);
            deliver!(hrr, c).unwrap();
            let ch2 = wire!(c);
            assert!(
                psk_identities(&ch2).is_empty(),
                "HRR may remove, not replace, a PSK"
            );
            deliver!(ch2, s).unwrap();
            finish(&mut c, &mut s).unwrap();
            assert_eq!(
                c.handshake_kind(),
                Some(HandshakeKind::FullWithHelloRetryRequest)
            );
            assert_eq!(c.negotiated_schedule_profile(), selected);
            assert!(c.peer_certificates().is_some());
            exchange(&mut c, &mut s);
        }
    }
}

#[test]
fn hrr_cannot_replace_incompatible_ticket_with_external_psk() {
    for original in [0x100, 0x101] {
        let other = if original == 0x100 { 0x101 } else { 0x100 };
        let psk = Arc::new(rustls::DeckExternalPsk::new(
            b"provisioned identity".to_vec(),
            vec![7; 32],
        ));
        let mut cc = client(provider(&[0x100, 0x101], false));
        cc.deck_external_psk = Some(psk.clone());
        let cc = Arc::new(cc);
        let first = Arc::new(server(provider(&[original], false)));
        let (mut c, mut s) = connections(cc.clone(), first);
        finish(&mut c, &mut s).unwrap();
        assert!(c.tls13_tickets_received() > 0);

        let mut sc = server(retry_server(provider(&[other], false)));
        sc.deck_external_psks = vec![psk];
        let (mut c, mut s) = connections(cc, Arc::new(sc));
        let ch1 = wire!(c);
        assert_eq!(psk_identities(&ch1).len(), 1);
        deliver!(ch1, s).unwrap();
        let hrr = wire!(s);
        deliver!(hrr, c).unwrap();
        let ch2 = wire!(c);
        assert!(
            psk_identities(&ch2).is_empty(),
            "CH1 did not offer an external PSK"
        );
        deliver!(ch2, s).unwrap();
        finish(&mut c, &mut s).unwrap();
        assert_eq!(
            c.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        );
        assert_eq!(c.negotiated_schedule_profile(), Some(other));
        assert!(c.peer_certificates().is_some());
        exchange(&mut c, &mut s);
    }
}

#[test]
fn unsolicited_profile_rejected_in_sh_and_hrr() {
    for retry in [false, true] {
        let sp = provider(&[], true);
        let sp = if retry { retry_server(sp) } else { sp };
        let (mut c, mut s) =
            connections(Arc::new(client(provider(&[], true))), Arc::new(server(sp)));
        let b = wire!(c);
        deliver!(b, s).unwrap();
        let mut b = wire!(s);
        rewrite_profile(&mut b, Some(0x100));
        assert!(deliver!(b, c).is_err());
        assert_fatal_alert(&wire!(c), AlertDescription::UnsupportedExtension);
    }
}

#[test]
fn quic_omits_imported_psk_and_rejects_unsolicited_profile_in_hrr() {
    let mut cc = client(provider(&[0x100, 0x101], true));
    cc.deck_external_psk = Some(Arc::new(rustls::DeckExternalPsk::new(
        b"provisioned identity".to_vec(),
        vec![7; 32],
    )));
    let mut c = rustls::quic::ClientConnection::new(
        Arc::new(cc),
        rustls::quic::Version::V1,
        ServerName::try_from("localhost").unwrap(),
        Vec::new(),
    )
    .unwrap();
    let mut ch = Vec::new();
    assert!(c.write_hs(&mut ch).is_none());
    // Wrap QUIC handshake bytes solely to reuse the plaintext hello inspection
    // and TCP server's HRR construction; no QUIC key schedule runs here.
    let mut record = vec![22, 3, 3];
    record.extend_from_slice(&(ch.len() as u16).to_be_bytes());
    record.extend_from_slice(&ch);
    assert!(psk_identities(&record).is_empty());
    let mut s = ServerConnection::new(Arc::new(server(retry_server(provider(&[], true))))).unwrap();
    deliver!(record, s).unwrap();
    let mut hrr = wire!(s);
    rewrite_profile(&mut hrr, Some(0x100));
    let len = u16::from_be_bytes([hrr[3], hrr[4]]) as usize;
    assert!(c.read_hs(&hrr[5..5 + len]).is_err());
    assert_eq!(c.alert(), Some(AlertDescription::UnsupportedExtension));
}

#[test]
fn imported_psk_survives_hrr_and_aead_change() {
    for k in [0x100, 0x101] {
        let psk = Arc::new(rustls::DeckExternalPsk::new(
            b"provisioned identity".to_vec(),
            vec![7; 32],
        ));
        let mut cc = client(provider(&[k], false));
        cc.deck_external_psk = Some(psk.clone());
        let mut sc = server(retry_server(only_aead(provider(&[k], false), 0x1303)));
        sc.deck_external_psks = vec![psk];
        let (mut c, mut s) = connections(Arc::new(cc), Arc::new(sc));
        let ch1 = wire!(c);
        let identities = psk_identities(&ch1);
        assert_eq!(identities.len(), 1);
        deliver!(ch1, s).unwrap();
        let hrr = wire!(s);
        deliver!(hrr, c).unwrap();
        let ch2 = wire!(c);
        assert_eq!(psk_identities(&ch2), identities);
        deliver!(ch2, s).unwrap();
        finish(&mut c, &mut s).unwrap();
        assert_eq!(c.handshake_kind(), Some(HandshakeKind::Resumed));
        assert!(c.peer_certificates().is_none());
        assert_eq!(c.negotiated_schedule_profile(), Some(k));
        assert_eq!(
            u16::from(c.negotiated_cipher_suite().unwrap().suite()),
            0x1303
        );
        exchange(&mut c, &mut s);
    }
}

#[test]
fn malformed_ch_profile_lists_fail_cleanly() {
    for length in [0u16, 1, 3, 65535] {
        let (mut c, mut s) = connections(
            Arc::new(client(provider(&[0x100, 0x101], false))),
            Arc::new(server(provider(&[0x100, 0x101], false))),
        );
        let mut b = wire!(c);
        let (mut pos, end) = extensions(&b);
        let mut changed = false;
        while pos < end {
            let id = u16::from_be_bytes([b[pos], b[pos + 1]]);
            let len = u16::from_be_bytes([b[pos + 2], b[pos + 3]]) as usize;
            if id == rustls::schedule_profile::EXTENSION_ID {
                b[pos + 4..pos + 6].copy_from_slice(&length.to_be_bytes());
                changed = true;
                break;
            }
            pos += 4 + len;
        }
        assert!(changed);
        assert!(deliver!(b, s).is_err(), "malformed list length {length}");
        assert_fatal_alert(&wire!(s), AlertDescription::DecodeError);
    }
}

#[test]
fn hkdf_identifiers_in_ch_are_ignored() {
    let (mut c, mut s) = connections(
        Arc::new(client(provider(&[0x100, 0x101], true))),
        Arc::new(server(provider(&[0x100, 0x101], true))),
    );
    let mut b = wire!(c);
    let (mut pos, end) = extensions(&b);
    let mut changed = false;
    while pos < end {
        let id = u16::from_be_bytes([b[pos], b[pos + 1]]);
        let len = u16::from_be_bytes([b[pos + 2], b[pos + 3]]) as usize;
        if id == rustls::schedule_profile::EXTENSION_ID {
            b[pos + 6..pos + 10].copy_from_slice(&[0, 1, 0, 2]);
            changed = true;
            break;
        }
        pos += 4 + len;
    }
    assert!(changed);
    deliver!(b, s).unwrap();
    assert_eq!(s.negotiated_schedule_profile(), None);
}
