//! Live TLS 1.3 handshake authenticated by an **out-of-band external PSK** on a
//! deck cipher suite (draft §10), end to end over two forked rustls peers.
//!
//! The client imports an external PSK (`epsk` + `external_identity`) for its
//! target deck suite into an `ipsk` (draft §5.9), offers the serialized
//! `ImportedIdentityV2` as the `PskIdentity.identity`, and computes the
//! **external** PSK binder (`"ext binder"`, draft §5.5). The server, configured
//! with the same external PSK, re-imports it for the suite it selects, matches
//! the offered identity, verifies the external binder, and completes a 1-RTT
//! PSK + (EC)DHE handshake — **no server Certificate** (the PSK authenticates).
//!
//! This exercises the parts of the deck external-PSK path that the derivation/
//! encoding tests (`deck-schedule`) cannot: the live wire offer, the server-side
//! import + identity match, the external binder over the real (truncated)
//! ClientHello transcript, and the imported `ipsk` keying the early stage.
//!
//! Two tests: [`external_psk_handshake_succeeds`] (the happy path) and
//! [`external_psk_wrong_secret_fails_binder`] (a server provisioned with a
//! different `epsk` computes a different `ipsk`, so the binder does not verify
//! and the handshake is rejected — proving the binder is genuinely checked).

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, DeckExternalPsk, HandshakeKind, ServerConfig, ServerConnection,
};
use rustls_integration::danger::accept_any_server_cert;
use rustls_integration::{deck_provider, deck_server_config};

/// Move all currently-pending TLS records from `$from` into `$to`.
macro_rules! pump {
    ($from:expr => $to:expr) => {
        // An IIFE so the `?` on `process_new_packets` is contained: `pump!` is a
        // `Result<(), rustls::Error>` expression the caller `?`s or `.unwrap()`s.
        (|| -> Result<(), rustls::Error> {
            let mut buf = Vec::new();
            while $from.wants_write() {
                $from.write_tls(&mut buf).unwrap();
            }
            let mut rd: &[u8] = &buf;
            let mut guard = 0;
            while !rd.is_empty() {
                $to.read_tls(&mut rd).unwrap();
                $to.process_new_packets()?;
                guard += 1;
                assert!(guard < 10_000, "read_tls stalled");
            }
            Ok(())
        })()
    };
}

fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let key: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
    (vec![cert.der().clone()], key)
}

fn name() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

/// A deck client config carrying `psk` as an out-of-band external PSK, with
/// resumption disabled (so a fresh client offers the external PSK, never a
/// ticket).
fn external_psk_client_config(psk: DeckExternalPsk) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(deck_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(accept_any_server_cert(Arc::new(deck_provider())))
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.deck_external_psk = Some(Arc::new(psk));
    Arc::new(config)
}

/// A deck server config that accepts `psks` as external PSKs (draft §10).
fn external_psk_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    psks: Vec<DeckExternalPsk>,
) -> Arc<ServerConfig> {
    let mut config = deck_server_config(certs, key).unwrap();
    config.deck_external_psks = psks.into_iter().map(Arc::new).collect();
    Arc::new(config)
}

/// Drive the handshake to completion (or the first error).
fn drive_handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), rustls::Error> {
    let mut rounds = 0;
    while client.is_handshaking() || server.is_handshaking() {
        pump!(client => server)?;
        pump!(server => client)?;
        rounds += 1;
        assert!(rounds < 32, "handshake did not converge");
    }
    Ok(())
}

#[test]
fn external_psk_handshake_succeeds() {
    let (certs, key) = self_signed();
    let psk = DeckExternalPsk::new(b"deck-external-identity".to_vec(), vec![0xABu8; 48]);

    let server_config = external_psk_server_config(certs, key, vec![psk.clone()]);
    let client_config = external_psk_client_config(psk);

    let mut client = ClientConnection::new(client_config, name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

    drive_handshake(&mut client, &mut server).expect("external-PSK handshake completes");

    // The external binder (draft §5.5) verified: the handshake is a PSK
    // resumption, 1-RTT, on both peers.
    assert_eq!(
        client.handshake_kind(),
        Some(HandshakeKind::Resumed),
        "client authenticated via the external PSK binder",
    );
    assert_eq!(
        server.handshake_kind(),
        Some(HandshakeKind::Resumed),
        "server accepted the external PSK",
    );

    // A PSK handshake sends no server Certificate — the PSK authenticates
    // (draft §10; RFC 8446 §2.2). So the client sees no peer certificate.
    assert!(
        client.peer_certificates().is_none(),
        "external-PSK handshake carries no server certificate",
    );

    // Negotiated on a deck suite (the target suite the identity bound).
    let suite = u16::from(client.negotiated_cipher_suite().unwrap().suite());
    assert!(
        (0xFF01..=0xFF05).contains(&suite),
        "negotiated a deck suite ({suite:#06x})",
    );

    // Application data flows on the external-PSK-authenticated connection.
    let msg = b"application data over an external-PSK deck handshake";
    client.writer().write_all(msg).unwrap();
    pump!(client => server).unwrap();
    let mut got = vec![0u8; msg.len()];
    server.reader().read_exact(&mut got).unwrap();
    assert_eq!(got, msg);
}

#[test]
fn external_psk_wrong_secret_fails_binder() {
    let (certs, key) = self_signed();
    let identity = b"deck-external-identity".to_vec();

    // Client and server share the identity but NOT the secret: the client offers a
    // binder over its `ipsk`; the server imports a different `ipsk` from its own
    // `epsk` (the identity is the same, since it encodes only external_identity +
    // target suite, not the secret), so the binder cannot verify.
    let client_psk = DeckExternalPsk::new(identity.clone(), vec![0x11u8; 48]);
    let server_psk = DeckExternalPsk::new(identity, vec![0x22u8; 48]);

    let server_config = external_psk_server_config(certs, key, vec![server_psk]);
    let client_config = external_psk_client_config(client_psk);

    let mut client = ClientConnection::new(client_config, name()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

    // The server must reject the mismatched binder (draft §5.5): the handshake
    // fails rather than completing or silently falling back.
    let result = drive_handshake(&mut client, &mut server);
    assert!(
        result.is_err(),
        "a wrong external-PSK secret must fail the binder check, not resume",
    );
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            rustls::Error::AlertReceived(_) | rustls::Error::PeerMisbehaved(_)
        ),
        "binder mismatch surfaces as an alert / peer-misbehaved error, got {err:?}",
    );
}
