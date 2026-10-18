//! Full then resumed 1-RTT handshakes through explicit and helper configs.
//! These tests retain the AEAD; negotiation.rs tests cross-AEAD compatibility.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, HandshakeKind, ServerConfig, ServerConnection};
use rustls_integration::danger::accept_any_server_cert;
use rustls_integration::{deck_client_config, deck_provider, deck_server_config};

/// Move all currently-pending TLS records from `$from` into `$to`.
macro_rules! pump {
    ($from:expr => $to:expr) => {{
        let mut buf = Vec::new();
        while $from.wants_write() {
            $from.write_tls(&mut buf).unwrap();
        }
        let mut rd: &[u8] = &buf;
        let mut guard = 0;
        while !rd.is_empty() {
            $to.read_tls(&mut rd).unwrap();
            $to.process_new_packets().unwrap();
            guard += 1;
            assert!(guard < 10_000, "read_tls stalled");
        }
    }};
}

fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("rcgen");
    let key: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
    (vec![cert.der().clone()], key)
}

/// A deck server config with TLS 1.3 tickets **enabled** (rustls default
/// `send_tls13_tickets = 2` + stateful session storage), so it issues a
/// NewSessionTicket.
fn resumption_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(deck_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    )
}

/// A deck client config with resumption **enabled** (rustls default in-memory
/// session store). Reused across both handshakes so the second one offers the
/// ticket stored by the first.
fn resumption_client_config() -> Arc<ClientConfig> {
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(deck_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(accept_any_server_cert(Arc::new(deck_provider())))
            .with_no_client_auth(),
    )
}

fn name() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

/// Pump a handshake to completion, then flush post-handshake messages (the
/// server's NewSessionTicket) to the client.
fn drive_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    let mut rounds = 0;
    while client.is_handshaking() || server.is_handshaking() {
        pump!(client => server);
        pump!(server => client);
        rounds += 1;
        assert!(rounds < 32, "handshake did not converge");
    }
    pump!(server => client); // deliver NewSessionTicket(s)
}

/// One application-data round trip, proving the (resumed) connection's keys work.
fn exchange(client: &mut ClientConnection, server: &mut ServerConnection, msg: &[u8]) {
    client.writer().write_all(msg).unwrap();
    pump!(client => server);
    let mut got = vec![0u8; msg.len()];
    server.reader().read_exact(&mut got).unwrap();
    assert_eq!(got, msg, "resumed connection carries application data");
}

#[test]
fn deck_session_resumption_full_then_resumed() {
    let (certs, key) = self_signed();
    let server_config = resumption_server_config(certs, key);
    let client_config = resumption_client_config();

    // ---- Handshake 1: full handshake, server issues a ticket. ----
    let mut c1 = ClientConnection::new(client_config.clone(), name()).unwrap();
    let mut s1 = ServerConnection::new(server_config.clone()).unwrap();
    drive_handshake(&mut c1, &mut s1);

    assert_eq!(
        c1.handshake_kind(),
        Some(HandshakeKind::Full),
        "first handshake is full",
    );
    assert!(
        c1.peer_certificates().is_some(),
        "full handshake authenticates with a certificate",
    );
    assert!(
        c1.tls13_tickets_received() >= 1,
        "server issued a NewSessionTicket (resumption_psk, draft [expand-op])",
    );
    let first_suite = u16::from(c1.negotiated_cipher_suite().unwrap().suite());

    // ---- Handshake 2: same client config → offers the ticket → resumes. ----
    let mut c2 = ClientConnection::new(client_config.clone(), name()).unwrap();
    let mut s2 = ServerConnection::new(server_config.clone()).unwrap();
    drive_handshake(&mut c2, &mut s2);

    // The deck PSK binder (draft [finished-and-binder-mac]) was computed by the client and verified by
    // the server: before this landed, either side would have panicked closed.
    assert_eq!(
        c2.handshake_kind(),
        Some(HandshakeKind::Resumed),
        "second handshake resumed via the deck PSK binder",
    );
    assert_eq!(
        s2.handshake_kind(),
        Some(HandshakeKind::Resumed),
        "server accepted the resumption PSK",
    );

    // Same-AEAD resumption (draft [governing-profile], [governing-profile]): the resumed suite equals the
    // ticket's recorded suite, and it is a deck suite.
    let resumed_suite = u16::from(c2.negotiated_cipher_suite().unwrap().suite());
    assert_eq!(
        resumed_suite, first_suite,
        "resumed under the recorded suite"
    );
    assert!(
        (0x1301..=0x1303).contains(&resumed_suite),
        "resumed on a deck suite ({resumed_suite:#06x})",
    );

    // Application data flows on the resumed (PSK + (EC)DHE) connection.
    exchange(
        &mut c2,
        &mut s2,
        b"resumed application data over a deck suite",
    );
}

/// The same full → resumed flow, but built with the **public deployment helpers**
/// `deck_server_config` / `deck_client_config` (1-RTT resumption on, 0-RTT off)
/// rather than hand-rolled configs. Pins that the advertised helpers resume out
/// of the box.
#[test]
fn resumption_via_public_helpers() {
    let (certs, key) = self_signed();
    let server_config = Arc::new(deck_server_config(certs, key).unwrap());
    let client_config = Arc::new(deck_client_config(accept_any_server_cert(Arc::new(
        deck_provider(),
    ))));

    // Handshake 1: full, helper server issues a ticket.
    let mut c1 = ClientConnection::new(client_config.clone(), name()).unwrap();
    let mut s1 = ServerConnection::new(server_config.clone()).unwrap();
    drive_handshake(&mut c1, &mut s1);
    assert_eq!(c1.handshake_kind(), Some(HandshakeKind::Full));
    assert!(
        c1.tls13_tickets_received() >= 1,
        "deck_server_config issues a NewSessionTicket by default",
    );

    // Handshake 2: same client config resumes.
    let mut c2 = ClientConnection::new(client_config.clone(), name()).unwrap();
    let mut s2 = ServerConnection::new(server_config.clone()).unwrap();
    drive_handshake(&mut c2, &mut s2);
    assert_eq!(
        c2.handshake_kind(),
        Some(HandshakeKind::Resumed),
        "public deck helpers resume out of the box",
    );
    assert_eq!(s2.handshake_kind(), Some(HandshakeKind::Resumed));

    exchange(&mut c2, &mut s2, b"resumed via the public deck helpers");
}
