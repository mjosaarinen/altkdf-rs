//! Unsupported deck features fail **cleanly**, never by panic.
//!
//! The only deck features the fork does not implement are 0-RTT early data
//! (draft §11) and the ECH acceptance confirmation (draft §5.8). This test
//! triggers each remaining unsupported deck path and asserts no unwind:
//!
//! * **0-RTT** — a deck client offered an early-data-capable ticket resumes at
//!   1-RTT (it declines to offer early data), rather than reaching the
//!   unimplemented deck early-traffic secret.
//! * **ECH** — both acceptance-confirmation paths return an `Error`, not a panic.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::deck_ech_confirmations_fail_cleanly;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, HandshakeKind, ServerConfig, ServerConnection};
use rustls_integration::danger::accept_any_server_cert;
use rustls_integration::deck_provider;
use rustls_integration::suites::deck_cipher_suites;

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

fn name() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

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

fn exchange(client: &mut ClientConnection, server: &mut ServerConnection, msg: &[u8]) {
    client.writer().write_all(msg).unwrap();
    pump!(client => server);
    let mut got = vec![0u8; msg.len()];
    server.reader().read_exact(&mut got).unwrap();
    assert_eq!(got, msg);
}

/// ECH acceptance confirmation (draft §5.8) is unimplemented for deck suites and
/// **fails cleanly**: both the non-HRR (typestate method) and HRR (free function)
/// paths return an `Error`, not a panic. The hook exercises both and returns true
/// only if neither unwound.
#[test]
fn deck_ech_confirmations_fail_with_error_not_panic() {
    let suite = deck_cipher_suites()[0]
        .tls13()
        .expect("deck suite is TLS 1.3");
    assert!(
        deck_ech_confirmations_fail_cleanly(suite),
        "both deck ECH acceptance-confirmation paths (draft §5.8) must return an Error, not panic",
    );
}

/// A deck client offered an early-data-capable ticket **declines 0-RTT** and
/// resumes at 1-RTT (draft §11), instead of reaching the unimplemented deck
/// early-traffic secret. Before the gate, the second handshake would have
/// panicked; the assertion here is that it completes as an ordinary resumption.
#[test]
fn deck_client_declines_0rtt_and_resumes_at_1rtt() {
    let (certs, key) = self_signed();

    // Server ADVERTISES early data in its tickets (max_early_data_size > 0) — the
    // scenario that, without the deck 0-RTT gate, would drive the client into the
    // unimplemented early-traffic secret on resumption.
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(deck_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    server_config.max_early_data_size = 16384;
    let server_config = Arc::new(server_config);

    // Client opts INTO early data.
    let mut client_config = ClientConfig::builder_with_provider(Arc::new(deck_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(accept_any_server_cert(Arc::new(deck_provider())))
        .with_no_client_auth();
    client_config.enable_early_data = true;
    let client_config = Arc::new(client_config);

    // Handshake 1: full; the issued ticket advertises early data.
    let mut c1 = ClientConnection::new(client_config.clone(), name()).unwrap();
    let mut s1 = ServerConnection::new(server_config.clone()).unwrap();
    drive_handshake(&mut c1, &mut s1);
    assert!(c1.tls13_tickets_received() >= 1, "ticket issued");

    // Handshake 2: resumes, declining 0-RTT — and MUST NOT panic reaching the
    // unimplemented deck early-traffic secret.
    let mut c2 = ClientConnection::new(client_config.clone(), name()).unwrap();
    let mut s2 = ServerConnection::new(server_config.clone()).unwrap();
    drive_handshake(&mut c2, &mut s2);

    assert_eq!(
        c2.handshake_kind(),
        Some(HandshakeKind::Resumed),
        "deck client resumes at 1-RTT",
    );
    assert!(
        !c2.is_early_data_accepted(),
        "a deck suite never negotiates 0-RTT (draft §11)",
    );

    exchange(&mut c2, &mut s2, b"1-RTT resume, no 0-RTT");
}
