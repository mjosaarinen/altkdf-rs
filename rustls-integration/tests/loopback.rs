//! Stage 4 M4: a live loopback handshake on a deck cipher suite.
//!
//! Two forked-rustls endpoints — both on the deck [`CryptoProvider`] — complete
//! a no-PSK 1-RTT TLS 1.3 handshake over an in-memory transport and exchange
//! application data in both directions. This is the end-to-end proof that the
//! deck key schedule (draft §7.3) wired into rustls (Stage 4) is self-consistent:
//!
//! * A successful **Finished** exchange proves both peers derived identical
//!   handshake traffic secrets and the same deck `TranscriptHash` (draft §2.1,
//!   §5.5) — a mismatch is a `decrypt_error` alert, not a passing test.
//! * Decrypting **application data** each way proves identical application
//!   traffic secrets and record keys (draft §5.3).
//! * The negotiated suite is one of `0xFF01..=0xFF05`, confirming that rustls
//!   carries and selects the private-use code points as `CipherSuite::Unknown`
//!   (PLAN.md Stage 4 audit item).
//!
//! The key exchange is whatever the deck provider prefers first — pure
//! **ML-KEM768** (draft-ietf-tls-mlkem), the clean single-`Absorb("dh", …)` path
//! (draft §7.3) — so this also exercises the post-quantum key exchange the design
//! targets.
//!
//! Certificate verification is out of scope for the draft (draft §15.5); the
//! client uses an accept-any verifier that still delegates the real TLS 1.3
//! CertificateVerify signature check to the provider, so the signature over the
//! deck transcript hash is genuinely validated.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, ProtocolVersion, ServerConfig, ServerConnection,
    SupportedCipherSuite,
};

use rustls_integration::danger::accept_any_server_cert;
use rustls_integration::{deck_client_config, deck_provider, deck_server_config};

/// A fresh self-signed `localhost` certificate + PKCS#8 key for the server.
fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed cert");
    let cert_der = cert.der().clone();
    let key_der: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
    (vec![cert_der], key_der)
}

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
            assert!(guard < 10_000, "read_tls stalled with bytes remaining");
        }
    }};
}

/// Create both connections and pump only the handshake to completion over an
/// in-memory transport, returning them for post-handshake inspection. The
/// trailing `server -> client` flush delivers any post-handshake messages the
/// server queues on completion (e.g. NewSessionTicket) so the client observes
/// them.
fn handshake_only(
    client_config: ClientConfig,
    server_config: ServerConfig,
) -> (ClientConnection, ServerConnection) {
    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .expect("client connection");
    let mut server = ServerConnection::new(Arc::new(server_config)).expect("server connection");

    let mut rounds = 0;
    while client.is_handshaking() || server.is_handshaking() {
        pump!(client => server);
        pump!(server => client);
        rounds += 1;
        assert!(rounds < 32, "handshake did not converge in {rounds} rounds");
    }
    pump!(server => client);
    (client, server)
}

/// Drive `client` and `server` through a full handshake and a two-way
/// application-data exchange over an in-memory transport. Returns the negotiated
/// cipher suite (which both peers must agree on).
fn drive(client_config: ClientConfig, server_config: ServerConfig) -> CipherSuite {
    let (mut client, mut server) = handshake_only(client_config, server_config);

    // Both peers finished on TLS 1.3 and agree on the suite.
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    let negotiated = client
        .negotiated_cipher_suite()
        .expect("client negotiated a suite");
    assert_eq!(
        Some(negotiated),
        server.negotiated_cipher_suite(),
        "client and server agree on the cipher suite",
    );

    // Application data client -> server proves matching c_ap traffic keys.
    let c2s = b"deck-schedule loopback: client to server";
    client.writer().write_all(c2s).unwrap();
    pump!(client => server);
    let mut got = vec![0u8; c2s.len()];
    server.reader().read_exact(&mut got).unwrap();
    assert_eq!(&got, c2s, "server decrypted client application data");

    // Application data server -> client proves matching s_ap traffic keys.
    let s2c = b"deck-schedule loopback: server to client (larger payload) ******";
    server.writer().write_all(s2c).unwrap();
    pump!(server => client);
    let mut got = vec![0u8; s2c.len()];
    client.reader().read_exact(&mut got).unwrap();
    assert_eq!(&got, s2c, "client decrypted server application data");

    negotiated.suite()
}

/// A deck provider restricted to exactly the suites in `suites`.
fn provider_with(suites: Vec<SupportedCipherSuite>) -> CryptoProvider {
    CryptoProvider {
        cipher_suites: suites,
        ..deck_provider()
    }
}

fn server_config_on(provider: CryptoProvider) -> ServerConfig {
    let (certs, key) = self_signed();
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.send_tls13_tickets = 0;
    config
}

fn client_config_on(provider: CryptoProvider) -> ClientConfig {
    let verifier = accept_any_server_cert(Arc::new(provider.clone()));
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config
}

/// Full handshake through the **public** `deck_server_config` / `deck_client_config`
/// helpers, offering all five deck suites. rustls selects in **client order** by
/// default (`ignore_client_order = false`), and both peers list the suites in the
/// same `0xFF01..=0xFF05` order, so the first-offered `0xFF01`
/// (`TLS_AES_128_GCM_TURBOSHAKE256`) is negotiated.
#[test]
fn loopback_public_helpers_negotiate_first_deck_suite() {
    let (certs, key) = self_signed();
    let server = deck_server_config(certs, key).unwrap();
    let client = deck_client_config(accept_any_server_cert(Arc::new(deck_provider())));

    let suite = drive(client, server);
    assert_eq!(
        u16::from(suite),
        0xFF01,
        "first-offered deck suite is negotiated (client order)",
    );
}

/// The deck provider's first key-exchange group is pure ML-KEM768
/// (draft-ietf-tls-mlkem), so a default handshake actually runs the
/// post-quantum key exchange the design targets: one KEM shared secret absorbed
/// as a single `Absorb("dh", …)` (draft §7.3), no hybrid ordering.
#[test]
fn loopback_uses_pure_mlkem768_key_exchange() {
    use rustls::NamedGroup;

    let (client, _server) = handshake_only(
        client_config_on(deck_provider()),
        server_config_on(deck_provider()),
    );

    assert_eq!(
        client.negotiated_key_exchange_group().map(|g| g.name()),
        Some(NamedGroup::MLKEM768),
        "default deck handshake uses pure ML-KEM768",
    );
}

/// Each of the five deck suites completes a handshake on its own (both profiles,
/// all three AEADs), confirming the code point negotiates and the profile the
/// fork routes it to (draft §6, Table 1) produces working record keys.
#[test]
fn loopback_each_deck_suite() {
    for reference in deck_schedule::suites::ALL {
        let cp = reference.code_point;
        let only: Vec<SupportedCipherSuite> = deck_provider()
            .cipher_suites
            .into_iter()
            .filter(|cs| u16::from(cs.suite()) == cp)
            .collect();
        assert_eq!(only.len(), 1, "exactly one suite for {}", reference.name);

        let server = server_config_on(provider_with(only.clone()));
        let client = client_config_on(provider_with(only));
        let got = drive(client, server);
        assert_eq!(u16::from(got), cp, "negotiated {}", reference.name);
    }
}

/// The deployment helpers default to **1-RTT resumption on, 0-RTT off** (Stage
/// 6A). Field-level policy check plus a behavioral one: a live handshake through
/// the helpers issues a NewSessionTicket. The full offer-and-resume flow is
/// covered end-to-end in `tests/resumption.rs`.
#[test]
fn deck_helpers_default_to_1rtt_resumption_no_0rtt() {
    let (certs, key) = self_signed();
    let server = deck_server_config(certs, key).unwrap();
    // Policy: TLS 1.3 resumption tickets enabled; early data (0-RTT) disabled.
    assert!(
        server.send_tls13_tickets > 0,
        "1-RTT resumption tickets are enabled by default",
    );
    assert_eq!(
        server.max_early_data_size, 0,
        "0-RTT (early data) stays off"
    );

    // Behavioral: the server issues at least one ticket over a live handshake.
    let client = deck_client_config(accept_any_server_cert(Arc::new(deck_provider())));
    let (client, _server) = handshake_only(client, server);
    assert!(
        client.tls13_tickets_received() >= 1,
        "deck_server_config issues NewSessionTicket(s) for 1-RTT resumption",
    );
}
