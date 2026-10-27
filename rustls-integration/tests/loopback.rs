//! Live 1-RTT handshakes for both XOF KDFs over the three backend AEADs.
//! Finished, CertificateVerify and bidirectional application data exercise the
//! negotiated transcript and schedule, with pure ML-KEM768 by default.

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
/// helpers, offering all six AEAD/KDF pairs. rustls selects in **client order** by
/// default (`ignore_client_order = false`), and both peers list the suites in the
/// same `0x1301..=0x1303` order, so the first-offered `0x1301`
/// (`TLS_AES_128_GCM_SHA256 + TLS13_TURBOSHAKE256`) is negotiated.
#[test]
fn loopback_public_helpers_negotiate_first_deck_suite() {
    let (certs, key) = self_signed();
    let server = deck_server_config(certs, key).unwrap();
    let client = deck_client_config(accept_any_server_cert(Arc::new(deck_provider())));

    let suite = drive(client, server);
    assert_eq!(
        u16::from(suite),
        0x1301,
        "first-offered deck suite is negotiated (client order)",
    );
}

/// The deck provider's first key-exchange group is pure ML-KEM768
/// (draft-ietf-tls-mlkem), so a default handshake actually runs the
/// post-quantum key exchange the design targets: one KEM shared secret absorbed
/// as a single `Absorb("shs_", …)` (draft `[key-schedule]`), no hybrid ordering.
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

/// Each of the six AEAD/KDF pairs completes a handshake on its own (both profiles,
/// all three AEADs), confirming the code point negotiates and the profile the
/// fork routes it to (draft `[cipher-suites]`, Table 1) produces working record keys.
#[test]
fn loopback_each_deck_suite() {
    for suite in deck_provider().cipher_suites {
        let cp = u16::from(suite.suite());
        let profile = suite
            .tls13()
            .unwrap()
            .common
            .hash_provider
            .schedule_profile();
        let server = server_config_on(provider_with(vec![suite]));
        let client = client_config_on(provider_with(vec![suite]));
        let (mut c, mut s) = handshake_only(client, server);
        assert_eq!(u16::from(c.negotiated_cipher_suite().unwrap().suite()), cp);
        assert_eq!(c.negotiated_schedule_profile(), profile);
        assert_eq!(s.negotiated_schedule_profile(), profile);
        c.writer().write_all(b"each AEAD/KDF").unwrap();
        pump!(c=>s);
        let mut got = [0; 13];
        s.reader().read_exact(&mut got).unwrap();
        assert_eq!(&got, b"each AEAD/KDF");
    }
}

/// Both backend hybrid groups complete XOF handshakes. Their component
/// boundaries are retained when the shared secret enters the schedule.
#[test]
fn loopback_hybrid_groups_under_both_kdfs() {
    use rustls::crypto::aws_lc_rs::kx_group::{SECP256R1MLKEM768, X25519MLKEM768};
    for group in [X25519MLKEM768, SECP256R1MLKEM768] {
        for suite_index in [0, 3] {
            let suite = deck_provider().cipher_suites[suite_index];
            let mut client_provider = provider_with(vec![suite]);
            client_provider.kx_groups = vec![group];
            let mut server_provider = provider_with(vec![suite]);
            server_provider.kx_groups = vec![group];
            let (mut client, mut server) = handshake_only(
                client_config_on(client_provider),
                server_config_on(server_provider),
            );
            assert_eq!(
                client.negotiated_key_exchange_group().map(|g| g.name()),
                Some(group.name()),
            );
            client.writer().write_all(b"hybrid XOF").unwrap();
            pump!(client => server);
            let mut received = [0u8; 10];
            server.reader().read_exact(&mut received).unwrap();
            assert_eq!(&received, b"hybrid XOF");
        }
    }
}

/// The deployment helpers default to **1-RTT resumption on, 0-RTT off**.
/// Field-level policy check plus a behavioral one: a live handshake through
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
