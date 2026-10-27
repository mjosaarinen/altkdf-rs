//! ECH confirmation fixtures and live accepted 0-RTT early data.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::client::{EchConfig, EchMode, EchStatus};
use rustls::crypto::aws_lc_rs::hpke::DH_KEM_P256_HKDF_SHA256_AES_128;
use rustls::crypto::hpke::Hpke;
use rustls::deck_ech_confirmations_for_test;
use rustls::pki_types::EchConfigListBytes;
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

/// The live fork's ECH confirmation hooks reproduce the current appendix
/// values for both KDFs, including the HRR variant.
#[test]
fn deck_ech_confirmations_match_current_vectors() {
    let random: [u8; 32] = core::array::from_fn(|i| i as u8);
    for (suite_index, kdf, expected) in [
        (
            0,
            deck_schedule::TURBOSHAKE256,
            (
                [0x7d, 0xea, 0xf5, 0x76, 0xfa, 0x50, 0xbd, 0x88],
                [0x1e, 0x89, 0xc5, 0x4e, 0x87, 0xb6, 0xe4, 0x55],
            ),
        ),
        (
            3,
            deck_schedule::SHAKE256,
            (
                [0x46, 0xbe, 0x34, 0x0e, 0x18, 0x67, 0x3a, 0xb0],
                [0x1e, 0xe4, 0x41, 0xe5, 0x0a, 0x27, 0x62, 0xff],
            ),
        ),
    ] {
        let suite = deck_cipher_suites()[suite_index].tls13().unwrap();
        let sh = deck_schedule::transcript::transcript_hash(&kdf, b"ech_conf_messages");
        let hrr = deck_schedule::transcript::transcript_hash(&kdf, b"hrr_ech_conf_messages");
        assert_eq!(
            deck_ech_confirmations_for_test(suite, &random, &sh, &hrr),
            Some(expected),
            "{} ECH confirmations",
            kdf.name,
        );
    }
}

/// A deck client can send ECH with an XOF offer. An ordinary deck server
/// rejects ECH, and the client detects that rejection after checking the
/// confirmation under the selected XOF KDF.
fn ech_config() -> EchConfig {
    let suite: &dyn Hpke = DH_KEM_P256_HKDF_SHA256_AES_128;
    let (public_key, _) = suite.generate_key_pair().unwrap();
    let mut contents = vec![1, 0, 16]; // config_id, DHKEM(P-256, HKDF-SHA256)
    contents.extend_from_slice(&(public_key.0.len() as u16).to_be_bytes());
    contents.extend_from_slice(&public_key.0);
    contents.extend_from_slice(&[0, 4, 0, 1, 0, 1]); // one HPKE KDF/AEAD pair
    let public_name = b"public.example";
    contents.extend_from_slice(&[0, public_name.len() as u8]);
    contents.extend_from_slice(public_name);
    contents.extend_from_slice(&[0, 0]); // no ECHConfig extensions
    let mut config = vec![0xfe, 0x0d]; // ECHConfig version 18
    config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    config.extend_from_slice(&contents);
    let mut list = Vec::new();
    list.extend_from_slice(&(config.len() as u16).to_be_bytes());
    list.extend_from_slice(&config);
    EchConfig::new(EchConfigListBytes::from(list), &[suite]).unwrap()
}

#[test]
fn deck_ech_offer_reaches_confirmation_check() {
    let (certs, key) = self_signed();
    let mut ordinary = rustls::crypto::aws_lc_rs::default_provider();
    ordinary.kx_groups = deck_provider().kx_groups;
    let mut ordinary_hrr = rustls::crypto::aws_lc_rs::default_provider();
    ordinary_hrr.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    for (server_provider, hrr) in [
        (deck_provider(), false),
        (ordinary, false),
        (ordinary_hrr, true),
    ] {
        let provider = Arc::new(deck_provider());
        let verifier = accept_any_server_cert(provider.clone());
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_ech(EchMode::Enable(ech_config()))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let server_config = ServerConfig::builder_with_provider(Arc::new(server_provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key.clone_key())
            .unwrap();
        let mut client = ClientConnection::new(Arc::new(client_config), name()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        pump!(client => server);
        if hrr {
            pump!(server => client);
            pump!(client => server);
        }
        let mut flight = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut flight).unwrap();
        }
        let mut wire = flight.as_slice();
        while !wire.is_empty() {
            client.read_tls(&mut wire).unwrap();
        }
        let result = client.process_new_packets();
        assert_eq!(client.ech_status(), EchStatus::Rejected);
        assert!(matches!(
            result,
            Err(rustls::Error::PeerIncompatible(
                rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(_)
            ))
        ));
    }
}

#[test]
fn deck_ech_with_imported_psk_fails_before_client_hello() {
    let provider = Arc::new(deck_provider());
    let verifier = accept_any_server_cert(provider.clone());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_ech(EchMode::Enable(ech_config()))
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.deck_external_psk = Some(Arc::new(rustls::DeckExternalPsk::new(
        b"identity".to_vec(),
        vec![0x42; 32],
    )));
    assert!(matches!(
        ClientConnection::new(Arc::new(config), name()),
        Err(rustls::Error::General(message))
            if message == "imported external PSKs with ECH are not supported"
    ));
}

/// A deck client offered an early-data-capable ticket sends encrypted 0-RTT
/// bytes that the server decrypts before the resumed handshake finishes.
#[test]
fn deck_client_sends_accepted_0rtt_and_resumes() {
    let (certs, key) = self_signed();
    for kdf_id in [0x0100, 0x0101] {
        let mut provider = deck_provider();
        provider.cipher_suites.retain(|suite| {
            suite
                .tls13()
                .unwrap()
                .common
                .hash_provider
                .schedule_profile()
                == Some(kdf_id)
        });
        let provider = Arc::new(provider);

        // The server advertises early data in its tickets.
        let mut server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key.clone_key())
            .unwrap();
        server_config.max_early_data_size = 16384;
        let server_config = Arc::new(server_config);

        // Client opts into early data.
        let mut client_config = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(accept_any_server_cert(provider))
            .with_no_client_auth();
        client_config.enable_early_data = true;
        let client_config = Arc::new(client_config);

        // Handshake 1: full; the issued ticket advertises early data.
        let mut c1 = ClientConnection::new(client_config.clone(), name()).unwrap();
        let mut s1 = ServerConnection::new(server_config.clone()).unwrap();
        drive_handshake(&mut c1, &mut s1);
        assert!(c1.tls13_tickets_received() >= 1, "ticket issued");

        // Handshake 2: the client sends early application data before ServerHello.
        let mut c2 = ClientConnection::new(client_config.clone(), name()).unwrap();
        let mut s2 = ServerConnection::new(server_config.clone()).unwrap();
        let early_message = b"accepted XOF 0-RTT";
        c2.early_data()
            .expect("client has early-data-capable ticket")
            .write_all(early_message)
            .unwrap();
        pump!(c2 => s2);
        let mut early_received = vec![0u8; early_message.len()];
        s2.early_data()
            .expect("server accepted early data")
            .read_exact(&mut early_received)
            .unwrap();
        assert_eq!(early_received, early_message);
        drive_handshake(&mut c2, &mut s2);

        assert_eq!(c2.negotiated_schedule_profile(), Some(kdf_id));
        assert_eq!(
            c2.handshake_kind(),
            Some(HandshakeKind::Resumed),
            "deck client resumes after accepted 0-RTT",
        );
        assert!(c2.is_early_data_accepted());

        exchange(&mut c2, &mut s2, b"1-RTT after accepted 0-RTT");
    }
}
