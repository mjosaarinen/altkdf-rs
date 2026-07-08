//! # tls-demo
//!
//! A live TLS 1.3 handshake on a deck cipher suite (draft §6), driven by the
//! [`rustls_integration`] fork. This library holds the pieces the `deck-server`
//! / `deck-client` binaries and the loopback integration test share: demo config
//! builders and a [`CapturingKeyLog`] that records the NSS-format key-log lines
//! rustls emits, so a test can cross-check that both peers logged **identical**
//! deck secrets (draft §2.1, §5.3, §7.3) without a packet capture.
//!
//! The binaries additionally honor `SSLKEYLOGFILE` (via [`rustls::KeyLogFile`]),
//! so a real run can be decrypted in Wireshark. Certificate authentication uses
//! an accept-any verifier ([`rustls_integration::danger`]) that still performs
//! the real signature check — PKI is out of the draft's scope (draft §15.5).

use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, KeyLog, ServerConfig};
use rustls_integration::danger::accept_any_server_cert;
use rustls_integration::{deck_client_config, deck_provider, deck_server_config};

/// The ALPN protocol the demo negotiates, to show ALPN works over a deck suite.
pub const DEMO_ALPN: &[u8] = b"deck-demo";

/// One NSS-format key-log line: `label`, the connection's `client_random`, and
/// the logged `secret` (deck traffic/exporter secrets are 64 octets — SecretLen,
/// draft §8, §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyLogLine {
    pub label: String,
    pub client_random: Vec<u8>,
    pub secret: Vec<u8>,
}

/// A [`KeyLog`] that captures every logged secret in memory, so a test can read
/// them back and compare the two peers' views. (The binaries use
/// [`rustls::KeyLogFile`] instead, for Wireshark.)
#[derive(Debug, Default)]
pub struct CapturingKeyLog {
    lines: Mutex<Vec<KeyLogLine>>,
}

impl CapturingKeyLog {
    /// A fresh capturing key log, shareable into a rustls config.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A snapshot of every line logged so far.
    pub fn lines(&self) -> Vec<KeyLogLine> {
        self.lines.lock().unwrap().clone()
    }

    /// The most recently logged secret for `label`, if any (each TLS 1.3 label
    /// is logged once per connection).
    pub fn secret_for(&self, label: &str) -> Option<Vec<u8>> {
        self.lines()
            .into_iter()
            .rev()
            .find(|l| l.label == label)
            .map(|l| l.secret)
    }
}

impl KeyLog for CapturingKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        self.lines.lock().unwrap().push(KeyLogLine {
            label: label.to_string(),
            client_random: client_random.to_vec(),
            secret: secret.to_vec(),
        });
    }
}

/// A fresh self-signed `localhost` certificate + PKCS#8 key (ECDSA-P256, rcgen's
/// default) for the demo server.
pub fn self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed cert");
    let cert_der = cert.der().clone();
    let key_der: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
    (vec![cert_der], key_der)
}

/// A demo [`ServerConfig`]: the deck server config (deck suites only, tickets
/// disabled — [`deck_server_config`]) plus the demo ALPN and a `key_log`.
pub fn demo_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
    key_log: Arc<dyn KeyLog>,
) -> ServerConfig {
    let mut config = deck_server_config(cert_chain, key_der).expect("deck server config");
    config.alpn_protocols = vec![DEMO_ALPN.to_vec()];
    config.key_log = key_log;
    config
}

/// A demo [`ClientConfig`]: the deck client config (resumption disabled,
/// accept-any verifier — [`deck_client_config`]) plus the demo ALPN and a
/// `key_log`.
pub fn demo_client_config(key_log: Arc<dyn KeyLog>) -> ClientConfig {
    let verifier = accept_any_server_cert(Arc::new(deck_provider()));
    let mut config = deck_client_config(verifier);
    config.alpn_protocols = vec![DEMO_ALPN.to_vec()];
    config.key_log = key_log;
    config
}
