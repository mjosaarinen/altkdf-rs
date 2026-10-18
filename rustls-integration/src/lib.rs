//! DeckTLS glue for the combined `draft-sullivan-tls-xof-schedule` PRs #2/#3.
//!
//! Internal virtual suites reuse standard AEAD code points and negotiate the
//! KDF in `schedule_profile` (`[cipher-suites]`). The explicit hash metadata,
//! not the SHA512 output-size tag, selects the XOF and PSK compatibility.
//! The helpers require an XOF schedule, enable 1-RTT resumption, and decline
//! 0-RTT. ECH, QUIC and live hybrid groups are outside this prototype's scope.

pub mod hash;
pub mod suites;

// Re-exported so downstream code (and the loopback test) can reach the schedule
// crate and the forked rustls through one dependency.
pub use deck_schedule;
pub use rustls;

/// Low-level XOF provider: both KDFs over three standard AEADs.
/// Use the config helpers for TLS 1.3 defaults. A provider with only virtual
/// suites requires XOF negotiation; add ordinary suites to permit HKDF fallback.
pub fn deck_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        cipher_suites: suites::deck_cipher_suites(),
        kx_groups: deck_kx_groups().to_vec(),
        ..rustls::crypto::aws_lc_rs::default_provider()
    }
}

/// TLS 1.3 server requiring an XOF KDF, with 1-RTT tickets on and 0-RTT off.
pub fn deck_server_config(
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, rustls::Error> {
    let mut config =
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(deck_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)?;
    // 1-RTT resumption stays on (rustls default tickets). 0-RTT is deferred
    // (draft [zero-rtt]): no early data is ever accepted.
    config.max_early_data_size = 0;
    Ok(config)
}

/// TLS 1.3 client requiring an XOF KDF, with 1-RTT resumption on and 0-RTT off.
pub fn deck_client_config(
    verifier: std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier>,
) -> rustls::ClientConfig {
    let mut config =
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(deck_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("deck provider supports TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
    // 1-RTT resumption stays on (rustls default store). 0-RTT is deferred
    // (draft [zero-rtt]): the client offers no early data.
    config.enable_early_data = false;
    config
}

/// Insecure verifiers for loopback demos and tests. **Never use in production.**
pub mod danger {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    /// A [`ServerCertVerifier`] that accepts **any** certificate chain but still
    /// performs the real TLS 1.3 / 1.2 CertificateVerify signature check,
    /// delegated to `provider`'s `signature_verification_algorithms`.
    ///
    /// It skips all identity and trust-chain validation, so it is **insecure**
    /// and exists only to exercise the deck key schedule over a loopback where
    /// PKI is out of the draft's scope (draft `[authentication]`). Keeping the signature check
    /// live means the CertificateVerify over the deck transcript hash (draft `[transcript-hash]`)
    /// is genuinely validated, so the schedule — not a stubbed verifier — is what
    /// the test relies on.
    pub fn accept_any_server_cert(provider: Arc<CryptoProvider>) -> Arc<dyn ServerCertVerifier> {
        Arc::new(AcceptAnyServerCert { provider })
    }

    #[derive(Debug)]
    struct AcceptAnyServerCert {
        provider: Arc<CryptoProvider>,
    }

    impl ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

/// The raw aws-lc-rs default provider, exposed as a smoke check: its `kx_groups`
/// include the `X25519MLKEM768` **hybrid** and omit pure `MLKEM768`, so the deck
/// provider overrides `kx_groups` with [`deck_kx_groups`] rather than use this as its base.
#[doc(hidden)]
pub fn aws_lc_rs_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

/// Single-component key exchanges: pure ML-KEM768, X25519 and secp256r1.
/// Hybrids need ordered component extraction that the backend does not expose.
pub fn deck_kx_groups() -> [&'static dyn rustls::crypto::SupportedKxGroup; 3] {
    use rustls::crypto::aws_lc_rs::kx_group::{MLKEM768, SECP256R1, X25519};
    [MLKEM768, X25519, SECP256R1]
}

#[cfg(test)]
mod tests {
    use crate::hash::{DeckHash, SHAKE256_HASH, TURBOSHAKE256_HASH};
    use rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256;
    use rustls::crypto::CipherSuiteCommon;
    use rustls::{CipherSuite, Tls13CipherSuite};

    #[test]
    fn aws_lc_rs_backed_rustls_links() {
        let provider = super::aws_lc_rs_provider();
        assert!(
            !provider.cipher_suites.is_empty(),
            "aws-lc-rs provider should register cipher suites"
        );
        // Pure ML-KEM is available as a standalone kx group for the deck's
        // single-component key exchange (draft-ietf-tls-mlkem). It is not in the
        // default provider's groups — the default offers only the X25519MLKEM768
        // hybrid — so the deck provider assembles a custom provider that includes it.
        assert_eq!(
            rustls::crypto::aws_lc_rs::kx_group::MLKEM768.name(),
            rustls::NamedGroup::MLKEM768,
        );
        // The deck reference schedule is reachable through this crate.
        let _ = deck_schedule::TURBOSHAKE256;
    }

    #[test]
    fn deck_kx_groups_exclude_hybrids() {
        use rustls::crypto::aws_lc_rs::kx_group;
        let names: Vec<_> = super::deck_kx_groups().iter().map(|g| g.name()).collect();

        assert!(
            names.contains(&kx_group::MLKEM768.name()),
            "pure ML-KEM present"
        );
        assert!(names.contains(&kx_group::X25519.name()));
        assert!(names.contains(&kx_group::SECP256R1.name()));
        assert!(
            !names.contains(&kx_group::X25519MLKEM768.name()),
            "hybrid X25519MLKEM768 must be excluded"
        );
        assert!(
            !names.contains(&kx_group::SECP256R1MLKEM768.name()),
            "hybrid SECP256R1MLKEM768 must be excluded"
        );
    }

    fn deck_suite(code: u16, hash: &'static DeckHash) -> &'static Tls13CipherSuite {
        let base = TLS13_AES_128_GCM_SHA256.tls13().unwrap();
        Box::leak(Box::new(Tls13CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::Unknown(code),
                hash_provider: hash,
                confidentiality_limit: base.common.confidentiality_limit,
            },
            hkdf_provider: base.hkdf_provider,
            aead_alg: base.aead_alg,
            quic: base.quic,
        }))
    }

    #[test]
    fn deck_resumption_requires_same_kdf() {
        let ff01 = deck_suite(0x1301, &TURBOSHAKE256_HASH);
        let ff02 = deck_suite(0x1302, &TURBOSHAKE256_HASH); // same profile, other AEAD
        let ff04 = deck_suite(0x1301, &SHAKE256_HASH); // other profile
        let real = TLS13_AES_128_GCM_SHA256.tls13().unwrap();

        // AEADs may change within one KDF; profiles cannot alias.
        assert!(ff01.can_resume_from(ff01).is_some(), "exact suite");
        assert!(
            ff01.can_resume_from(ff02).is_some(),
            "same profile, diff suite"
        );
        assert!(
            ff01.can_resume_from(ff04).is_none(),
            "cross profile alias blocked"
        );

        // Deck and real suites never resume from each other, both directions.
        assert!(ff01.can_resume_from(real).is_none());
        assert!(real.can_resume_from(ff01).is_none());

        // Real-suite behavior is unchanged (RFC 8446 same-hash rule intact).
        assert!(
            real.can_resume_from(real).is_some(),
            "real self-resume intact"
        );
    }

    #[test]
    fn deck_schedule_matches_reference() {
        use deck_schedule::schedule::{run, ScheduleInputs};
        use deck_schedule::{Protocol, TURBOSHAKE256};
        use rustls::deck_schedule_selftest;

        let suite = deck_suite(0x1301, &TURBOSHAKE256_HASH);
        let dhe = vec![0x42u8; 32];
        let th_sh = vec![0x11u8; 64];
        let th_sf = vec![0x22u8; 64];
        let th_cf = vec![0x33u8; 64];
        let fin = vec![0x44u8; 64];

        let got = deck_schedule_selftest(suite, &dhe, &th_sh, &th_sf, &th_cf, &fin);

        let dhe_ref: &[&[u8]] = &[&dhe];
        let want = run(
            TURBOSHAKE256,
            Protocol::Tls13,
            &ScheduleInputs {
                psk: None,
                dhe_components: dhe_ref,
                th_ch: &[],
                th_sh: &th_sh,
                th_sf: &th_sf,
                th_cf: &th_cf,
            },
        )
        .unwrap();

        assert_eq!(got.c_hs_traffic, want.c_hs_traffic, "c hs traffic");
        assert_eq!(got.s_hs_traffic, want.s_hs_traffic, "s hs traffic");
        assert_eq!(got.c_ap_traffic, want.c_ap_traffic, "c ap traffic");
        assert_eq!(got.s_ap_traffic, want.s_ap_traffic, "s ap traffic");
        assert_eq!(got.exp_master, want.exp_master, "exp master");
        assert_eq!(got.res_master, want.res_master, "res master");

        // Finished MAC and record keys route to the matching deck derivations.
        assert_eq!(
            got.server_finished,
            deck_schedule::derive::finished_verify_data(
                TURBOSHAKE256,
                Protocol::Tls13,
                &deck_schedule::derive::handshake_record(
                    TURBOSHAKE256,
                    Protocol::Tls13,
                    &got.s_hs_traffic,
                    16,
                    12
                )
                .0,
                &fin,
            ),
            "server Finished verify_data",
        );
        let (_, keys) = deck_schedule::derive::handshake_record(
            TURBOSHAKE256,
            Protocol::Tls13,
            &got.s_hs_traffic,
            16,
            12,
        );
        let (rk, riv) = (keys.key, keys.iv);
        // `record_keys` now returns zeroize-on-drop `Secret`s; compare the bytes.
        assert_eq!(got.record_key, *rk, "record write_key");
        assert_eq!(got.record_iv, *riv, "record write_iv");
    }
}
