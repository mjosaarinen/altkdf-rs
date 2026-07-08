//! # rustls-integration
//!
//! Wires the [`deck_schedule`] reference key schedule of
//! `draft-sullivan-tls-xof-ciphers-00` into a vendored [`rustls`] 0.23 fork, and
//! drives it over a live TLS 1.3 handshake.
//!
//! The draft changes *only* the key schedule — no wire format, no state machine
//! (draft §1.2) — so the integration is confined to a few seams (see
//! `../README.md`):
//!
//! - a [`rustls::crypto::hash::Hash`] provider backed by the deck
//!   `TranscriptHash` (draft §2.1);
//! - the five deck cipher suites `0xFF01..=0xFF05` (draft §6), reusing
//!   aws-lc-rs's AEADs;
//! - a forked `tls13::KeySchedule` that calls [`deck_schedule`] and absorbs
//!   `TH_SH` / `TH_SF` into the stage ratchets (draft §7.3), with the PSK binder
//!   parametrized by label for resumption *and* external PSKs (§5.5, §10);
//! - out-of-band external-PSK (§10) config surface — [`rustls::DeckExternalPsk`]
//!   plus `ClientConfig.deck_external_psk` / `ServerConfig.deck_external_psks` —
//!   for a live external-PSK handshake; and
//! - a [`rustls::crypto::CryptoProvider`] assembled from the above plus
//!   aws-lc-rs's key exchange (incl. pure ML-KEM), signature, and RNG providers.
//!
//! Two forked endpoints complete a live 1-RTT handshake on every deck suite, and
//! on a deck suite also session resumption and an external-PSK handshake (see
//! `tests/`). 0-RTT (§11) and ECH (§5.8) are not driven live: 0-RTT is declined at
//! negotiation (deferred scope) and ECH fails closed cleanly (rustls has no
//! server-side ECH to verify a confirmation against), rather than either
//! fabricating a result.
//!
//! This crate is a **prototype** tracking the draft; it is not a general-purpose
//! rustls provider.

pub mod hash;
pub mod suites;

// Re-exported so downstream code (and the loopback test) can reach the schedule
// crate and the forked rustls through one dependency.
pub use deck_schedule;
pub use rustls;

/// **Low-level building block.** The deck
/// [`CryptoProvider`](rustls::crypto::CryptoProvider): the five deck cipher
/// suites (draft §6) over the single-component key-exchange groups
/// ([`deck_kx_groups`]), reusing aws-lc-rs's signature-verification algorithms,
/// RNG, and key provider. The draft changes only the AEAD + key schedule (draft
/// §1.2), so everything outside `cipher_suites`/`kx_groups` is inherited from the
/// aws-lc-rs default provider unchanged.
///
/// # Note: prefer the config helpers
///
/// For a working deck endpoint use [`deck_server_config`] / [`deck_client_config`],
/// which apply the sane deck defaults (TLS 1.3, 1-RTT resumption on, 0-RTT off).
/// This bare provider is a **building block**: a `CryptoProvider` cannot encode
/// ticket/resumption/early-data policy (that lives on
/// [`ServerConfig`](rustls::ServerConfig) / [`ClientConfig`](rustls::ClientConfig)),
/// so a config built directly on it just takes rustls's defaults. Reach for
/// `deck_provider` to compose a provider (e.g. to borrow its
/// `signature_verification_algorithms` for a custom verifier) or to
/// restrict/reorder the offered suites. (0-RTT and ECH remain deferred and fail
/// closed regardless of config; draft §11, §5.8.)
pub fn deck_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        cipher_suites: suites::deck_cipher_suites(),
        kx_groups: deck_kx_groups().to_vec(),
        ..rustls::crypto::aws_lc_rs::default_provider()
    }
}

/// A TLS 1.3 deck [`ServerConfig`](rustls::ServerConfig) with the sane deck
/// defaults: **1-RTT session resumption enabled, 0-RTT (early data) off**.
///
/// The deck PSK binder (draft §5.5) is implemented, so this helper leaves
/// rustls's default TLS 1.3 tickets on (`send_tls13_tickets`), letting a client
/// resume — see `tests/resumption.rs`. Early data stays off
/// (`max_early_data_size = 0`): 0-RTT is deferred for deck suites (draft §11),
/// and the fork additionally skips the server early-traffic secret for them. The
/// provider offers only deck suites, so the connection always negotiates a deck
/// schedule profile (draft §6). For a deterministic no-ticket config (e.g. a
/// test that must see zero NewSessionTickets), set `send_tls13_tickets = 0` on
/// the returned value.
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
    // (draft §11): no early data is ever accepted.
    config.max_early_data_size = 0;
    Ok(config)
}

/// A TLS 1.3 deck [`ClientConfig`](rustls::ClientConfig) with the sane deck
/// defaults: **1-RTT session resumption enabled, 0-RTT (early data) off**.
///
/// The caller supplies the server-certificate `verifier` (a real
/// `WebPkiServerVerifier`, or an accept-any verifier for a loopback test); the
/// draft leaves authentication out of scope (draft §15.5). Client resumption is
/// left at rustls's default (an in-memory session store), so a stored ticket is
/// offered and resumed — the deck PSK binder (draft §5.5) is implemented; see
/// `tests/resumption.rs`. Early data stays off (`enable_early_data = false`):
/// 0-RTT is deferred (draft §11). To force no resumption, set
/// `resumption = rustls::client::Resumption::disabled()` on the returned value.
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
    // (draft §11): the client offers no early data.
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
    /// PKI is out of the draft's scope (draft §15.5). Keeping the signature check
    /// live means the CertificateVerify over the deck transcript hash (draft §2.1)
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

/// The raw aws-lc-rs default provider. Smoke check for M1 only: its `kx_groups`
/// include the `X25519MLKEM768` **hybrid** and omit pure `MLKEM768`, so M4 must
/// override `kx_groups` with [`deck_kx_groups`] rather than use this as its base.
#[doc(hidden)]
pub fn aws_lc_rs_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

/// The key-exchange groups the deck `CryptoProvider` offers (draft §7.3):
/// single-component only, so each `input_secret` is exactly one
/// `Absorb("dh", secret)`. Pure ML-KEM (`MLKEM768`, draft-ietf-tls-mlkem) plus
/// classical `X25519` and `secp256r1`.
///
/// Hybrids (`X25519MLKEM768`, `SECP256R1MLKEM768`) are deliberately excluded:
/// rustls flattens their two component secrets into one `SharedSecret`, which the
/// deck cannot split back into the draft's ordered per-component absorbs.
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

    /// The vendored rustls fork builds with the aws-lc-rs backend and exposes a
    /// provider (Stage 4 M1 baseline), including pure ML-KEM key exchange. Also
    /// confirms the deck crate is reachable.
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
        // hybrid — so M4 assembles a custom provider that includes it.
        assert_eq!(
            rustls::crypto::aws_lc_rs::kx_group::MLKEM768.name(),
            rustls::NamedGroup::MLKEM768,
        );
        // The deck reference schedule is reachable through this crate.
        let _ = deck_schedule::TURBOSHAKE256;
    }

    /// The deck key-exchange list is single-component only (draft §7.3): pure
    /// ML-KEM + classical, and NO hybrids (which rustls flattens into one
    /// `SharedSecret`, breaking the ordered per-component `Absorb("dh", …)`).
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

    /// A throwaway deck `Tls13CipherSuite` for the resumption-policy test: the
    /// deck `Hash` provider under a `0xFF0x` code point, reusing an aws-lc-rs
    /// suite's AEAD/HKDF (irrelevant to `can_resume_from`, which keys only on the
    /// hash tag and the suite value). `Box::leak` yields the `&'static` the API wants.
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

    /// DECK-FORK regression (draft §4, §15.2): deck suites are PSK/resumption
    /// compatible ONLY with the exact same cipher suite — not other suites of the
    /// same profile, and not across profiles — while real suites keep RFC 8446's
    /// same-hash rule. See `rustls/src/tls13/mod.rs::can_resume_from`.
    #[test]
    fn deck_resumption_requires_exact_suite() {
        let ff01 = deck_suite(0xFF01, &TURBOSHAKE256_HASH);
        let ff02 = deck_suite(0xFF02, &TURBOSHAKE256_HASH); // same profile, other AEAD
        let ff04 = deck_suite(0xFF04, &SHAKE256_HASH); // other profile
        let real = TLS13_AES_128_GCM_SHA256.tls13().unwrap();

        // Exact suite resumes; nothing else does.
        assert!(ff01.can_resume_from(ff01).is_some(), "exact suite");
        assert!(
            ff01.can_resume_from(ff02).is_none(),
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

    /// The forked rustls `KeySchedule`, driven through the no-PSK 1-RTT order its
    /// typestates use, derives exactly the secrets that `deck-schedule`'s one-shot
    /// `schedule::run` produces for the same inputs (draft §7.3). This validates
    /// the M3 wiring — the stage-boundary ordering (TH_SH → main ratchet, TH_SF
    /// retained, TH_CF at res master) — against the independent deck reference,
    /// not merely by peer agreement. Also checks the Finished MAC and record-key
    /// leaf ops route to the matching deck derivations (§5.3, §5.5).
    #[test]
    fn deck_schedule_matches_reference() {
        use deck_schedule::profile::TURBOSHAKE256;
        use deck_schedule::schedule::{run, ScheduleInputs};
        use rustls::deck_schedule_selftest;

        let suite = deck_suite(0xFF01, &TURBOSHAKE256_HASH);
        let dhe = vec![0x42u8; 32];
        let th_sh = vec![0x11u8; 64];
        let th_sf = vec![0x22u8; 64];
        let th_cf = vec![0x33u8; 64];
        let fin = vec![0x44u8; 64];

        let got = deck_schedule_selftest(suite, &dhe, &th_sh, &th_sf, &th_cf, &fin);

        let dhe_ref: &[&[u8]] = &[&dhe];
        let want = run(
            &TURBOSHAKE256,
            &ScheduleInputs {
                psk: None,
                dhe_components: dhe_ref,
                recorded_suite: 0xFF01,
                selected_suite: 0xFF01,
                th_ch: &[],
                th_sh: &th_sh,
                th_sf: &th_sf,
                th_cf: &th_cf,
            },
        );

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
                &TURBOSHAKE256,
                &got.s_hs_traffic,
                0xFF01,
                &fin,
            ),
            "server Finished verify_data",
        );
        let (rk, riv) =
            deck_schedule::derive::record_keys(&TURBOSHAKE256, &got.s_hs_traffic, 0xFF01, 16, 12);
        // `record_keys` now returns zeroize-on-drop `Secret`s; compare the bytes.
        assert_eq!(got.record_key, *rk, "record write_key");
        assert_eq!(got.record_iv, *riv, "record write_iv");
    }
}
