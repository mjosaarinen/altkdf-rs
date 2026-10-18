//! Internal virtual suites: standard wire AEAD code point plus negotiated KDF.
//! Only the hash provider differs; the AEAD is reused from aws-lc-rs.
use crate::hash::{DeckHash, SHAKE256_HASH, TURBOSHAKE256_HASH};
use rustls::crypto::{aws_lc_rs, CipherSuiteCommon};
use rustls::{SupportedCipherSuite, Tls13CipherSuite};
use std::sync::OnceLock;

fn suites() -> &'static [SupportedCipherSuite; 6] {
    static SUITES: OnceLock<[SupportedCipherSuite; 6]> = OnceLock::new();
    SUITES.get_or_init(|| {
        std::array::from_fn(|i| {
            let source = [
                aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
                aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
                aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            ][i % 3]
                .tls13()
                .unwrap();
            let hash: &'static DeckHash = if i < 3 {
                &TURBOSHAKE256_HASH
            } else {
                &SHAKE256_HASH
            };
            SupportedCipherSuite::Tls13(Box::leak(Box::new(Tls13CipherSuite {
                common: CipherSuiteCommon {
                    suite: source.common.suite,
                    hash_provider: hash,
                    confidentiality_limit: source.common.confidentiality_limit,
                },
                hkdf_provider: source.hkdf_provider,
                aead_alg: source.aead_alg,
                quic: None,
            })))
        })
    })
}
/// Both KDFs over AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305.
/// CCM suites are represented by the core but not implemented by aws-lc-rs.
pub fn deck_cipher_suites() -> Vec<SupportedCipherSuite> {
    suites().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standard_wire_suites_and_independent_kdfs() {
        let suites = deck_cipher_suites();
        for (i, s) in suites.iter().enumerate() {
            assert_eq!(u16::from(s.suite()), 0x1301 + (i % 3) as u16);
            assert_eq!(
                s.tls13().unwrap().common.hash_provider.schedule_profile(),
                Some(if i < 3 { 0x0100 } else { 0x0101 })
            );
            assert_eq!(
                s.tls13().unwrap().aead_alg.key_len(),
                if i % 3 == 0 { 16 } else { 32 }
            );
        }
    }
}
