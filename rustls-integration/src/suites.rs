//! The five deck cipher suites `0xFF01..=0xFF05` as rustls `Tls13CipherSuite`s
//! (draft §6, Table 1).
//!
//! A cipher suite of the draft is `AEAD + ScheduleProfile`, and the profile
//! follows from the code point alone — there is no separate negotiation (draft
//! §3, §1.2). Each deck suite is therefore built by **reusing the aws-lc-rs AEAD
//! implementation** (draft §6: "the AEAD algorithms … are those of RFC 8446")
//! paired with the deck `TranscriptHash` provider for its profile
//! ([`DeckHash`], draft §2.1). The forked `KeySchedule` reads the profile off
//! the code point (`deck_profile`, draft §7.3) and calls `deck-schedule`
//! directly, so the suite object only has to carry the right AEAD and hash.
//!
//! Two fields of `Tls13CipherSuite` are inert for a deck suite:
//!
//! * `hkdf_provider` — required by the type but never invoked on the deck path
//!   (the schedule is deck-native, not HKDF; see the crate README). We borrow
//!   the base suite's provider so the field is well-formed.
//! * `quic` — `None`: QUIC is out of scope for deck suites (draft §13.1).
//!
//! Code points are the private-use placeholders of draft Appendix C, pending
//! IANA assignment (draft §14 OPEN ISSUE). They match `deck_schedule::suites`
//! and the fork's `deck_profile` routing (`0xFF01..=0xFF03` → TURBOSHAKE256,
//! `0xFF04..=0xFF05` → SHAKE256); a test below pins that agreement.

use std::sync::OnceLock;

use rustls::crypto::aws_lc_rs::cipher_suite::{
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
};
use rustls::{CipherSuite, CipherSuiteCommon, SupportedCipherSuite, Tls13CipherSuite};

use crate::hash::{DeckHash, SHAKE256_HASH, TURBOSHAKE256_HASH};

/// One deck suite: its code point, the aws-lc-rs suite whose AEAD (and, unused,
/// HKDF) it borrows, and the deck transcript-hash provider of its profile.
struct DeckSuiteSpec {
    code: u16,
    aead_source: SupportedCipherSuite,
    hash: &'static DeckHash,
}

/// The five deck suites in draft §6 order, matching `deck_schedule::suites::ALL`.
const SPECS: [DeckSuiteSpec; 5] = [
    DeckSuiteSpec {
        code: 0xFF01, // TLS_AES_128_GCM_TURBOSHAKE256
        aead_source: TLS13_AES_128_GCM_SHA256,
        hash: &TURBOSHAKE256_HASH,
    },
    DeckSuiteSpec {
        code: 0xFF02, // TLS_AES_256_GCM_TURBOSHAKE256
        aead_source: TLS13_AES_256_GCM_SHA384,
        hash: &TURBOSHAKE256_HASH,
    },
    DeckSuiteSpec {
        code: 0xFF03, // TLS_CHACHA20_POLY1305_TURBOSHAKE256
        aead_source: TLS13_CHACHA20_POLY1305_SHA256,
        hash: &TURBOSHAKE256_HASH,
    },
    DeckSuiteSpec {
        code: 0xFF04, // TLS_AES_128_GCM_SHAKE256
        aead_source: TLS13_AES_128_GCM_SHA256,
        hash: &SHAKE256_HASH,
    },
    DeckSuiteSpec {
        code: 0xFF05, // TLS_AES_256_GCM_SHAKE256
        aead_source: TLS13_AES_256_GCM_SHA384,
        hash: &SHAKE256_HASH,
    },
];

/// Build one deck `Tls13CipherSuite`, leaking it to obtain the `&'static` the
/// rustls API wants (these live for the process, like any suite static).
fn build(spec: &DeckSuiteSpec) -> &'static Tls13CipherSuite {
    // The aws-lc-rs AEAD sources are all TLS 1.3 suites, so `.tls13()` is `Some`.
    let base = spec
        .aead_source
        .tls13()
        .expect("aws-lc-rs AEAD source is a TLS 1.3 suite");
    Box::leak(Box::new(Tls13CipherSuite {
        common: CipherSuiteCommon {
            // rustls carries an unrecognized (here private-use) code point as
            // `CipherSuite::Unknown`; the fork keys deck policy off this value
            // (draft §4, §6). `deck_suite_cp` reads it back as `u16`.
            suite: CipherSuite::Unknown(spec.code),
            hash_provider: spec.hash,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        // Inert on the deck path (schedule is deck-native, draft §7.3).
        hkdf_provider: base.hkdf_provider,
        // RFC 8446 AEAD, reused (draft §6).
        aead_alg: base.aead_alg,
        // QUIC out of scope for deck suites (draft §13.1).
        quic: None,
    }))
}

/// The five deck cipher suites (draft §6), interned once for the process.
fn deck_suites() -> &'static [SupportedCipherSuite; 5] {
    static SUITES: OnceLock<[SupportedCipherSuite; 5]> = OnceLock::new();
    SUITES.get_or_init(|| std::array::from_fn(|i| SupportedCipherSuite::Tls13(build(&SPECS[i]))))
}

/// The five deck cipher suites (draft §6), in preference order `0xFF01..=0xFF05`
/// — the `cipher_suites` list for the deck [`CryptoProvider`](crate::deck_provider).
pub fn deck_cipher_suites() -> Vec<SupportedCipherSuite> {
    deck_suites().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every deck suite is registered under a `CipherSuite::Unknown(0xFF0x)`
    /// point, in the exact order and with the exact code points of the reference
    /// `deck_schedule::suites::ALL` (draft §6). This pins the two crates together.
    #[test]
    fn code_points_match_reference() {
        let got = deck_cipher_suites();
        assert_eq!(got.len(), deck_schedule::suites::ALL.len());
        for (cs, reference) in got.iter().zip(deck_schedule::suites::ALL.iter()) {
            assert_eq!(
                cs.suite(),
                CipherSuite::Unknown(reference.code_point),
                "suite order / code point matches {}",
                reference.name,
            );
        }
    }

    /// Each suite's reused AEAD has the key length the reference records as `Nk`
    /// (draft §6): the AEAD is what `deck_record_keys` splits `key‖iv` from, so a
    /// wrong AEAD would silently produce wrong-length record keys.
    #[test]
    fn aead_key_len_matches_reference_nk() {
        for (cs, reference) in deck_cipher_suites()
            .iter()
            .zip(deck_schedule::suites::ALL.iter())
        {
            let nk = cs.tls13().unwrap().aead_alg.key_len();
            assert_eq!(nk, reference.nk, "Nk for {}", reference.name);
        }
    }

    /// The profile split is `0xFF01..=0xFF03` TurboSHAKE256, `0xFF04..=0xFF05`
    /// SHAKE256 — both report the `SHA512` transcript-hash tag (the deck sentinel,
    /// draft §2.1), which the fork's exact-suite resumption rule relies on.
    #[test]
    fn all_deck_suites_report_sha512_tag() {
        use rustls::crypto::hash::HashAlgorithm;
        for cs in deck_cipher_suites() {
            assert_eq!(
                cs.tls13().unwrap().common.hash_provider.algorithm(),
                HashAlgorithm::SHA512,
            );
        }
    }
}
