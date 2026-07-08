//! Cipher suites and code points (draft §6, Appendix C).
//!
//! Five suites over two profiles. Code points are TBD (draft §14 OPEN ISSUE);
//! until IANA assigns them, and because every derived output binds the
//! governing cipher suite value, this crate and the draft's Appendix C use the
//! declared private-use placeholders `0xFF01..=0xFF05` (draft Appendix C).

use crate::profile::{Profile, SHAKE256, TURBOSHAKE256};

/// A cipher suite of this document: an AEAD plus a schedule profile (draft §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CipherSuite {
    /// 16-bit code point (placeholder until IANA assignment; draft §14).
    pub code_point: u16,
    /// Human-readable name (draft §6, Table 1).
    pub name: &'static str,
    /// AEAD key length `Nk`, octets (draft §2, RFC 8446).
    pub nk: usize,
    /// AEAD nonce length `Nn`, octets (draft §2, RFC 8446).
    pub nn: usize,
    /// The schedule profile this suite selects (draft §3, Table 1).
    pub profile: Profile,
}

/// `TLS_AES_128_GCM_TURBOSHAKE256` (draft §6, Table 1).
pub const TLS_AES_128_GCM_TURBOSHAKE256: CipherSuite = CipherSuite {
    code_point: 0xFF01,
    name: "TLS_AES_128_GCM_TURBOSHAKE256",
    nk: 16,
    nn: 12,
    profile: TURBOSHAKE256,
};

/// `TLS_AES_256_GCM_TURBOSHAKE256` (draft §6, Table 1).
pub const TLS_AES_256_GCM_TURBOSHAKE256: CipherSuite = CipherSuite {
    code_point: 0xFF02,
    name: "TLS_AES_256_GCM_TURBOSHAKE256",
    nk: 32,
    nn: 12,
    profile: TURBOSHAKE256,
};

/// `TLS_CHACHA20_POLY1305_TURBOSHAKE256` (draft §6, Table 1).
pub const TLS_CHACHA20_POLY1305_TURBOSHAKE256: CipherSuite = CipherSuite {
    code_point: 0xFF03,
    name: "TLS_CHACHA20_POLY1305_TURBOSHAKE256",
    nk: 32,
    nn: 12,
    profile: TURBOSHAKE256,
};

/// `TLS_AES_128_GCM_SHAKE256` (draft §6, Table 1).
pub const TLS_AES_128_GCM_SHAKE256: CipherSuite = CipherSuite {
    code_point: 0xFF04,
    name: "TLS_AES_128_GCM_SHAKE256",
    nk: 16,
    nn: 12,
    profile: SHAKE256,
};

/// `TLS_AES_256_GCM_SHAKE256` (draft §6, Table 1).
pub const TLS_AES_256_GCM_SHAKE256: CipherSuite = CipherSuite {
    code_point: 0xFF05,
    name: "TLS_AES_256_GCM_SHAKE256",
    nk: 32,
    nn: 12,
    profile: SHAKE256,
};

/// All five suites (draft §6).
pub const ALL: [CipherSuite; 5] = [
    TLS_AES_128_GCM_TURBOSHAKE256,
    TLS_AES_256_GCM_TURBOSHAKE256,
    TLS_CHACHA20_POLY1305_TURBOSHAKE256,
    TLS_AES_128_GCM_SHAKE256,
    TLS_AES_256_GCM_SHAKE256,
];
