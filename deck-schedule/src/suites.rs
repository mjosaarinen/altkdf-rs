//! Standard TLS 1.3 AEAD parameters; KDF selection is independent ([cipher-suites]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CipherSuite {
    pub code_point: u16,
    pub name: &'static str,
    pub nk: usize,
    pub nn: usize,
}
pub const TLS_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
    code_point: 0x1301,
    name: "TLS_AES_128_GCM_SHA256",
    nk: 16,
    nn: 12,
};
pub const TLS_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
    code_point: 0x1302,
    name: "TLS_AES_256_GCM_SHA384",
    nk: 32,
    nn: 12,
};
pub const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
    code_point: 0x1303,
    name: "TLS_CHACHA20_POLY1305_SHA256",
    nk: 32,
    nn: 12,
};
pub const TLS_AES_128_CCM_SHA256: CipherSuite = CipherSuite {
    code_point: 0x1304,
    name: "TLS_AES_128_CCM_SHA256",
    nk: 16,
    nn: 12,
};
pub const TLS_AES_128_CCM_8_SHA256: CipherSuite = CipherSuite {
    code_point: 0x1305,
    name: "TLS_AES_128_CCM_8_SHA256",
    nk: 16,
    nn: 12,
};
pub const ALL: [CipherSuite; 5] = [
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_AES_128_CCM_SHA256,
    TLS_AES_128_CCM_8_SHA256,
];
