//! Hex encoding for deterministic fixtures, with no external dependencies.
use alloc::{string::String, vec::Vec};

pub fn encode(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(2 * bytes.len());
    for b in bytes {
        write!(out, "{b:02x}").unwrap();
    }
    out
}

pub fn decode(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            let digit = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid fixture hex"),
            };
            digit(p[0]) * 16 + digit(p[1])
        })
        .collect()
}
