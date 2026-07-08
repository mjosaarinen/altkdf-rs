//! Injective framing (draft §2) and the KMAC-style length encoders (draft §5.2).
//!
//! `frame(x) = uint16(len(x)) || x`. Every variable-length item absorbed by the
//! deck is framed, which makes the input encoding injective (draft §15.7.3).
//! The `*_encode` / `bytepad` helpers are the byte-oriented encoders the MAC
//! layout uses.

use alloc::vec::Vec;

/// `uint16(n)`: two-octet big-endian encoding (draft §2).
pub fn uint16(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}

/// `frame(x) = uint16(len(x)) || x` (draft §2).
///
/// Panics if `x` exceeds `0xFFFE` octets. The draft guarantees no framed value
/// is longer than that (§2, §3, §10).
pub fn frame(x: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + x.len());
    frame_into(&mut out, x);
    out
}

/// Append `frame(x)` to `buf`.
pub fn frame_into(buf: &mut Vec<u8>, x: &[u8]) {
    assert!(
        x.len() <= 0xFFFE,
        "framed value exceeds 0xFFFE octets (draft §2)"
    );
    buf.extend_from_slice(&uint16(x.len() as u16));
    buf.extend_from_slice(x);
}

/// Minimal big-endian octet length of `n`, taking 1 when `n == 0` (draft §5.2).
fn min_be_len(n: u64) -> usize {
    let bits = 64 - n.leading_zeros() as usize;
    bits.div_ceil(8).max(1)
}

/// `left_encode(n)`: length octet `b` then `n` as `b` octets (draft §5.2).
pub fn left_encode(n: u64) -> Vec<u8> {
    let b = min_be_len(n);
    let be = n.to_be_bytes();
    let mut out = Vec::with_capacity(1 + b);
    out.push(b as u8);
    out.extend_from_slice(&be[8 - b..]);
    out
}

/// `right_encode(n)`: `n` as `b` octets then the length octet `b` (draft §5.2).
pub fn right_encode(n: u64) -> Vec<u8> {
    let b = min_be_len(n);
    let be = n.to_be_bytes();
    let mut out = Vec::with_capacity(b + 1);
    out.extend_from_slice(&be[8 - b..]);
    out.push(b as u8);
    out
}

/// `encode_string(s) = left_encode(8*len(s)) || s` (draft §5.2).
///
/// Capacity is reserved exactly, so appending `s` never reallocates — `s` may be
/// a secret (e.g. a MAC key), which a reallocation could leave in freed heap
/// (draft §15.7.2.2).
pub fn encode_string(s: &[u8]) -> Vec<u8> {
    let lead = left_encode(8 * s.len() as u64);
    let mut out = Vec::with_capacity(lead.len() + s.len());
    out.extend_from_slice(&lead);
    out.extend_from_slice(s);
    out
}

/// `bytepad(s, w) = left_encode(w) || s || 0x00…`, padded to a multiple of `w`
/// (draft §5.2).
///
/// Capacity is reserved exactly (same secret-in-freed-heap reason as
/// [`encode_string`]): neither the `s` copy nor the zero padding reallocates.
pub fn bytepad(s: &[u8], w: usize) -> Vec<u8> {
    let lead = left_encode(w as u64);
    let padded = (lead.len() + s.len()).div_ceil(w) * w;
    let mut out = Vec::with_capacity(padded);
    out.extend_from_slice(&lead);
    out.extend_from_slice(s);
    out.resize(padded, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn frame_basic() {
        assert_eq!(frame(b""), vec![0x00, 0x00]);
        assert_eq!(frame(b"psk"), vec![0x00, 0x03, b'p', b's', b'k']);
    }

    #[test]
    fn encoders_kat() {
        // From SP 800-185 conventions.
        assert_eq!(left_encode(0), vec![0x01, 0x00]);
        assert_eq!(right_encode(0), vec![0x00, 0x01]);
        assert_eq!(left_encode(136), vec![0x01, 0x88]);
        assert_eq!(right_encode(8 * 64), vec![0x02, 0x00, 0x02]); // 512 = 0x0200
        assert_eq!(encode_string(b""), vec![0x01, 0x00]);
        // bytepad(encode_string("") , 136) starts with left_encode(136).
        let bp = bytepad(&encode_string(b""), 136);
        assert_eq!(bp.len(), 136);
        assert_eq!(&bp[..4], &[0x01, 0x88, 0x01, 0x00]);
    }
}
