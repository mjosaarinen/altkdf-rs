//! Injective framing (draft `[conventions]`).
//!
//! `frame(x) = uint16(len(x)) || x`. Every item a deck absorbs is framed, which
//! makes the input encoding injective (draft `[domain-separation]`).

use alloc::vec::Vec;

/// Largest framed value: a uint16 length encodes 65535 (draft `[conventions]`).
pub const MAX_FRAME: usize = 0xFFFF;

/// `uint16(n)`: two-octet big-endian encoding.
pub fn uint16(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}

/// `frame(x) = uint16(len(x)) || x`.
///
/// Panics if `x` exceeds [`MAX_FRAME`] octets. The draft bounds every framed
/// value; the public entry points of this crate reject longer inputs with an
/// error before they reach the framing.
pub fn frame(x: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + x.len());
    frame_into(&mut out, x);
    out
}

/// Append `frame(x)` to `buf`.
pub fn frame_into(buf: &mut Vec<u8>, x: &[u8]) {
    assert!(x.len() <= MAX_FRAME, "framed value exceeds 0xFFFF octets");
    buf.extend_from_slice(&uint16(x.len() as u16));
    buf.extend_from_slice(x);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn frame_basic() {
        assert_eq!(frame(b""), vec![0x00, 0x00]);
        assert_eq!(frame(b"psk_"), vec![0x00, 0x04, b'p', b's', b'k', b'_']);
    }

    /// A 65535-octet value is framable (the draft's limit is 0xFFFF inclusive).
    #[test]
    fn frame_limit_inclusive() {
        let x = vec![0u8; MAX_FRAME];
        assert_eq!(&frame(&x)[..2], &[0xFF, 0xFF]);
    }

    #[test]
    #[should_panic]
    fn frame_over_limit_panics() {
        frame(&vec![0u8; MAX_FRAME + 1]);
    }
}
