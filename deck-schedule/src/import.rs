//! The external PSK importer: `ImportedIdentityV2` (draft §10).
//!
//! An external PSK (`epsk`) used with a deck cipher suite is imported *per target
//! cipher suite* into an `ipsk` (draft §5.9). The context hashed into that
//! derivation is the serialized `ImportedIdentityV2`, and the client offers that
//! same serialization as the `PskIdentity.identity` on the wire — so the identity
//! a peer sees is exactly the one bound into the derivation, an injective
//! per-suite binding (draft §10). Binding `target_ciphersuite` (rather than RFC
//! 9258's `target_kdf`) diversifies the imported PSK per cipher suite, matching
//! the per-suite binding used everywhere else in this document.
//!
//! The binder over an imported PSK uses the `"ext binder"` label
//! ([`BinderKind::External`](crate::derive::BinderKind::External), draft §5.5),
//! keyed by the early secret of the schedule keyed by the `ipsk`
//! ([`schedule::early_secret`](crate::schedule::early_secret)).
//!
//! Note: this crate implements the *derivation and encoding* of §10. Driving an
//! external PSK through a live TLS handshake additionally needs external-PSK
//! support in the TLS stack; the vendored rustls fork adds that surface and
//! exercises it in `rustls-integration/tests/external_psk.rs`.

use alloc::vec::Vec;

use crate::derive::{psk_import, PskImportError};
use crate::frame::uint16;
use crate::suites::{self, CipherSuite};
use crate::Secret;

/// `target_protocol` for TLS 1.3 — the only value this document defines (draft §10).
pub const TARGET_PROTOCOL_TLS13: u16 = 0x0304;

/// `ImportedIdentityV2` (draft §10): binds an external PSK identity to a target
/// cipher suite (and thus schedule profile).
///
/// ```text
/// struct {
///     opaque external_identity<1..2^16-1>;
///     opaque context<0..2^16-1>;
///     uint16 target_protocol;      /* 0x0304 for TLS 1.3 */
///     uint16 target_ciphersuite;   /* a cipher suite of this document */
/// } ImportedIdentityV2;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportedIdentityV2<'a> {
    /// `external_identity` — the label the external PSK is known by (`<1..2^16-1>`).
    pub external_identity: &'a [u8],
    /// `context` — optional importer context (`<0..2^16-1>`).
    pub context: &'a [u8],
    /// `target_protocol` — `0x0304` (TLS 1.3) for this document.
    pub target_protocol: u16,
    /// `target_ciphersuite` — a deck cipher-suite code point (draft §6).
    pub target_ciphersuite: u16,
}

/// An imported external PSK: the serialized `ImportedIdentityV2` offered on the
/// wire, and the derived `ipsk` that keys the schedule (draft §5.9, §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedPsk {
    /// The exact `PskIdentity.identity` bytes to offer (serialized identity). A
    /// wire value, not secret.
    pub identity: Vec<u8>,
    /// The imported PSK (`SecretLen` octets), keying the early stage (draft §5.9);
    /// a live secret, zeroized on drop.
    pub ipsk: Secret,
}

impl<'a> ImportedIdentityV2<'a> {
    /// Build an identity for deck cipher suite `target`, with `target_protocol`
    /// fixed to TLS 1.3 (draft §10).
    pub fn for_suite(external_identity: &'a [u8], context: &'a [u8], target: &CipherSuite) -> Self {
        Self {
            external_identity,
            context,
            target_protocol: TARGET_PROTOCOL_TLS13,
            target_ciphersuite: target.code_point,
        }
    }

    /// TLS presentation-language serialization (draft §10): the exact
    /// `PskIdentity.identity` offered on the wire and hashed as the derivation
    /// context. Each `opaque` field is a 2-octet length prefix followed by its
    /// bytes, then the two `uint16`s.
    ///
    /// Fallible so invalid lengths cannot silently truncate through `as u16`:
    /// `external_identity` MUST be non-empty (`opaque<1..2^16-1>`), and the whole
    /// serialization MUST fit `PskIdentity.identity<1..2^16-1>` — i.e.
    /// `len(external_identity) + len(context) + 8 ≤ 0xFFFF` — which also keeps
    /// each length field within `u16`.
    pub fn serialize(&self) -> Result<Vec<u8>, PskImportError> {
        if self.external_identity.is_empty() {
            return Err(PskImportError::IdentityFieldOutOfRange);
        }
        // 8 = two 2-octet length prefixes + target_protocol + target_ciphersuite.
        let total = self.external_identity.len() + self.context.len() + 8;
        if total > 0xFFFF {
            return Err(PskImportError::IdentityTooLong);
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&uint16(self.external_identity.len() as u16));
        out.extend_from_slice(self.external_identity);
        out.extend_from_slice(&uint16(self.context.len() as u16));
        out.extend_from_slice(self.context);
        out.extend_from_slice(&uint16(self.target_protocol));
        out.extend_from_slice(&uint16(self.target_ciphersuite));
        Ok(out)
    }

    /// Import `epsk` under this identity into an `ipsk` (draft §5.9, §10),
    /// returning the wire identity alongside the derived PSK.
    ///
    /// Enforces the §10 input rules: `target_protocol` is TLS 1.3,
    /// `target_ciphersuite` is one of this document's suites, and the identity
    /// serializes within `PskIdentity.identity<1..2^16-1>` (via [`Self::serialize`]).
    /// `epsk` bounds (`≤ 0xFFFE`) are enforced by the underlying derivation.
    pub fn import(&self, epsk: &[u8]) -> Result<ImportedPsk, PskImportError> {
        if self.target_protocol != TARGET_PROTOCOL_TLS13 {
            return Err(PskImportError::WrongTargetProtocol);
        }
        let target = suites::ALL
            .iter()
            .find(|s| s.code_point == self.target_ciphersuite)
            .ok_or(PskImportError::UnknownTargetSuite)?;
        // The serialized identity is the derivation context (draft §5.9), so the
        // wire identity and the bound context are the same bytes by construction.
        let identity = self.serialize()?;
        let ipsk = psk_import(target, epsk, &identity)?;
        Ok(ImportedPsk { identity, ipsk })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::{binder_verify_data, BinderKind};
    use crate::schedule::early_secret;
    use crate::suites::{
        TLS_AES_128_GCM_SHAKE256, TLS_AES_128_GCM_TURBOSHAKE256, TLS_AES_256_GCM_TURBOSHAKE256,
    };
    use alloc::vec;

    /// Serialization is the §10 presentation language, byte for byte.
    #[test]
    fn serialize_is_presentation_language() {
        let iid = ImportedIdentityV2::for_suite(b"id", b"ctx", &TLS_AES_128_GCM_TURBOSHAKE256);
        // 0x0002 "id" 0x0003 "ctx" 0x0304 0xFF01
        let expected = [
            0x00, 0x02, b'i', b'd', 0x00, 0x03, b'c', b't', b'x', 0x03, 0x04, 0xFF, 0x01,
        ];
        assert_eq!(iid.serialize().unwrap(), expected);
    }

    /// Empty context serializes as a bare `0x0000` length, no payload (draft §10).
    #[test]
    fn empty_context_serializes_as_zero_length() {
        let iid = ImportedIdentityV2::for_suite(b"x", b"", &TLS_AES_128_GCM_TURBOSHAKE256);
        assert_eq!(
            iid.serialize().unwrap(),
            [0x00, 0x01, b'x', 0x00, 0x00, 0x03, 0x04, 0xFF, 0x01]
        );
    }

    /// The whole serialization is offered as `PskIdentity.identity<1..2^16-1>`
    /// (draft §10), so it must fit `0xFFFF` octets even when each field is
    /// individually in range. `external_identity + context + 8` is the ceiling.
    #[test]
    fn import_rejects_oversized_serialized_identity() {
        let ts = TLS_AES_128_GCM_TURBOSHAKE256;
        // 0xFFF7 + 0 + 8 == 0xFFFF: the largest identity that fits.
        let ok = vec![0u8; 0xFFF7];
        assert!(ImportedIdentityV2::for_suite(&ok, b"", &ts)
            .serialize()
            .is_ok());
        assert!(ImportedIdentityV2::for_suite(&ok, b"", &ts)
            .import(&[0u8; 32])
            .is_ok());

        // One octet more overflows `PskIdentity.identity`.
        let too_long = vec![0u8; 0xFFF8];
        assert_eq!(
            ImportedIdentityV2::for_suite(&too_long, b"", &ts).serialize(),
            Err(PskImportError::IdentityTooLong),
        );
        assert_eq!(
            ImportedIdentityV2::for_suite(&too_long, b"", &ts).import(&[0u8; 32]),
            Err(PskImportError::IdentityTooLong),
        );

        // The ceiling is on the *sum*: split across the two fields also overflows.
        let half = vec![0u8; 0x8000];
        assert_eq!(
            ImportedIdentityV2::for_suite(&half, &half, &ts).import(&[0u8; 32]),
            Err(PskImportError::IdentityTooLong),
        );
    }

    /// `ipsk` binds `target_ciphersuite`: importing the same `epsk`/identity fields
    /// under different suites yields different `ipsk`s (and different wire
    /// identities), diversifying per suite (draft §10).
    #[test]
    fn import_binds_target_ciphersuite() {
        let epsk = [0x33u8; 32];
        let a = ImportedIdentityV2::for_suite(b"peer", b"", &TLS_AES_128_GCM_TURBOSHAKE256)
            .import(&epsk)
            .unwrap();
        // Same AEAD family, other profile (SHAKE256) → different suite code point.
        let b = ImportedIdentityV2::for_suite(b"peer", b"", &TLS_AES_128_GCM_SHAKE256)
            .import(&epsk)
            .unwrap();
        // Same profile, different AEAD.
        let c = ImportedIdentityV2::for_suite(b"peer", b"", &TLS_AES_256_GCM_TURBOSHAKE256)
            .import(&epsk)
            .unwrap();
        assert_ne!(a.ipsk, b.ipsk, "cross-profile diversification");
        assert_ne!(a.ipsk, c.ipsk, "same-profile, cross-suite diversification");
        assert_ne!(a.identity, b.identity, "wire identity differs by suite");
        assert_eq!(a.ipsk.len(), 64);
    }

    /// `ipsk` binds `external_identity` and `context` (draft §10).
    #[test]
    fn import_binds_identity_and_context() {
        let epsk = [0x44u8; 32];
        let base = ImportedIdentityV2::for_suite(b"alice", b"ctx", &TLS_AES_128_GCM_TURBOSHAKE256)
            .import(&epsk)
            .unwrap();
        let other_id =
            ImportedIdentityV2::for_suite(b"bob", b"ctx", &TLS_AES_128_GCM_TURBOSHAKE256)
                .import(&epsk)
                .unwrap();
        let other_ctx =
            ImportedIdentityV2::for_suite(b"alice", b"ctx2", &TLS_AES_128_GCM_TURBOSHAKE256)
                .import(&epsk)
                .unwrap();
        assert_ne!(base.ipsk, other_id.ipsk, "external_identity is bound");
        assert_ne!(base.ipsk, other_ctx.ipsk, "context is bound");
    }

    /// §10 input rules are enforced.
    #[test]
    fn import_rejects_bad_fields() {
        let ts = TLS_AES_128_GCM_TURBOSHAKE256;
        // Empty external_identity (opaque<1..>).
        assert_eq!(
            ImportedIdentityV2::for_suite(b"", b"", &ts).import(&[0u8; 32]),
            Err(PskImportError::IdentityFieldOutOfRange),
        );
        // Wrong target_protocol.
        let bad_proto = ImportedIdentityV2 {
            external_identity: b"id",
            context: b"",
            target_protocol: 0x0303, // TLS 1.2
            target_ciphersuite: ts.code_point,
        };
        assert_eq!(
            bad_proto.import(&[0u8; 32]),
            Err(PskImportError::WrongTargetProtocol),
        );
        // Unknown target_ciphersuite.
        let bad_suite = ImportedIdentityV2 {
            external_identity: b"id",
            context: b"",
            target_protocol: TARGET_PROTOCOL_TLS13,
            target_ciphersuite: 0x1301, // a real TLS 1.3 suite, not a deck suite
        };
        assert_eq!(
            bad_suite.import(&[0u8; 32]),
            Err(PskImportError::UnknownTargetSuite),
        );
        // Overlong epsk (bound enforced by the derivation).
        assert_eq!(
            ImportedIdentityV2::for_suite(b"id", b"", &ts).import(&vec![0u8; 0xFFFF]),
            Err(PskImportError::EpskTooLong),
        );
    }

    /// The full external-PSK client offer (draft §10 → §5.9 → §5.5): import the
    /// `ipsk`, key the early stage on it, and compute the `"ext binder"`. Pins
    /// that the imported PSK feeds the external-binder path and yields an
    /// `FLen`-octet tag that differs from a resumption binder.
    #[test]
    fn imported_psk_offer_ext_binder() {
        let profile = &crate::profile::TURBOSHAKE256;
        let target = TLS_AES_128_GCM_TURBOSHAKE256;
        let epsk = [0x55u8; 48];
        let th_ch0 = [0x51u8; 64];

        let imported = ImportedIdentityV2::for_suite(b"peer", b"ctx", &target)
            .import(&epsk)
            .unwrap();
        let early = early_secret(profile, &imported.ipsk);

        let ext = binder_verify_data(
            profile,
            &early,
            BinderKind::External,
            target.code_point,
            &th_ch0,
        );
        assert_eq!(ext.len(), profile.flen);

        // An imported PSK uses the external-binder label, not the resumption one.
        let res = binder_verify_data(
            profile,
            &early,
            BinderKind::Resumption,
            target.code_point,
            &th_ch0,
        );
        assert_ne!(
            ext, res,
            "ext binder differs from res binder over the same ipsk"
        );
    }
}
