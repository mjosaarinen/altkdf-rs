//! DECK-FORK (draft §10, RFC 9258): out-of-band external PSKs for deck suites.
//!
//! An external PSK is an identity + secret provisioned outside TLS. Unlike a
//! resumption PSK it is not derived from a prior handshake; it is imported *per
//! target cipher suite* into an `ipsk` (draft §5.9, §10) that keys the early
//! stage, and its binder uses the `"ext binder"` label (draft §5.5).
//!
//! At the TLS wire level an external-PSK handshake is structurally a resumption
//! handshake — `pre_shared_key` + `psk_dhe_ke`, no server Certificate — so the
//! fork routes it through the same offer/accept machinery, differing only in the
//! PSK source (import vs `resumption_psk`) and the binder label.

use core::fmt;

use alloc::vec::Vec;
use zeroize::Zeroizing;

/// An out-of-band external PSK (draft §10): a shared `external_identity` and the
/// secret `epsk`, provisioned to both peers outside TLS. Set
/// [`ClientConfig::deck_external_psk`](crate::ClientConfig::deck_external_psk) to
/// offer one, and [`ServerConfig::deck_external_psks`](crate::ServerConfig::deck_external_psks)
/// to accept.
///
/// The `epsk` is held in a [`Zeroizing`] buffer and erased on drop (draft
/// §15.7.2.2); both fields are private and the [`fmt::Debug`] impl redacts the
/// secret, so the PSK cannot leak through a config `{:?}` dump or a stray clone's
/// freed heap.
#[derive(Clone)]
pub struct DeckExternalPsk {
    /// `external_identity` (draft §10) — the label the PSK is known by. A wire
    /// value (offered inside the serialized `ImportedIdentityV2`), not a secret.
    external_identity: Vec<u8>,
    /// The external PSK secret (`epsk`, draft §10). Zeroized on drop.
    epsk: Zeroizing<Vec<u8>>,
}

impl DeckExternalPsk {
    /// A new external PSK from an identity and secret. The secret is copied into a
    /// zeroizing buffer.
    pub fn new(external_identity: impl Into<Vec<u8>>, epsk: impl Into<Vec<u8>>) -> Self {
        Self {
            external_identity: external_identity.into(),
            epsk: Zeroizing::new(epsk.into()),
        }
    }

    /// Import this external PSK for the deck cipher suite with code point
    /// `suite_code` (draft §5.9, §10). Returns the wire `PskIdentity.identity`
    /// (the serialized `ImportedIdentityV2` — the same bytes are both the
    /// derivation context and the offered identity, an injective per-suite
    /// binding) and the imported `ipsk` (zeroized on drop). `None` if `suite_code`
    /// is not a deck suite of this document, or the identity is out of range
    /// (draft §10).
    pub(crate) fn import_for(&self, suite_code: u16) -> Option<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let target = deck_schedule::suites::ALL
            .iter()
            .find(|s| s.code_point == suite_code)?;
        let imported =
            deck_schedule::ImportedIdentityV2::for_suite(&self.external_identity, b"", target)
                .import(&self.epsk)
                .ok()?;
        // `imported.ipsk` is a `deck_schedule::Secret` (`Zeroizing<Vec<u8>>`);
        // hand it back still zeroizing, never a bare `Vec`.
        Some((imported.identity, imported.ipsk))
    }
}

/// Redacted so a `ClientConfig`/`ServerConfig` `{:?}` never prints the PSK secret.
impl fmt::Debug for DeckExternalPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeckExternalPsk")
            .field("external_identity", &self.external_identity)
            .field("epsk", &"<redacted>")
            .finish()
    }
}
