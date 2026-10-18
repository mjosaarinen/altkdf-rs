//! DECK-FORK ([psk-importer]): provisioned external PSKs imported per target KDF.
//! The wire identity is RFC 9258 ImportedIdentity; the binder label is ibk.
use core::fmt;

use alloc::vec::Vec;
use zeroize::Zeroizing;

/// An out-of-band external PSK (draft `[psk-importer]`): a shared `external_identity` and the
/// secret `epsk`, provisioned to both peers outside TLS. Set
/// [`ClientConfig::deck_external_psk`](crate::ClientConfig::deck_external_psk) to
/// offer one, and [`ServerConfig::deck_external_psks`](crate::ServerConfig::deck_external_psks)
/// to accept.
///
/// The `epsk` is held in a [`Zeroizing`] buffer and erased on drop (draft
/// `[erasure-boundaries]`); both fields are private and the [`fmt::Debug`] impl redacts the
/// secret, so the PSK cannot leak through a config `{:?}` dump or a stray clone's
/// freed heap.
#[derive(Clone)]
pub struct DeckExternalPsk {
    /// `external_identity` (draft `[psk-importer]`), the label the PSK is known by. A wire
    /// value (offered inside the serialized `ImportedIdentity`), not a secret.
    external_identity: Vec<u8>,
    /// The external PSK secret (`epsk`, draft `[psk-importer]`). Zeroized on drop.
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

    /// Import under the target KDF Identifier. No AEAD is bound by the importer.
    pub(crate) fn import_for(&self, kdf_id: u16) -> Option<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let target = deck_schedule::Kdf::from_id(kdf_id)?;
        let imported = deck_schedule::ImportedIdentity::for_kdf(
            &self.external_identity,
            b"",
            deck_schedule::Protocol::Tls13,
            target,
        )
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
