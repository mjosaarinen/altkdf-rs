//! DECK-FORK: schedule_profile negotiation ([cipher-suites]).
use crate::{
    common_state::CommonState,
    crypto::CryptoProvider,
    enums::{AlertDescription, CipherSuite},
    Error, SupportedCipherSuite,
};
use alloc::vec::Vec;

/// Experimental private-use extension ID; not an IANA assignment.
pub const EXTENSION_ID: u16 = 0xffa6;

pub(crate) fn profiles(provider: &CryptoProvider) -> Vec<u16> {
    let mut ids = Vec::new();
    for s in &provider.cipher_suites {
        if let Some(id) = s.hash_provider().schedule_profile() {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    ids
}
pub(crate) fn choose_client(
    provider: &CryptoProvider,
    code: CipherSuite,
    profile: Option<u16>,
    extension_sent: bool,
    ech_offered: bool,
    common: &mut CommonState,
) -> Result<SupportedCipherSuite, Error> {
    let offered = profiles(provider);
    if let Some(id) = profile {
        if !extension_sent {
            return Err(common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                Error::General("unsolicited schedule_profile".into()),
            ));
        }
        if !offered.contains(&id) {
            return Err(common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                Error::General("unoffered schedule_profile".into()),
            ));
        }
    }
    let configured = provider
        .cipher_suites
        .iter()
        .find(|s| s.suite() == code && s.hash_provider().schedule_profile() == profile)
        .copied();
    // DECK-FORK ([cipher-suites]): an ECH rejection may complete an outer
    // handshake under ordinary TLS 1.3 even when the inner handshake requires
    // XOF. The same AEAD code point was offered by the virtual XOF suite.
    #[cfg(feature = "aws_lc_rs")]
    let outer_hkdf = if configured.is_none() && ech_offered && profile.is_none() {
        crate::crypto::aws_lc_rs::default_provider()
            .cipher_suites
            .iter()
            .find(|s| {
                s.suite() == code
                    && s.version().version == crate::ProtocolVersion::TLSv1_3
                    && provider
                        .cipher_suites
                        .iter()
                        .any(|offered| offered.suite() == code)
            })
            .copied()
    } else {
        None
    };
    #[cfg(not(feature = "aws_lc_rs"))]
    let outer_hkdf = None;
    configured.or(outer_hkdf).ok_or_else(|| {
        common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            Error::General("required schedule or cipher suite not negotiated".into()),
        )
    })
}
