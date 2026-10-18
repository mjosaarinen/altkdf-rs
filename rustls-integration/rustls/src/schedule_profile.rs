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
    provider
        .cipher_suites
        .iter()
        .find(|s| s.suite() == code && s.hash_provider().schedule_profile() == profile)
        .copied()
        .ok_or_else(|| {
            common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                Error::General("required schedule or cipher suite not negotiated".into()),
            )
        })
}
