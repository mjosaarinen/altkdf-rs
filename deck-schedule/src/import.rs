//! RFC 9258 ImportedIdentity and target-KDF import ([psk-importer]).
use crate::{
    deck::Deck,
    frame::{frame_into, MAX_FRAME},
    kdf::{Kdf, Protocol},
    labels,
    transcript::transcript_hash,
    Error, Secret,
};
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportedIdentity<'a> {
    pub external_identity: &'a [u8],
    pub context: &'a [u8],
    pub target_protocol: u16,
    pub target_kdf: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedPsk {
    pub identity: Vec<u8>,
    pub ipsk: Secret,
}
impl<'a> ImportedIdentity<'a> {
    pub fn for_kdf(
        external_identity: &'a [u8],
        context: &'a [u8],
        proto: Protocol,
        kdf: Kdf,
    ) -> Self {
        Self {
            external_identity,
            context,
            target_protocol: proto.version(),
            target_kdf: kdf.id,
        }
    }
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        if self.external_identity.is_empty() {
            return Err(Error::IdentityFieldOutOfRange);
        }
        let total = self
            .external_identity
            .len()
            .checked_add(self.context.len())
            .and_then(|n| n.checked_add(8))
            .ok_or(Error::IdentityTooLong)?;
        if total > MAX_FRAME {
            return Err(Error::IdentityTooLong);
        }
        let mut out = Vec::with_capacity(total);
        frame_into(&mut out, self.external_identity);
        frame_into(&mut out, self.context);
        out.extend_from_slice(&self.target_protocol.to_be_bytes());
        out.extend_from_slice(&self.target_kdf.to_be_bytes());
        Ok(out)
    }
    pub fn import(&self, epsk: &[u8]) -> Result<ImportedPsk, Error> {
        if epsk.is_empty() || epsk.len() > MAX_FRAME {
            return Err(Error::InvalidPsk);
        }
        let proto =
            Protocol::from_version(self.target_protocol).ok_or(Error::WrongTargetProtocol)?;
        let kdf = Kdf::from_id(self.target_kdf).ok_or(Error::UnknownTargetKdf)?;
        let identity = self.serialize()?;
        let th = transcript_hash(&kdf, &identity);
        let ipsk = Deck::keyed(kdf, proto, epsk).derive(labels::IPK, Some(&th), kdf.secret_len)?;
        Ok(ImportedPsk { identity, ipsk })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SHAKE256, TURBOSHAKE256};
    #[test]
    fn identity_ceiling_and_import_binding() {
        let identity = alloc::vec![0;0xfff7];
        assert_eq!(
            ImportedIdentity::for_kdf(&identity, b"", Protocol::Tls13, TURBOSHAKE256)
                .serialize()
                .unwrap()
                .len(),
            65535
        );
        assert_eq!(
            ImportedIdentity::for_kdf(&identity, b"x", Protocol::Tls13, TURBOSHAKE256).serialize(),
            Err(Error::IdentityTooLong)
        );
        let a = ImportedIdentity::for_kdf(b"peer", b"", Protocol::Tls13, TURBOSHAKE256)
            .import(b"epsk")
            .unwrap();
        let b = ImportedIdentity::for_kdf(b"peer", b"", Protocol::Tls13, SHAKE256)
            .import(b"epsk")
            .unwrap();
        assert_ne!(a.ipsk, b.ipsk);
        assert_ne!(a.identity, b.identity);
        assert_eq!(a.ipsk.len(), 64);
    }
}
