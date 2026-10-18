//! Three-stage schedule, implemented from `[key-schedule]` and `[absent-empty]`.
use crate::{
    deck::Deck,
    frame::MAX_FRAME,
    kdf::{Kdf, Protocol},
    labels, Error, Secret,
};
use alloc::vec::Vec;

/// Determines the binder label and therefore the early-to-handshake residue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PskKind {
    External,
    Imported,
    Resumption,
}
impl PskKind {
    pub fn label(self) -> &'static labels::Label {
        match self {
            Self::External => labels::EBK,
            Self::Imported => labels::IBK,
            Self::Resumption => labels::RBK,
        }
    }
}

/// Early trunk. Absence absorbs an explicitly empty PSK, but has no leaves.
#[derive(Clone)]
pub struct EarlyStage {
    deck: Deck,
    psk_kind: Option<PskKind>,
}
impl EarlyStage {
    pub fn new(kdf: Kdf, proto: Protocol, psk: Option<(&[u8], PskKind)>) -> Result<Self, Error> {
        if let Some((key, kind)) = psk {
            if key.is_empty()
                || key.len() > MAX_FRAME
                || (kind != PskKind::External && key.len() != kdf.secret_len)
            {
                return Err(Error::InvalidPsk);
            }
        }
        let mut deck = Deck::early(kdf, proto);
        deck.absorb(labels::PSK, psk.map_or(b"".as_slice(), |(p, _)| p));
        Ok(Self {
            deck,
            psk_kind: psk.map(|(_, k)| k),
        })
    }
    /// Joint binder key and residue, in that order (`[finished-and-binder-mac]`).
    pub fn binder_key(&self) -> Result<(Secret, Secret), Error> {
        let kind = self.psk_kind.ok_or(Error::InvalidPsk)?;
        let sl = self.deck.kdf().secret_len;
        let mut values = self
            .deck
            .derive_n(&[(kind.label(), sl), (labels::DRV, sl)], None)?;
        let residue = values.pop().unwrap();
        Ok((values.pop().unwrap(), residue))
    }
    pub fn early_traffic(&self, th_ch: &[u8]) -> Result<(Secret, Secret), Error> {
        if self.psk_kind.is_none() {
            return Err(Error::InvalidPsk);
        }
        let sl = self.deck.kdf().secret_len;
        let mut v = self
            .deck
            .derive_n(&[(labels::CET, sl), (labels::EES, sl)], Some(th_ch))?;
        let ees = v.pop().unwrap();
        Ok((v.pop().unwrap(), ees))
    }
    /// PSK path MUST use the DeriveN residue, never the standalone ratchet.
    pub fn into_handshake(self) -> HandshakeStage {
        let deck = if self.psk_kind.is_some() {
            let (_, residue) = self.binder_key().expect("validated early stage");
            Deck::stage(self.deck.kdf(), self.deck.protocol(), &residue)
        } else {
            self.deck.ratchet()
        };
        HandshakeStage { deck }
    }
}

#[derive(Clone)]
pub struct HandshakeStage {
    deck: Deck,
}
impl HandshakeStage {
    /// Once per component, in the group's specified concatenation order.
    pub fn absorb(&mut self, component: &[u8]) -> Result<(), Error> {
        if component.len() > MAX_FRAME {
            return Err(Error::FrameTooLong);
        }
        self.deck.absorb(labels::SHS, component);
        Ok(())
    }
    pub fn traffic(&self, th_sh: &[u8]) -> Result<(Secret, Secret), Error> {
        let sl = self.deck.kdf().secret_len;
        let mut v = self
            .deck
            .derive_n(&[(labels::CHT, sl), (labels::SHT, sl)], Some(th_sh))?;
        let server = v.pop().unwrap();
        Ok((v.pop().unwrap(), server))
    }
    pub fn into_application(self) -> AppStage {
        AppStage {
            deck: self.deck.ratchet(),
        }
    }
}

#[derive(Clone)]
pub struct AppStage {
    deck: Deck,
}
impl AppStage {
    pub fn traffic(&self, th_sf: &[u8]) -> Result<(Secret, Secret, Secret), Error> {
        let sl = self.deck.kdf().secret_len;
        let mut v = self.deck.derive_n(
            &[(labels::CAT, sl), (labels::SAT, sl), (labels::EXS, sl)],
            Some(th_sf),
        )?;
        let exporter = v.pop().unwrap();
        let server = v.pop().unwrap();
        Ok((v.pop().unwrap(), server, exporter))
    }
    pub fn resumption(&self, th_cf: &[u8]) -> Result<Secret, Error> {
        self.deck
            .derive(labels::RSS, Some(th_cf), self.deck.kdf().secret_len)
    }
}

/// Reference/vector inputs only. Production callers use the stages above.
pub struct ScheduleInputs<'a> {
    pub psk: Option<(&'a [u8], PskKind)>,
    pub dhe_components: &'a [&'a [u8]],
    pub th_ch: &'a [u8],
    pub th_sh: &'a [u8],
    pub th_sf: &'a [u8],
    pub th_cf: &'a [u8],
}
/// Synthetic reference data, deliberately plain vectors; never production state.
pub struct ScheduleOutputs {
    pub c_e_traffic: Option<Vec<u8>>,
    pub e_exp_master: Option<Vec<u8>>,
    pub c_hs_traffic: Vec<u8>,
    pub s_hs_traffic: Vec<u8>,
    pub c_ap_traffic: Vec<u8>,
    pub s_ap_traffic: Vec<u8>,
    pub exp_master: Vec<u8>,
    pub res_master: Vec<u8>,
}
pub fn run(kdf: Kdf, proto: Protocol, inp: &ScheduleInputs<'_>) -> Result<ScheduleOutputs, Error> {
    let early = EarlyStage::new(kdf, proto, inp.psk)?;
    let (c_e_traffic, e_exp_master) = if inp.psk.is_some() {
        let (c, e) = early.early_traffic(inp.th_ch)?;
        (Some(c.to_vec()), Some(e.to_vec()))
    } else {
        (None, None)
    };
    let mut h = early.into_handshake();
    for c in inp.dhe_components {
        h.absorb(c)?;
    }
    let (c_h, s_h) = h.traffic(inp.th_sh)?;
    let app = h.into_application();
    let (c_a, s_a, exp) = app.traffic(inp.th_sf)?;
    Ok(ScheduleOutputs {
        c_e_traffic,
        e_exp_master,
        c_hs_traffic: c_h.to_vec(),
        s_hs_traffic: s_h.to_vec(),
        c_ap_traffic: c_a.to_vec(),
        s_ap_traffic: s_a.to_vec(),
        exp_master: exp.to_vec(),
        res_master: app.resumption(inp.th_cf)?.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TURBOSHAKE256 as K;
    const P: Protocol = Protocol::Tls13;
    #[test]
    fn psk_bounds_and_binder_domains() {
        assert!(EarlyStage::new(K, P, Some((b"", PskKind::External))).is_err());
        assert!(EarlyStage::new(K, P, Some((b"short", PskKind::Imported))).is_err());
        assert!(EarlyStage::new(K, P, Some((b"short", PskKind::External))).is_ok());
        let keys: Vec<_> = [PskKind::External, PskKind::Imported, PskKind::Resumption]
            .into_iter()
            .map(|kind| {
                EarlyStage::new(K, P, Some((&[7; 64], kind)))
                    .unwrap()
                    .binder_key()
                    .unwrap()
            })
            .collect();
        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i], keys[j]);
            }
        }
    }
    #[test]
    fn component_boundaries_and_order() {
        let base = EarlyStage::new(K, P, None).unwrap().into_handshake();
        let mut a = base.clone();
        a.absorb(b"ab").unwrap();
        a.absorb(b"cd").unwrap();
        let mut b = base.clone();
        b.absorb(b"cd").unwrap();
        b.absorb(b"ab").unwrap();
        let mut c = base;
        c.absorb(b"abcd").unwrap();
        assert_ne!(a.traffic(&[1; 64]).unwrap(), b.traffic(&[1; 64]).unwrap());
        assert_ne!(a.traffic(&[1; 64]).unwrap(), c.traffic(&[1; 64]).unwrap());
    }
}
