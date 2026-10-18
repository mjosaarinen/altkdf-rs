//! Tags and labels (draft `[labels]`, `[iana-labels]`).
//!
//! Tags are 4 octets and fixed by the draft; labels are 3 octets and listed in
//! the TLS XOF Key Schedule Labels registry. Every label differs from every tag
//! in length, so a parser always knows which it is reading.

/// A 4-octet tag (draft `[tag-table]`).
pub type Tag = [u8; 4];
/// A 3-octet registered label (draft `[label-table]`).
pub type Label = [u8; 3];

/// The PSK, in the early stage.
pub const PSK: &Tag = b"psk_";
/// Each asymmetric shared secret component.
pub const SHS: &Tag = b"shs_";
/// `Init` seed: a ratchet residue or a retained secret.
pub const SEED: &Tag = b"seed";
/// Transcript checkpoint at a stage leaf (context tag of a live trunk).
pub const TH: &Tag = b"th__";
/// Retained-secret derivation context (context tag of a seeded deck).
pub const CTX: &Tag = b"ctx_";
/// Each output length.
pub const OUT: &Tag = b"out_";
/// DeriveN terminal marker and output count.
pub const OUTS: &Tag = b"outs";

/// `c_e_traffic`.
pub const CET: &Label = b"cet";
/// `early_exporter_secret`.
pub const EES: &Label = b"ees";
/// `binder_key`, non-imported external PSK.
pub const EBK: &Label = b"ebk";
/// `binder_key`, imported PSK.
pub const IBK: &Label = b"ibk";
/// `binder_key`, resumption PSK.
pub const RBK: &Label = b"rbk";
/// A ratchet residue.
pub const DRV: &Label = b"drv";
/// `c_hs_traffic`.
pub const CHT: &Label = b"cht";
/// `s_hs_traffic`.
pub const SHT: &Label = b"sht";
/// `c_ap_traffic`.
pub const CAT: &Label = b"cat";
/// `s_ap_traffic`.
pub const SAT: &Label = b"sat";
/// `exporter_secret`.
pub const EXS: &Label = b"exs";
/// `resumption_secret`.
pub const RSS: &Label = b"rss";
/// `finished_key`.
pub const FIN: &Label = b"fin";
/// Every MAC tag.
pub const MAC: &Label = b"mac";
/// `key_block` (write_key || write_iv).
pub const KEY: &Label = b"key";
/// The next traffic secret.
pub const UPD: &Label = b"upd";
/// `resumption_psk`.
pub const RSP: &Label = b"rsp";
/// `ipsk`.
pub const IPK: &Label = b"ipk";
/// An exporter label secret.
pub const EXL: &Label = b"exl";
/// An exporter output.
pub const EXP: &Label = b"exp";
/// `accept_confirmation` (ECH).
pub const ECA: &Label = b"eca";
/// `hrr_accept_confirmation` (ECH).
pub const HCA: &Label = b"hca";
/// `sn_key` (DTLS 1.3).
pub const SNK: &Label = b"snk";

/// Initial contents of the TLS XOF Key Schedule Labels registry
/// (draft `[iana-labels-table]`), in table order.
pub const REGISTERED: [&Label; 23] = [
    CET, EES, EBK, IBK, RBK, DRV, CHT, SHT, CAT, SAT, EXS, RSS, FIN, MAC, KEY, UPD, RSP, IPK, EXL,
    EXP, ECA, HCA, SNK,
];

/// Whether `l` is in the registry's initial contents.
pub fn is_registered(l: &Label) -> bool {
    REGISTERED.contains(&l)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Labels are pairwise distinct (draft `[labels]`).
    #[test]
    fn labels_distinct() {
        for (i, a) in REGISTERED.iter().enumerate() {
            for b in &REGISTERED[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    /// Tags are pairwise distinct; "outs" is distinct from every tag, and tags
    /// shorter than four letters are padded with underscores.
    #[test]
    fn tags_distinct() {
        let tags = [PSK, SHS, SEED, TH, CTX, OUT, OUTS];
        for (i, a) in tags.iter().enumerate() {
            for b in &tags[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
