//! Deterministic synthetic fixtures from `[test-vectors]`, implemented from prose.
//! No code from the specification's Go or Python implementations is used.
use crate::{
    deck::Deck,
    derive, frame, hex,
    import::ImportedIdentity,
    kdf::{Kdf, Protocol},
    labels,
    schedule::{EarlyStage, PskKind},
    transcript::transcript_hash,
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

pub type Values = Vec<(String, Vec<u8>)>;
fn put(v: &mut Values, name: &str, value: &[u8]) {
    v.push((name.to_string(), value.to_vec()));
}
fn block(k: &derive::TrafficKeys) -> Vec<u8> {
    [&k.key[..], &k.iv[..]].concat()
}

/// All 81 appendix values for one KDF, in appendix order.
pub fn build(kdf: Kdf) -> Values {
    let p = Protocol::Tls13;
    let th = |x: &[u8]| transcript_hash(&kdf, x);
    let mut v = Values::new();
    let inputs = [
        ("TranscriptHash(\"psk\")", b"psk".as_slice()),
        (
            "TranscriptHash(\"asymmetric ...\")",
            b"asymmetric shared secret",
        ),
        ("TranscriptHash(\"epsk\")", b"epsk"),
        ("TH_CH0", b"truncated ClientHello"),
        ("TH_CH", b"ClientHello"),
        ("TH_SH", b"ClientHello..ServerHello"),
        ("TH_PRE_SF", b"ClientHello..before server Finished"),
        ("TH_SF", b"ClientHello..server Finished"),
        ("TH_CF", b"ClientHello..client Finished"),
    ];
    let vals: Vec<_> = inputs.iter().map(|(_, x)| th(x)).collect();
    for ((name, _), value) in inputs.iter().zip(&vals) {
        put(&mut v, name, value);
    }
    let (psk, shared, epsk, ch0, ch, sh, pre_sf, sf, cf) = (
        &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5], &vals[6], &vals[7], &vals[8],
    );
    put(
        &mut v,
        "Init() sequence",
        Deck::early(kdf, p).seq_for_test(),
    );
    let contribution = [frame::frame(labels::PSK), frame::frame(psk)].concat();
    put(&mut v, "Absorb(E,\"psk_\",PSK) contributed", &contribution);
    let e = EarlyStage::new(kdf, p, Some((psk, PskKind::Resumption))).unwrap();
    let (cet, ees) = e.early_traffic(ch).unwrap();
    put(&mut v, "c_e_traffic", &cet);
    put(&mut v, "early_exporter_secret", &ees);
    let (bk, residue) = e.binder_key().unwrap();
    put(&mut v, "binder_key (rbk)", &bk);
    put(
        &mut v,
        "Absorb(E,\"psk_\",\"\") contributed",
        &[frame::frame(labels::PSK), frame::frame(b"")].concat(),
    );
    put(
        &mut v,
        "finished_key (binder)",
        &derive::finished_key(kdf, p, &bk),
    );
    put(
        &mut v,
        "binder verify_data",
        &derive::binder_verify_data(kdf, p, &bk, ch0),
    );
    let ext = EarlyStage::new(kdf, p, Some((psk, PskKind::External))).unwrap();
    let (ebk, _) = ext.binder_key().unwrap();
    put(&mut v, "binder_key (ebk)", &ebk);
    put(
        &mut v,
        "finished_key (external binder)",
        &derive::finished_key(kdf, p, &ebk),
    );
    put(
        &mut v,
        "external binder verify_data",
        &derive::binder_verify_data(kdf, p, &ebk, ch0),
    );
    put(&mut v, "residue E->H", &residue);
    let mut h = e.into_handshake();
    h.absorb(shared).unwrap();
    let (cht, sht) = h.traffic(sh).unwrap();
    put(&mut v, "c_hs_traffic", &cht);
    put(&mut v, "s_hs_traffic", &sht);
    let (cfk, ck) = derive::handshake_record(kdf, p, &cht, 16, 12);
    let (sfk, sk) = derive::handshake_record(kdf, p, &sht, 16, 12);
    put(&mut v, "finished_key (server)", &sfk);
    put(
        &mut v,
        "server verify_data",
        &derive::finished_verify_data(kdf, p, &sfk, pre_sf),
    );
    put(&mut v, "finished_key (client)", &cfk);
    put(
        &mut v,
        "client verify_data",
        &derive::finished_verify_data(kdf, p, &cfk, sf),
    );
    put(&mut v, "key_block (client handshake)", &block(&ck));
    put(&mut v, "key_block (server handshake)", &block(&sk));
    let mut hd = Deck::stage(kdf, p, &residue);
    hd.absorb(labels::SHS, shared);
    put(
        &mut v,
        "residue H->T",
        &hd.derive(labels::DRV, None, 64).unwrap(),
    );
    let app = h.into_application();
    let (cat, sat, exs) = app.traffic(sf).unwrap();
    let rss = app.resumption(cf).unwrap();
    put(&mut v, "c_ap_traffic", &cat);
    put(&mut v, "s_ap_traffic", &sat);
    put(&mut v, "exporter_secret", &exs);
    put(&mut v, "resumption_secret", &rss);
    let (c1, k0) = derive::application_record(kdf, p, &cat, 16, 12);
    let (s1, s0) = derive::application_record(kdf, p, &sat, 16, 12);
    put(&mut v, "key_block", &block(&k0));
    put(&mut v, "write_key = key_block[0..16]", &k0.key);
    put(&mut v, "write_iv  = key_block[16..28]", &k0.iv);
    put(&mut v, "key_block (server application)", &block(&s0));
    put(
        &mut v,
        "key_block (early)",
        &block(&derive::early_record_keys(kdf, p, &cet, 16, 12)),
    );
    put(&mut v, "app_traffic_secret_1", &c1);
    put(&mut v, "server_app_traffic_secret_1", &s1);
    let (c2, k1) = derive::application_record(kdf, p, &c1, 16, 12);
    let (s2, sk1) = derive::application_record(kdf, p, &s1, 16, 12);
    put(&mut v, "key_block (client generation 1)", &block(&k1));
    put(&mut v, "key_block (server generation 1)", &block(&sk1));
    put(&mut v, "app_traffic_secret_2 (lookahead)", &c2);
    put(&mut v, "server_app_traffic_secret_2 (lookahead)", &s2);
    put(
        &mut v,
        "resumption_psk (nonce)",
        &derive::resumption_psk(kdf, p, &rss, b"nonce"),
    );
    put(
        &mut v,
        "resumption_psk (empty nonce)",
        &derive::resumption_psk(kdf, p, &rss, b""),
    );
    for (base, els_name, out_name) in [
        (&exs, "exporter_label_secret", "TLS-Exporter (32 octets)"),
        (
            &ees,
            "early_exporter_label_secret",
            "early exporter (32 octets)",
        ),
    ] {
        put(
            &mut v,
            els_name,
            &derive::exporter_label_secret(kdf, p, base, b"test label").unwrap(),
        );
        put(
            &mut v,
            out_name,
            &derive::exporter(kdf, p, base, b"test label", b"test context", 32).unwrap(),
        );
    }
    let imported = ImportedIdentity::for_kdf(b"external psk identity", b"", p, kdf)
        .import(epsk)
        .unwrap();
    put(&mut v, "ImportedIdentity", &imported.identity);
    put(&mut v, "ipsk (ipk)", &imported.ipsk);
    let random: Vec<u8> = (0..32).collect();
    put(
        &mut v,
        "accept_confirmation",
        &derive::ech_accept_confirmation(kdf, p, &random, &th(b"ech_conf_messages")),
    );
    put(
        &mut v,
        "hrr_accept_confirmation",
        &derive::hrr_ech_accept_confirmation(kdf, p, &random, &th(b"hrr_ech_conf_messages")),
    );
    let dp = Protocol::Dtls13;
    put(
        &mut v,
        "Init() sequence (DTLS)",
        Deck::early(kdf, dp).seq_for_test(),
    );
    let mut dh = EarlyStage::new(kdf, dp, Some((psk, PskKind::Resumption)))
        .unwrap()
        .into_handshake();
    dh.absorb(shared).unwrap();
    let (dcht, _) = dh.traffic(sh).unwrap();
    let (dcat, _, _) = dh.into_application().traffic(sf).unwrap();
    put(&mut v, "c_hs_traffic (DTLS)", &dcht);
    put(&mut v, "c_ap_traffic (DTLS)", &dcat);
    put(
        &mut v,
        "key_block (DTLS)",
        &block(&derive::application_record(kdf, dp, &dcat, 16, 12).1),
    );
    put(
        &mut v,
        "sn_key (DTLS, Nk=16)",
        &derive::sn_key(kdf, dp, &dcat, 16),
    );
    put(
        &mut v,
        "sn_key (DTLS handshake, Nk=16)",
        &derive::sn_key(kdf, dp, &dcht, 16),
    );
    let ie = EarlyStage::new(kdf, p, Some((&imported.ipsk, PskKind::Imported))).unwrap();
    let (ibk, ir) = ie.binder_key().unwrap();
    put(&mut v, "binder_key (ibk)", &ibk);
    put(
        &mut v,
        "finished_key (imported binder)",
        &derive::finished_key(kdf, p, &ibk),
    );
    put(
        &mut v,
        "imported binder verify_data",
        &derive::binder_verify_data(kdf, p, &ibk, ch0),
    );
    put(&mut v, "residue E->H (imported)", &ir);
    let mut ih = ie.into_handshake();
    ih.absorb(shared).unwrap();
    let (ic, is) = ih.traffic(sh).unwrap();
    put(&mut v, "c_hs_traffic (imported)", &ic);
    put(&mut v, "s_hs_traffic (imported)", &is);
    let mut nd = Deck::early(kdf, p);
    nd.absorb(labels::PSK, b"");
    put(
        &mut v,
        "residue E->H (no PSK)",
        &nd.derive(labels::DRV, None, 64).unwrap(),
    );
    let mut nh = EarlyStage::new(kdf, p, None).unwrap().into_handshake();
    nh.absorb(shared).unwrap();
    let (nc, ns) = nh.traffic(sh).unwrap();
    put(&mut v, "c_hs_traffic (no PSK)", &nc);
    put(&mut v, "s_hs_traffic (no PSK)", &ns);

    let hc = derive::exporter(
        kdf,
        p,
        &exs,
        b"EXPORTER-server authenticator handshake context",
        b"",
        64,
    )
    .unwrap();
    let fk = derive::exporter(
        kdf,
        p,
        &exs,
        b"EXPORTER-server authenticator finished key",
        b"",
        64,
    )
    .unwrap();
    put(&mut v, "Handshake Context", &hc);
    put(&mut v, "Finished MAC Key", &fk);
    let der=hex::decode("3081c9307da003020102020101300506032b6570300f310d300b06035504030c0474657374301e170d3236303130313030303030305a170d3336303130313030303030305a300f310d300b06035504030c0474657374302a300506032b657003210003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8300506032b657003410023c815b130eac1285714a01f2b99ffb720c5b23406ff492bbf9a4852f6e6c99f000959f0a2886763e10679390eee02d4e48d6f382729357fc52bde69e6430f07");
    let cert = [
        hex::decode("0b0000d601a50000d10000cc"),
        der,
        hex::decode("0000"),
    ]
    .concat();
    let cv = [hex::decode("0f00004408070040"), alloc::vec![0;64]].concat();
    put(
        &mut v,
        "TranscriptHash(HC || Certificate)",
        &th(&[&hc[..], &cert].concat()),
    );
    let ea_th = th(&[&hc[..], &cert, &cv].concat());
    put(
        &mut v,
        "Finished",
        &derive::mac(kdf, p, &fk, &ea_th, 64).unwrap(),
    );
    let empty_th = th(&[
        &hc[..],
        b"CertificateRequest",
        &hex::decode("0b00000400000000"),
    ]
    .concat());
    put(
        &mut v,
        "Finished (empty authenticator)",
        &derive::mac(kdf, p, &fk, &empty_th, 64).unwrap(),
    );
    for (suffix, components) in [
        ("PSK-only", Vec::new()),
        (
            "hybrid",
            alloc::vec![th(b"hybrid component 1"), th(b"hybrid component 2")],
        ),
    ] {
        let mut vh = EarlyStage::new(kdf, p, Some((psk, PskKind::Resumption)))
            .unwrap()
            .into_handshake();
        for c in &components {
            vh.absorb(c).unwrap();
        }
        let (c, s) = vh.traffic(sh).unwrap();
        let (a, _, _) = vh.into_application().traffic(sf).unwrap();
        put(&mut v, &alloc::format!("c_hs_traffic ({suffix})"), &c);
        put(&mut v, &alloc::format!("s_hs_traffic ({suffix})"), &s);
        put(&mut v, &alloc::format!("c_ap_traffic ({suffix})"), &a);
    }
    v
}

/// Print values as tab-separated name/hex pairs for a structured cross-check.
pub fn generate() -> String {
    let mut out = String::new();
    for k in [crate::SHAKE256, crate::TURBOSHAKE256] {
        for (name, value) in build(k) {
            out.push_str(&alloc::format!(
                "{}\t{}\t{}\n",
                k.name,
                name,
                hex::encode(&value)
            ));
        }
    }
    out
}
