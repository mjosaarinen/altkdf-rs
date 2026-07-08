//! Deterministic generation of the Appendix C test-vector sets (draft App. C).
//!
//! Every derivation of the draft is run over a fixed, fully-specified set of
//! inputs and emitted as self-describing JSON: each record names an operation
//! (`op`), lists all of its arguments (`args`), and pins the resulting octets
//! (`expected`). Because every derived output binds the governing cipher suite,
//! no *final* vector can exist before IANA assigns code points (draft §14 OPEN
//! ISSUE); the sets use the declared private-use placeholders `0xFF01..=0xFF05`
//! (draft Appendix C).
//!
//! The generator is deterministic and dependency-free, so the emitted JSON is
//! byte-stable: [`crate::vectors::generate_json`] is the single source of truth,
//! called both by the `gen_vectors` example (which writes the package-local
//! files under `vectors/`) and by `tests/vectors.rs` (which asserts the
//! committed files are current). An independent implementation reproduces the
//! same JSON from the draft alone (draft Appendix C; see `vectors/reproduce.py`).
//!
//! The inputs are simple deterministic ramps `pat(tag, n)[i] = tag + i (mod
//! 256)`, one distinct `tag` per role, so a reader can trace every field back to
//! its source. Transcript checkpoints (`TH_*`) are supplied as opaque 64-octet
//! inputs: `TranscriptHash` takes no cipher-suite input and the schedule merely
//! consumes its outputs (draft §2.1), so the transcript hash is pinned by its
//! own `transcript_hash` records and the schedule records treat `TH_*` as data.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::derive::{
    self, binder_verify_data, ech_accept_confirmation, exporter, finished_verify_data,
    hrr_ech_accept_confirmation, key_update, record_keys, resumption_psk, BinderKind,
};
use crate::fips;
use crate::import::ImportedIdentityV2;
use crate::mac::mac;
use crate::profile::Profile;
use crate::schedule::{run, Psk, ScheduleInputs};
use crate::suites::{self, CipherSuite};
use crate::transcript::{transcript_hash, transcript_hash_after_hrr};

/// A deterministic input ramp: `pat(tag, n)[i] = tag + i (mod 256)`.
fn pat(tag: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| tag.wrapping_add(i as u8)).collect()
}

/// One emitted value: hex octets, an integer, an ASCII string, JSON null, or a
/// list of hex octet strings (for multi-component (EC)DHE).
enum Val {
    Hex(Vec<u8>),
    Int(u64),
    Str(&'static str),
    Null,
    ArrHex(Vec<Vec<u8>>),
}

/// A `"key": value` pair inside an `args` or `expected` object. Order is
/// preserved so the JSON is byte-stable.
struct Field {
    key: &'static str,
    val: Val,
}

fn f(key: &'static str, val: Val) -> Field {
    Field { key, val }
}

/// One test vector: a named operation with its arguments and expected outputs.
struct Record {
    name: String,
    op: &'static str,
    args: Vec<Field>,
    expected: Vec<Field>,
}

/// Accumulates the records for one profile's vector set.
struct Gen<'a> {
    profile: &'a Profile,
    /// The cipher suites of this profile, in code-point order (draft §6).
    suites: &'a [CipherSuite],
    records: Vec<Record>,
}

impl<'a> Gen<'a> {
    /// The primary suite whose profile parameters drive the single-suite
    /// derivations (record keys, exporters, MACs, …): the first suite of the
    /// profile in code-point order.
    fn suite0(&self) -> u16 {
        self.suites[0].code_point
    }

    fn push(
        &mut self,
        name: impl Into<String>,
        op: &'static str,
        args: Vec<Field>,
        expected: Vec<Field>,
    ) {
        self.records.push(Record {
            name: name.into(),
            op,
            args,
            expected,
        });
    }

    /// Transcript-hash pins: empty, a short string, and a multi-block input
    /// (draft §2.1). Independent of any cipher suite.
    fn transcript_pins(&mut self) {
        for (name, x) in [
            ("th_empty", Vec::new()),
            ("th_abc", b"abc".to_vec()),
            ("th_multiblock", pat(0x01, 200)),
        ] {
            let out = transcript_hash(self.profile, &x);
            self.push(
                name,
                "transcript_hash",
                vec![f("x", Val::Hex(x))],
                vec![f("hash", Val::Hex(out))],
            );
        }

        // HelloRetryRequest synthetic transcript (draft §2.1, RFC 8446 §4.4.1).
        let ch1 = pat(0x02, 96);
        let rest = pat(0x03, 128); // HelloRetryRequest || ClientHello2 || ...
        let out = transcript_hash_after_hrr(self.profile, &ch1, &rest);
        self.push(
            "th_after_hrr",
            "transcript_hash_after_hrr",
            vec![f("client_hello1", Val::Hex(ch1)), f("rest", Val::Hex(rest))],
            vec![f("hash", Val::Hex(out))],
        );
    }

    /// A full schedule trace, plus the no-PSK and PSK-only variants (draft §7.3,
    /// §7.3.1). Emits every stage secret and leaf of each trace in one record.
    fn schedule_traces(&mut self) {
        let th_ch = pat(0x10, 64);
        let th_sh = pat(0x20, 64);
        let th_sf = pat(0x30, 64);
        let th_cf = pat(0x40, 64);
        let psk = pat(0x01, Psk::LEN);
        let dh0 = pat(0xD0, 32);
        let dh1 = pat(0xD8, 32);
        let s0 = self.suite0();

        // Full 1-RTT trace: PSK offered (early leaves present) and a single
        // (EC)DHE secret. recorded == selected == s0 (draft §4).
        self.schedule_record(
            "schedule_full",
            Some(&psk),
            &[&dh0],
            s0,
            s0,
            &th_ch,
            &th_sh,
            &th_sf,
            &th_cf,
        );

        // No-PSK: Absorb(E,"psk",""); early_secret is the profile's public
        // constant and no early leaves are produced (draft §7.3.1).
        self.schedule_record(
            "schedule_no_psk",
            None,
            &[&dh0],
            s0,
            s0,
            &th_ch,
            &th_sh,
            &th_sf,
            &th_cf,
        );

        // PSK-only: the "dh" absorb is omitted entirely (draft §7.3.1).
        self.schedule_record(
            "schedule_psk_only",
            Some(&psk),
            &[],
            s0,
            s0,
            &th_ch,
            &th_sh,
            &th_sf,
            &th_cf,
        );

        // Hybrid (EC)DHE: two components absorbed in group order, never
        // concatenated (draft §7.3).
        self.schedule_record(
            "schedule_full_hybrid",
            Some(&psk),
            &[&dh0, &dh1],
            s0,
            s0,
            &th_ch,
            &th_sh,
            &th_sf,
            &th_cf,
        );

        // Artificial wiring pin: recorded != selected (both this profile) to bind
        // the per-output suite routing — early leaves bind the *recorded* suite,
        // the handshake and application leaves bind *selected* (draft §4, §7.3).
        // This is NOT a valid handshake: §4 forbids a server selecting a PSK
        // whose recorded suite differs from the one it selects. It exists only so
        // the vector set catches a recorded/selected mix-up that the
        // recorded == selected traces above cannot.
        let recorded = self.suites[0].code_point;
        let selected = self.suites[1].code_point;
        self.schedule_record(
            "schedule_suite_split",
            Some(&psk),
            &[&dh0],
            recorded,
            selected,
            &th_ch,
            &th_sh,
            &th_sf,
            &th_cf,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn schedule_record(
        &mut self,
        name: &str,
        psk: Option<&[u8]>,
        dh: &[&[u8]],
        recorded_suite: u16,
        selected_suite: u16,
        th_ch: &[u8],
        th_sh: &[u8],
        th_sf: &[u8],
        th_cf: &[u8],
    ) {
        let inp = ScheduleInputs {
            psk: psk.map(|p| Psk::new(p).expect("64-octet PSK")),
            dhe_components: dh,
            recorded_suite,
            selected_suite,
            th_ch,
            th_sh,
            th_sf,
            th_cf,
        };
        let out = run(self.profile, &inp);

        let args = vec![
            f(
                "psk",
                match psk {
                    Some(p) => Val::Hex(p.to_vec()),
                    None => Val::Null,
                },
            ),
            f(
                "dhe_components",
                Val::ArrHex(dh.iter().map(|c| c.to_vec()).collect()),
            ),
            f("recorded_suite", Val::Int(recorded_suite as u64)),
            f("selected_suite", Val::Int(selected_suite as u64)),
            f("th_ch", Val::Hex(th_ch.to_vec())),
            f("th_sh", Val::Hex(th_sh.to_vec())),
            f("th_sf", Val::Hex(th_sf.to_vec())),
            f("th_cf", Val::Hex(th_cf.to_vec())),
        ];
        let opt = |v: Option<Vec<u8>>| match v {
            Some(b) => Val::Hex(b),
            None => Val::Null,
        };
        let expected = vec![
            f("early_secret", Val::Hex(out.early_secret)),
            f("c_e_traffic", opt(out.c_e_traffic)),
            f("e_exp_master", opt(out.e_exp_master)),
            f("main_secret", Val::Hex(out.main_secret)),
            f("c_hs_traffic", Val::Hex(out.c_hs_traffic)),
            f("s_hs_traffic", Val::Hex(out.s_hs_traffic)),
            f("c_ap_traffic", Val::Hex(out.c_ap_traffic)),
            f("s_ap_traffic", Val::Hex(out.s_ap_traffic)),
            f("exp_master", Val::Hex(out.exp_master)),
            f("res_master", Val::Hex(out.res_master)),
        ];
        self.push(name, "schedule", args, expected);
    }

    /// PSK binders, external and resumption, derived in two steps from a fixed
    /// early_secret keyed by the PSK (draft §5.5).
    fn binders(&mut self) {
        let early_secret = pat(0xE0, 64);
        let th_ch0 = pat(0x50, 64);
        let s0 = self.suite0();
        for (name, kind, label) in [
            ("binder_external", BinderKind::External, "ext binder"),
            ("binder_resumption", BinderKind::Resumption, "res binder"),
        ] {
            let out = binder_verify_data(self.profile, &early_secret, kind, s0, &th_ch0);
            self.push(
                name,
                "binder_verify_data",
                vec![
                    f("early_secret", Val::Hex(early_secret.clone())),
                    f("kind", Val::Str(label)),
                    f("suite", Val::Int(s0 as u64)),
                    f("th_ch0", Val::Hex(th_ch0.clone())),
                ],
                vec![f("verify_data", Val::Hex(out))],
            );
        }
    }

    /// Record write_key / write_iv for every suite of the profile — both key
    /// lengths (draft §5.3, Appendix C).
    fn record_key_blocks(&mut self) {
        let ts = pat(0x70, 64);
        for s in self.suites {
            let (k, iv) = record_keys(self.profile, &ts, s.code_point, s.nk, s.nn);
            self.push(
                format!("record_keys_{}", s.name),
                "record_keys",
                vec![
                    f("traffic_secret", Val::Hex(ts.clone())),
                    f("suite", Val::Int(s.code_point as u64)),
                    f("nk", Val::Int(s.nk as u64)),
                    f("nn", Val::Int(s.nn as u64)),
                ],
                vec![
                    f("write_key", Val::Hex(k.to_vec())),
                    f("write_iv", Val::Hex(iv.to_vec())),
                ],
            );
        }
    }

    /// Client and server Finished verify_data (draft §5.5).
    fn finished(&mut self) {
        let s0 = self.suite0();
        for (name, base_tag, th_tag) in [
            ("finished_server", 0x72u8, 0x30u8),
            ("finished_client", 0x73u8, 0x40u8),
        ] {
            let base_key = pat(base_tag, 64);
            let th = pat(th_tag, 64);
            let out = finished_verify_data(self.profile, &base_key, s0, &th);
            self.push(
                name,
                "finished_verify_data",
                vec![
                    f("base_key", Val::Hex(base_key)),
                    f("suite", Val::Int(s0 as u64)),
                    f("th", Val::Hex(th)),
                ],
                vec![f("verify_data", Val::Hex(out))],
            );
        }
    }

    /// Two key-update generations, N+1 derived from N (draft §5.4).
    fn key_updates(&mut self) {
        let s0 = self.suite0();
        let gen0 = pat(0x71, 64);
        let gen1 = key_update(self.profile, &gen0, s0);
        let gen2 = key_update(self.profile, &gen1, s0);
        self.push(
            "key_update_gen1",
            "key_update",
            vec![
                f("app_traffic_secret", Val::Hex(gen0)),
                f("suite", Val::Int(s0 as u64)),
            ],
            vec![f("next", Val::Hex(gen1.to_vec()))],
        );
        self.push(
            "key_update_gen2",
            "key_update",
            vec![
                f("app_traffic_secret", Val::Hex(gen1.to_vec())),
                f("suite", Val::Int(s0 as u64)),
            ],
            vec![f("next", Val::Hex(gen2.to_vec()))],
        );
    }

    /// Resumption PSKs with a present and an empty ticket nonce (draft §5.7).
    fn resumption(&mut self) {
        let s0 = self.suite0();
        let res_master = pat(0x74, 64);
        for (name, nonce) in [
            ("resumption_psk_nonce", pat(0x12, 8)),
            ("resumption_psk_empty_nonce", Vec::new()),
        ] {
            let out = resumption_psk(self.profile, &res_master, s0, &nonce);
            self.push(
                name,
                "resumption_psk",
                vec![
                    f("res_master", Val::Hex(res_master.clone())),
                    f("suite", Val::Int(s0 as u64)),
                    f("ticket_nonce", Val::Hex(nonce)),
                ],
                vec![f("resumption_psk", Val::Hex(out.to_vec()))],
            );
        }
    }

    /// Exporters, including an empty-context exporter and the early exporter
    /// (draft §5.6).
    fn exporters(&mut self) {
        let s0 = self.suite0();
        for (name, master_tag, label, context, length) in [
            ("exporter", 0x73u8, "EXPORTER-test", pat(0x11, 16), 48usize),
            (
                "exporter_empty_context",
                0x73u8,
                "EXPORTER-test",
                Vec::new(),
                32usize,
            ),
            (
                "early_exporter",
                0xE1u8,
                "EXPORTER-early",
                pat(0x11, 16),
                48usize,
            ),
        ] {
            let master = pat(master_tag, 64);
            let out = exporter(
                self.profile,
                &master,
                s0,
                label.as_bytes(),
                &context,
                length,
            )
            .expect("length within 0xFFFE");
            self.push(
                name,
                "exporter",
                vec![
                    f("exp_master", Val::Hex(master)),
                    f("suite", Val::Int(s0 as u64)),
                    f("label", Val::Str(label)),
                    f("context", Val::Hex(context)),
                    f("length", Val::Int(length as u64)),
                ],
                vec![f("out", Val::Hex(out.to_vec()))],
            );
        }
    }

    /// Both ECH acceptance confirmations (draft §5.8).
    fn ech(&mut self) {
        let s0 = self.suite0();
        let random = pat(0x75, 32);
        let conf = pat(0x13, 40);
        let out = ech_accept_confirmation(self.profile, &random, s0, &conf);
        self.push(
            "ech_accept_confirmation",
            "ech_accept_confirmation",
            vec![
                f("client_hello_inner_random", Val::Hex(random.clone())),
                f("selected_suite", Val::Int(s0 as u64)),
                f("ech_conf_messages", Val::Hex(conf.clone())),
            ],
            vec![f("confirmation", Val::Hex(out))],
        );
        let hrr = hrr_ech_accept_confirmation(self.profile, &random, s0, &conf);
        self.push(
            "hrr_ech_accept_confirmation",
            "hrr_ech_accept_confirmation",
            vec![
                f("client_hello_inner_random", Val::Hex(random)),
                f("selected_suite", Val::Int(s0 as u64)),
                f("hrr_ech_conf_messages", Val::Hex(conf)),
            ],
            vec![f("confirmation", Val::Hex(hrr))],
        );
    }

    /// A raw `MAC` KAT with fully specified arguments (draft §5.2): pins the MAC
    /// byte layout directly (TurboKMAC256 / KMAC256) over this profile.
    fn mac_kat(&mut self) {
        let s0 = self.suite0();
        let key = pat(0x78, 64);
        let message = pat(0x15, 32);
        let out = mac(
            self.profile,
            &key,
            s0,
            b"finished",
            &message,
            self.profile.flen,
        );
        self.push(
            "mac_kat",
            "mac",
            vec![
                f("key", Val::Hex(key)),
                f("suite", Val::Int(s0 as u64)),
                f("label", Val::Str("finished")),
                f("message", Val::Hex(message)),
                f("l", Val::Int(self.profile.flen as u64)),
            ],
            vec![f("tag", Val::Hex(out))],
        );
    }

    /// PSK-importer ipsk variants (draft §5.9, §10). The TurboSHAKE256 set
    /// carries three, including an epsk at the 0xFFFE frame limit; the SHAKE256
    /// set carries one (draft Appendix C.1/C.2).
    fn psk_imports(&mut self, extra_variants: bool) {
        let target = &self.suites[0];
        // A real `ImportedIdentityV2` (draft §10): its serialization is both the
        // wire `PskIdentity.identity` and the derivation context (draft §5.9), and
        // is recorded as an expected output so the checker validates the encoding.
        let external_identity: &[u8] = b"deck importer test identity";
        let context = pat(0x14, 20);
        let iid = ImportedIdentityV2::for_suite(external_identity, &context, target);

        let mut variants: Vec<(&str, Vec<u8>)> = vec![("psk_import", pat(0x76, 32))];
        if extra_variants {
            variants.push(("psk_import_64", pat(0x77, 64)));
            // epsk at the frame limit: exactly 0xFFFE octets (draft §10).
            variants.push(("psk_import_frame_limit", pat(0x00, 0xFFFE)));
        }
        for (name, epsk) in variants {
            let imported = iid.import(&epsk).expect("valid import");
            self.push(
                name,
                "psk_import",
                vec![
                    f("external_identity", Val::Hex(external_identity.to_vec())),
                    f("context", Val::Hex(context.clone())),
                    f("target_protocol", Val::Int(iid.target_protocol as u64)),
                    f("target_ciphersuite", Val::Int(target.code_point as u64)),
                    f("epsk", Val::Hex(epsk)),
                ],
                vec![
                    f("imported_identity_v2", Val::Hex(imported.identity)),
                    f("ipsk", Val::Hex(imported.ipsk.to_vec())),
                ],
            );
        }
    }

    /// Suite-binding cross-checks (draft §4, §15.3): the same expansion under
    /// two different governing suites yields unrelated outputs. Emitted as two
    /// `expand` records; the reproduction checks they differ.
    fn suite_binding(&mut self) {
        let secret = pat(0x79, 64);
        let (a, b) = (self.suites[0].code_point, self.suites[1].code_point);
        for (name, suite) in [("suite_bind_a", a), ("suite_bind_b", b)] {
            let out = derive::expand(self.profile, &secret, b"c hs traffic", suite, None, 64);
            self.push(
                name,
                "expand",
                vec![
                    f("secret", Val::Hex(secret.clone())),
                    f("label", Val::Str("c hs traffic")),
                    f("suite", Val::Int(suite as u64)),
                    f("context", Val::Null),
                    f("l", Val::Int(64)),
                ],
                vec![f("out", Val::Hex(out.to_vec()))],
            );
        }
    }
}

/// Build the full record list for a profile and its suites.
fn build(profile: &Profile, suites: &[CipherSuite], extra_import_variants: bool) -> Vec<Record> {
    let mut g = Gen {
        profile,
        suites,
        records: Vec::new(),
    };
    g.transcript_pins();
    g.schedule_traces();
    g.binders();
    g.record_key_blocks();
    g.finished();
    g.key_updates();
    g.resumption();
    g.exporters();
    g.ech();
    g.mac_kat();
    g.psk_imports(extra_import_variants);
    g.suite_binding();
    g.records
}

// -- JSON emission (hand-rolled, byte-stable, dependency-free) --------------

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xF) as u32, 16).unwrap());
    }
    s
}

/// Append a JSON string literal for an ASCII value, escaping `"` and `\`.
fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
}

fn emit_val(out: &mut String, v: &Val) {
    match v {
        Val::Hex(b) => json_str(out, &hex(b)),
        Val::Int(n) => out.push_str(&n.to_string()),
        Val::Str(s) => json_str(out, s),
        Val::Null => out.push_str("null"),
        Val::ArrHex(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                json_str(out, &hex(item));
            }
            out.push(']');
        }
    }
}

/// Emit an `args`/`expected` object at the given indentation.
fn emit_fields(out: &mut String, fields: &[Field], indent: &str) {
    if fields.is_empty() {
        out.push_str("{}");
        return;
    }
    out.push_str("{\n");
    for (i, field) in fields.iter().enumerate() {
        out.push_str(indent);
        out.push_str("  ");
        json_str(out, field.key);
        out.push_str(": ");
        emit_val(out, &field.val);
        if i + 1 < fields.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(indent);
    out.push('}');
}

/// Serialize a profile's vector set to byte-stable, human-readable JSON.
///
/// `profile_name` is the profile name (e.g. `"TLS13-TURBOSHAKE256"`);
/// `suites` are its cipher suites in code-point order; `extra_import_variants`
/// selects the three-variant PSK importer coverage of Appendix C.1.
pub fn generate_json(
    profile: &Profile,
    profile_name: &str,
    suites: &[CipherSuite],
    extra_import_variants: bool,
) -> String {
    let records = build(profile, suites, extra_import_variants);

    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"draft\": \"draft-sullivan-tls-xof-ciphers-00\",\n");
    out.push_str("  \"profile\": ");
    json_str(&mut out, profile_name);
    out.push_str(",\n");
    out.push_str("  \"profile_id_hex\": ");
    json_str(&mut out, &hex(profile.profile_id));
    out.push_str(",\n");
    out.push_str(&format!("  \"rounds\": {},\n", profile.rounds));
    out.push_str(&format!("  \"secret_len\": {},\n", profile.secret_len));
    out.push_str(&format!("  \"flen\": {},\n", profile.flen));
    out.push_str("  \"suites\": [\n");
    for (i, s) in suites.iter().enumerate() {
        out.push_str("    { \"code_point\": ");
        out.push_str(&s.code_point.to_string());
        out.push_str(", \"name\": ");
        json_str(&mut out, s.name);
        out.push_str(&format!(", \"nk\": {}, \"nn\": {} }}", s.nk, s.nn));
        if i + 1 < suites.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ],\n");
    out.push_str(
        "  \"note\": \"Placeholder code points 0xFF01..0xFF05 (draft \\u00a714 OPEN ISSUE). Inputs are deterministic ramps pat(tag,n)[i]=tag+i mod 256. record_count counts records in THIS set; a 'schedule' record bundles a whole \\u00a77.3 trace, so it is not the Appendix C enumeration (44 for TURBOSHAKE256, 40 for SHAKE256, counted per derived secret).\",\n",
    );
    out.push_str(&format!("  \"record_count\": {},\n", records.len()));
    out.push_str("  \"vectors\": [\n");
    for (i, r) in records.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str("      \"name\": ");
        json_str(&mut out, &r.name);
        out.push_str(",\n");
        out.push_str("      \"op\": ");
        json_str(&mut out, r.op);
        out.push_str(",\n");
        out.push_str("      \"args\": ");
        emit_fields(&mut out, &r.args, "      ");
        out.push_str(",\n");
        out.push_str("      \"expected\": ");
        emit_fields(&mut out, &r.expected, "      ");
        out.push('\n');
        out.push_str("    }");
        if i + 1 < records.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

/// The TurboSHAKE256 vector set (draft Appendix C.1): three suites, three PSK
/// importer variants.
pub fn turboshake256_json() -> String {
    generate_json(
        &crate::profile::TURBOSHAKE256,
        "TLS13-TURBOSHAKE256",
        &[
            suites::TLS_AES_128_GCM_TURBOSHAKE256,
            suites::TLS_AES_256_GCM_TURBOSHAKE256,
            suites::TLS_CHACHA20_POLY1305_TURBOSHAKE256,
        ],
        true,
    )
}

/// The SHAKE256 vector set (draft Appendix C.2): two suites, one PSK importer
/// variant.
pub fn shake256_json() -> String {
    generate_json(
        &crate::profile::SHAKE256,
        "TLS13-SHAKE256",
        &[
            suites::TLS_AES_128_GCM_SHAKE256,
            suites::TLS_AES_256_GCM_SHAKE256,
        ],
        false,
    )
}

// -- Appendix D: the informative FIPS-component schedule --------------------
//
// Not part of Appendix C: the FIPS-component schedule (draft Appendix D) is
// informative, has no code point, no cipher suite, and no draft vectors. These
// self-generated vectors pin this crate's *interpretation* of Appendix D (the
// choices documented in `crate::fips`) and are independently reproduced by
// `vectors/reproduce.py`. Every value ultimately rests on KMAC256 (SP 800-185
// Sample #4), the one anchored primitive.

/// Build the FIPS-component schedule vector records (draft Appendix D). Uses the
/// same deterministic ramps as the deck sets so a reader can trace each field.
fn fips_records() -> Vec<Record> {
    let mut records = Vec::new();
    let mut push = |name: &str, op: &'static str, args: Vec<Field>, expected: Vec<Field>| {
        records.push(Record {
            name: name.to_string(),
            op,
            args,
            expected,
        });
    };

    // TranscriptHash = plain SHAKE256(·, 64) (no "tls13 hash" prefix).
    for (name, x) in [
        ("fips_th_empty", Vec::new()),
        ("fips_th_multiblock", pat(0x01, 200)),
    ] {
        let out = fips::transcript_hash(&x);
        push(
            name,
            "fips_transcript_hash",
            vec![f("messages", Val::Hex(x))],
            vec![f("hash", Val::Hex(out))],
        );
    }

    // Extract = KMAC256(K=salt, X=IKM, L=512, S="").
    let salt = pat(0x50, 64);
    let ikm = pat(0x60, 32);
    push(
        "fips_extract",
        "fips_extract",
        vec![
            f("salt", Val::Hex(salt.clone())),
            f("ikm", Val::Hex(ikm.clone())),
        ],
        vec![f("prk", Val::Hex(fips::extract(&salt, &ikm).to_vec()))],
    );

    // Expand-Label: a one-block (64-octet) and a two-block (100-octet) request,
    // pinning the SP 800-108 counter-mode chaining and the length binding.
    let secret = pat(0x70, 64);
    for (name, length) in [
        ("fips_expand_label_1blk", 64usize),
        ("fips_expand_label_2blk", 100),
    ] {
        let out = fips::expand_label(&secret, b"c hs traffic", b"", length);
        push(
            name,
            "fips_expand_label",
            vec![
                f("secret", Val::Hex(secret.clone())),
                f("label", Val::Str("c hs traffic")),
                f("context", Val::Hex(Vec::new())),
                f("length", Val::Int(length as u64)),
            ],
            vec![f("out", Val::Hex(out.to_vec()))],
        );
    }

    // Full schedule traces: no-PSK and PSK (with a concatenated (EC)DHE secret).
    let th_ch = pat(0x10, 64);
    let th_sh = pat(0x20, 64);
    let th_sf = pat(0x30, 64);
    let th_cf = pat(0x40, 64);
    let psk = pat(0x01, fips::HLEN);
    let dhe = pat(0xD0, 32);
    for (name, psk_opt) in [
        ("fips_schedule_no_psk", None),
        ("fips_schedule_full", Some(psk.as_slice())),
    ] {
        let inp = fips::FipsInputs {
            psk: psk_opt,
            dhe: &dhe,
            th_ch: &th_ch,
            th_sh: &th_sh,
            th_sf: &th_sf,
            th_cf: &th_cf,
        };
        let out = fips::run(&inp);
        let opt = |o: Option<Vec<u8>>| match o {
            Some(v) => Val::Hex(v),
            None => Val::Null,
        };
        push(
            name,
            "fips_schedule",
            vec![
                f(
                    "psk",
                    match psk_opt {
                        Some(p) => Val::Hex(p.to_vec()),
                        None => Val::Null,
                    },
                ),
                f("dhe", Val::Hex(dhe.clone())),
                f("th_ch", Val::Hex(th_ch.clone())),
                f("th_sh", Val::Hex(th_sh.clone())),
                f("th_sf", Val::Hex(th_sf.clone())),
                f("th_cf", Val::Hex(th_cf.clone())),
            ],
            vec![
                f("early_secret", Val::Hex(out.early_secret)),
                f("c_e_traffic", opt(out.c_e_traffic)),
                f("e_exp_master", opt(out.e_exp_master)),
                f("handshake_secret", Val::Hex(out.handshake_secret)),
                f("c_hs_traffic", Val::Hex(out.c_hs_traffic)),
                f("s_hs_traffic", Val::Hex(out.s_hs_traffic)),
                f("master_secret", Val::Hex(out.master_secret)),
                f("c_ap_traffic", Val::Hex(out.c_ap_traffic)),
                f("s_ap_traffic", Val::Hex(out.s_ap_traffic)),
                f("exp_master", Val::Hex(out.exp_master)),
                f("res_master", Val::Hex(out.res_master)),
            ],
        );
    }

    // Leaf derivations, on the AES-128 record-key sizes (Nk=16, Nn=12, §6).
    let base = pat(0x80, 64);
    let th = pat(0x90, 64);
    push(
        "fips_finished",
        "fips_finished_verify_data",
        vec![
            f("base_key", Val::Hex(base.clone())),
            f("th", Val::Hex(th.clone())),
        ],
        vec![f(
            "verify_data",
            Val::Hex(fips::finished_verify_data(&base, &th)),
        )],
    );

    let ts = pat(0xA0, 64);
    let (wk, iv) = fips::record_keys(&ts, 16, 12);
    push(
        "fips_record_keys",
        "fips_record_keys",
        vec![
            f("traffic_secret", Val::Hex(ts.clone())),
            f("nk", Val::Int(16)),
            f("nn", Val::Int(12)),
        ],
        vec![
            f("write_key", Val::Hex(wk.to_vec())),
            f("write_iv", Val::Hex(iv.to_vec())),
        ],
    );

    push(
        "fips_key_update",
        "fips_key_update",
        vec![f("app_traffic_secret", Val::Hex(ts.clone()))],
        vec![f("next", Val::Hex(fips::key_update(&ts).to_vec()))],
    );

    let em = pat(0xB0, 64);
    let exp_ctx = pat(0xB8, 16);
    push(
        "fips_exporter",
        "fips_exporter",
        vec![
            f("exp_master", Val::Hex(em.clone())),
            f("label", Val::Str("EXPORTER-test")),
            f("context", Val::Hex(exp_ctx.clone())),
            f("length", Val::Int(32)),
        ],
        vec![f(
            "out",
            Val::Hex(fips::exporter(&em, b"EXPORTER-test", &exp_ctx, 32).to_vec()),
        )],
    );

    let rm = pat(0xC0, 64);
    let nonce = pat(0xC8, 8);
    push(
        "fips_resumption",
        "fips_resumption_psk",
        vec![
            f("res_master", Val::Hex(rm.clone())),
            f("ticket_nonce", Val::Hex(nonce.clone())),
        ],
        vec![f(
            "resumption_psk",
            Val::Hex(fips::resumption_psk(&rm, &nonce).to_vec()),
        )],
    );

    let early = pat(0xE0, 64);
    let th_ch0 = pat(0xE8, 64);
    for (name, kind, kind_str) in [
        ("fips_binder_ext", fips::BinderKind::External, "ext binder"),
        (
            "fips_binder_res",
            fips::BinderKind::Resumption,
            "res binder",
        ),
    ] {
        push(
            name,
            "fips_binder_verify_data",
            vec![
                f("early_secret", Val::Hex(early.clone())),
                f("kind", Val::Str(kind_str)),
                f("th_ch0", Val::Hex(th_ch0.clone())),
            ],
            vec![f(
                "verify_data",
                Val::Hex(fips::binder_verify_data(&early, kind, &th_ch0)),
            )],
        );
    }

    records
}

/// The FIPS-component schedule vector set (draft Appendix D, **informative**).
/// Byte-stable JSON, same shape as the deck sets but with no profile/suite header
/// (the FIPS schedule binds no cipher suite). Reproduced by `vectors/reproduce.py`.
pub fn fips_json() -> String {
    let records = fips_records();

    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"draft\": \"draft-sullivan-tls-xof-ciphers-00\",\n");
    out.push_str("  \"schedule\": \"FIPS-component (Appendix D)\",\n");
    out.push_str("  \"informative\": true,\n");
    out.push_str(
        "  \"note\": \"Draft Appendix D is informative: no code point, no cipher suite, no IANA registration. RFC 8446 \\u00a77.1 extract-and-expand with PRF replaced by KMAC256 (SP 800-185) throughout, Extract from SP 800-56C, TranscriptHash = SHAKE256(.,64). These vectors pin this crate's documented interpretation (crate::fips); the draft gives none. Inputs are deterministic ramps pat(tag,n)[i]=tag+i mod 256.\",\n",
    );
    out.push_str(&format!("  \"record_count\": {},\n", records.len()));
    out.push_str("  \"vectors\": [\n");
    for (i, r) in records.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str("      \"name\": ");
        json_str(&mut out, &r.name);
        out.push_str(",\n");
        out.push_str("      \"op\": ");
        json_str(&mut out, r.op);
        out.push_str(",\n");
        out.push_str("      \"args\": ");
        emit_fields(&mut out, &r.args, "      ");
        out.push_str(",\n");
        out.push_str("      \"expected\": ");
        emit_fields(&mut out, &r.expected, "      ");
        out.push('\n');
        out.push_str("    }");
        if i + 1 < records.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}
