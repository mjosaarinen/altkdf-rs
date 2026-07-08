# deck-schedule/vectors

Machine-readable test vectors for both deck profiles (draft Appendix C) and the
informative FIPS-component schedule (draft Appendix D).

Two families:

1. **Public primitive KATs** — RFC 9861 (TurboSHAKE256), FIPS 202 (SHAKE256),
   SP 800-185 (KMAC256). They validate the permutation, sponge, and MAC of
   `deck-schedule` independently of the draft, and live as unit tests in
   `deck-schedule/src/{sponge,mac}.rs`.

2. **Draft Appendix C vectors** — the full schedule trace and every §5
   derivation, under the `0xFF01..=0xFF05` placeholder code points. Because
   every derived output binds the governing cipher suite, no *final* vector can
   exist before IANA assigns code points (draft §14 OPEN ISSUE). Until then,
   `deck-schedule` generates these and an independent implementation reproduces
   them (draft Appendix C).

## Files

- `turboshake256.json` — TLS13-TURBOSHAKE256 set (draft App. C.1), 31 records.
- `shake256.json` — TLS13-SHAKE256 set (draft App. C.2), 28 records.
- `fips.json` — the informative **FIPS-component schedule** (draft Appendix D):
  RFC 8446 §7.1 with KMAC256 as the PRF throughout, Extract from SP 800-56C,
  TranscriptHash = SHAKE256(·, 64). Appendix D is non-normative and defines no
  profile/code point/suite, so this set has no profile header and pins this
  crate's documented interpretation (`deck-schedule/src/fips.rs`); the draft
  gives no vectors for it. 14 records.
- `reproduce.py` — the independent reproduction (below).

`record_count` in each file is the number of records in *that* file. It is not
the draft's Appendix C figure (44 / 40), which counts individual derived secrets:
a single `schedule` record here bundles a whole §7.3 trace (~8–10 secrets), so
the two counts intentionally differ.

Regenerate the JSON from the workspace root with `make vectors`
(`cargo run -p deck-schedule --example gen_vectors`). The generator is deterministic, and
`deck-schedule/tests/vectors.rs` fails if the committed files drift from it.

## Format

Each file is one JSON object:

```jsonc
{
  "draft": "draft-sullivan-tls-xof-ciphers-00",
  "profile": "TLS13-TURBOSHAKE256",
  "profile_id_hex": "...", "rounds": 12, "secret_len": 64, "flen": 64,
  "suites": [ { "code_point": 65281, "name": "...", "nk": 16, "nn": 12 }, ... ],
  "note": "...",
  "record_count": 31,
  "vectors": [
    { "name": "th_abc", "op": "transcript_hash",
      "args": { "x": "616263" },
      "expected": { "hash": "<hex>" } },
    ...
  ]
}
```

Every record is self-describing: `op` names a draft operation, `args` lists all
of its inputs, and `expected` pins the resulting octets — so a reader can
reproduce it from the draft without consulting either implementation. Octet
strings are lowercase hex; a `null` value marks an absent input (e.g. no PSK).
Inputs are deterministic ramps `pat(tag, n)[i] = tag + i (mod 256)`, one `tag`
per role. Transcript checkpoints (`TH_*`) are supplied to `schedule` records as
opaque 64-octet inputs; the transcript hash itself is pinned by the
`transcript_hash` records (draft §2.1). A `schedule` record bundles a whole
§7.3 trace, so the record counts (31 / 28) expand to more individual pinned
secrets (158 expected fields across both files). One `schedule` record —
`schedule_suite_split` — deliberately sets `recorded_suite != selected_suite`
(both of the same profile) to pin the per-output suite routing of draft §4/§7.3:
early leaves bind the recorded suite, handshake/application leaves bind the
selected suite. That configuration is *not* a valid handshake (§4 requires them
equal for any selected PSK); it exists only so a recorded/selected mix-up is
caught, which the `recorded == selected` traces cannot detect.

Covered `op`s (deck, Appendix C): `transcript_hash`, `transcript_hash_after_hrr`,
`schedule`, `binder_verify_data`, `record_keys`, `finished_verify_data`,
`key_update`, `resumption_psk`, `exporter`, `ech_accept_confirmation`,
`hrr_ech_accept_confirmation`, `mac`, `psk_import`, `expand`. The FIPS-component
set (`fips.json`, Appendix D) uses parallel `fips_*` ops (`fips_transcript_hash`,
`fips_extract`, `fips_expand_label`, `fips_schedule`, `fips_finished_verify_data`,
`fips_record_keys`, `fips_key_update`, `fips_exporter`, `fips_resumption_psk`,
`fips_binder_verify_data`).

## Independent reproduction

`reproduce.py` is a second implementation, written from the draft text alone and
sharing no code with the Rust crate. It re-implements Keccak-p[1600, nr], the
sponge, the KMAC layout, the deck operations, the schedule, and every §5
derivation — plus the Appendix D FIPS-component schedule (KMAC256 Extract/Expand,
SP 800-108 counter mode) — then reproduces every `expected` field byte-for-byte
(all three files: 59 deck + 14 FIPS = 73 vectors). Its Keccak is first
self-validated against RFC 9861, FIPS 202 / `hashlib`, and the SP 800-185 KMAC256
Sample #4, and cross-checked against `pycryptodome`'s TurboSHAKE256 and KMAC256
when installed.

```sh
make reproduce            # or, from deck-schedule/: python3 vectors/reproduce.py -v
```

This is the main spec-level cross-check: the schedule wiring is confirmed by an
independent reimplementation over an independently-validated primitive, not just
by the crate's own determinism.
