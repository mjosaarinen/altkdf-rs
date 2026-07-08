# altkdf-rs — TLS 1.3 Deck Key Schedule prototype in Rust

A prototype of **`draft-sullivan-tls-xof-ciphers-00`**, "TLS 1.3 Cipher Suites
with Alternative Key-Schedule Profiles": TLS 1.3 cipher suites whose key schedule
is a **deck function over a single Keccak permutation** (TurboSHAKE256 or
SHAKE256) instead of HKDF-over-SHA-2. One permutation runs the whole schedule,
and a full handshake costs ~⅓ of the permutation calls of an HKDF-SHA3 schedule
(draft Appendix A; measured here at ~3.8× via `make bench`).

The draft is in [`doc/draft-sullivan-tls-xof-ciphers-00.txt`](doc/draft-sullivan-tls-xof-ciphers-00.txt).

## Layout

| path | what |
|---|---|
| `deck-schedule/` | core crate: Keccak-p permutation, sponge, deck ops, MAC, three-stage schedule, all §5 derivations, §10 PSK import, informative Appendix D FIPS schedule. `#![no_std]` + `alloc`, one dependency (`zeroize`); KAT-validated. |
| `rustls-integration/` | Stage 4: rustls fork wiring the deck schedule into a real TLS 1.3 stack |
| `tls-demo/` | Stage 5: client + server binaries; live handshake + keylog verification |
| `deck-schedule/vectors/` | primitive KATs + draft Appendix C schedule vectors packaged with the core crate |
| `PLAN.md` | **staged plan and progress tracker** |

## Quickstart

See [`PLAN.md`](PLAN.md) for the staged plan and exactly what's validated vs.
drafted, and [`FINDINGS.md`](FINDINGS.md) for consolidated notes to the draft
author (a Table 4 invocation over-count, a conservative §A.1 permutation figure,
and the under-specified Appendix D encoding).

```sh
cargo test        # all crates: deck-schedule, rustls-integration, tls-demo
make ci           # + fmt-check, clippy -D warnings, vector reproduction, benchmark
make bench        # just the Appendix A.1 permutation-count benchmark
```

Run the live demo (two terminals):

```sh
SSLKEYLOGFILE=/tmp/deck.keylog cargo run -p tls-demo --bin deck-server
SSLKEYLOGFILE=/tmp/deck.keylog cargo run -p tls-demo --bin deck-client
```

## Status

**All planned stages (0–5) are complete, plus the security/realism follow-ups
(6A resumption, 6B PSK import, 6C clean-failure, 6D zeroize), the Appendix A.1
benchmark, the informative Appendix D FIPS-component schedule, and a `no_std`
core crate. `make ci` and strict `cargo doc` are green.** What remains is
optional stretch (see the end of this list). Detail:

- **Core crate (`deck-schedule`) — Stages 0–3 done & validated.** Keccak-p
  permutation, sponge, framed deck ops, MAC, the three-stage schedule, and every
  §5 derivation. Primitives pinned to public KATs (RFC 9861 TurboSHAKE256,
  FIPS 202 SHAKE256, SP 800-185 KMAC256, incl. multi-block); the full schedule +
  derivations (plus the Appendix D FIPS-component schedule) are emitted as vectors
  (`deck-schedule/vectors/*.json`, 73 records) and reproduced byte-for-byte by an
  independent Python implementation (`deck-schedule/vectors/reproduce.py`). The
  crate is `#![no_std]`.
- **Stage 4 (rustls integration) — done.** Vendored rustls 0.23.41 fork
  (aws-lc-rs backend, for pure ML-KEM key exchange); the deck `TranscriptHash` as
  a `crypto::hash::Hash` provider; the TLS 1.3 `KeySchedule` rewritten onto the
  deck for 1-RTT (0-RTT / ECH unsupported), cross-checked against the reference
  for every derived secret. The five cipher suites `0xFF01..=0xFF05` are
  registered and the deck `CryptoProvider` + TLS 1.3 configs assembled. **Two
  forked endpoints complete a live 1-RTT handshake over ML-KEM768 and exchange
  application data** on every deck suite (`rustls-integration/tests/loopback.rs`).
- **Stage 5 (demo + wire verification) — done.** `deck-server` / `deck-client`
  binaries complete a real-socket TLS 1.3 handshake on a deck suite (`0xFF01` over
  ML-KEM768), with ALPN and `SSLKEYLOGFILE` (NSS key-log for Wireshark). The
  `tls-demo` integration test exercises a live `KeyUpdate` (§5.4) and
  `export_keying_material` (§5.6) and cross-checks that both peers logged
  identical 64-octet deck secrets (`tls-demo/tests/demo.rs`).
- **Stage 6A (PSK binder + resumption) — done.** The deck PSK binder (§5.5) is
  implemented (its MAC binds the `"res binder"`/`"ext binder"` label, *not*
  `"finished"` — pinned by a regression test); a full handshake issues a ticket
  and a second **resumes** on a deck suite (`tests/resumption.rs`). The
  `deck_server_config`/`deck_client_config` helpers now default to **1-RTT
  resumption on, 0-RTT off**. 0-RTT stays deferred (the server skips the early
  secret for deck suites).
- **Stage 6B (external PSK importer, §10) — done, including a live handshake.**
  `ImportedIdentityV2` serialization + `import()` in `deck-schedule` bind the
  external PSK per target cipher suite into an `ipsk` (§5.9) that feeds the
  `"ext binder"` path (§5.5); the Appendix C `psk_import` vectors carry a real
  `ImportedIdentityV2` and are independently reproduced. rustls 0.23.41 had no
  external-PSK configuration surface, so the fork gained one (`DeckExternalPsk`,
  `ClientConfig.deck_external_psk` / `ServerConfig.deck_external_psks`, an external
  offer path + server-side identity match + external-binder verify). **Two forked
  peers now complete a 1-RTT handshake authenticated by an out-of-band external
  PSK on a deck suite — no server Certificate** (`tests/external_psk.rs`), and a
  wrong-`epsk` variant is rejected at the binder. External PSK + (EC)DHE is
  structurally a 1-RTT resumption, so it reuses the resumption machinery,
  differing only in the PSK source and the binder label (now parametrized).
- **Stage 6C (panic → clean failure) — done.** No peer- or config-reachable deck
  path panics: 0-RTT is declined at negotiation (a deck client offered an
  early-data ticket resumes at 1-RTT), and the ECH acceptance confirmation (§5.8)
  returns a clean `Error` instead of the old fail-closed panic
  (`tests/hardening.rs`). Remaining fork panics are `unreachable!` internal
  invariants.
- **Stage 6D (zeroize hardening, §15.7.2.2) — done.** Live secret state zeroizes
  on drop: the sponge state and deck accumulators (the draft's explicit call-out),
  every squeezed secret (returned as `Secret = Zeroizing<Vec<u8>>`), and the fork's
  `DeckState` stage secrets + record-key scratch. Wire values stay plain bytes. One
  new dependency (`zeroize`).
- **Invocation-count benchmark (Appendix A.1) — done.**
  `deck-schedule/examples/invocations.rs` (`make bench`, in `make ci`) instruments
  Keccak-f[1600] and measures one full representative handshake: **HKDF-SHA3-256 =
  156 permutations / 39 invocations (matches the draft exactly)**; the deck
  (stateful) = 41 / 28, a **3.80×** permutation win. (It measures 28 deck
  invocations — the §7.3 schedule has two ratchets — vs Table 4's 29, a minor
  draft over-count.)
- **Appendix D (informative FIPS-component schedule) — done.** RFC 8446 §7.1 with
  KMAC256 as the PRF throughout (Extract from SP 800-56C, Expand = SP 800-108
  counter mode), TranscriptHash = SHAKE256(·, 64), in `deck-schedule/src/fips.rs`.
  Emitted as `deck-schedule/vectors/fips.json` (14 records) and independently
  reproduced. The benchmark gained a FIPS-component row — **117 perms / 39 invocations**, same
  invocation count as HKDF-SHA3-256, still ~2.85× the deck.
- **`no_std` — done.** The core crate is `#![no_std]` + `alloc` and builds for
  bare-metal `thumbv7em-none-eabi` (`make no-std`, in `make ci`).
- **Stage 6 (stretch) — remaining:** live ECH (§5.8) only. Live ECH is
  **blocked** — rustls has no server-side ECH subsystem to verify a deck
  acceptance confirmation against — so it stays fail-closed by design. (The live
  external-PSK wire handshake is done; see Stage 6B above.) Note 0-RTT early data
  (§11) is likewise not driven live — declined at negotiation, resumes at 1-RTT —
  a deliberate non-goal, not a stretch item (Stage 6C).


## Design in one paragraph

`cipher suite = AEAD + ScheduleProfile`. The profile is selected by the
negotiated cipher-suite code point alone — no new extension, no wire/state-machine
change (draft §1.2) — so the rustls integration is confined to the key-schedule
module. The schedule is expressed with five deck operations
(`Init/Absorb/Fork/Squeeze/Ratchet`, draft §7.1) over one sponge; both profiles
share the code and differ only in permutation round count (12 vs 24). Every
derivation is length-framed and binds `profile_id` + the governing cipher suite,
giving byte-exact, testable outputs (draft §7.1.2, §15.7.3).

> Placeholder code points `0xFF01..=0xFF05` are used until IANA assignment
> (draft §14 OPEN ISSUE).
