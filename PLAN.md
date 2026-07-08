# Prototype Plan — TLS 1.3 Deck Key Schedule

A working prototype of `draft-sullivan-tls-xof-ciphers-00`: the deck key
schedule as a standalone, KAT-validated Rust crate, integrated into
[rustls](https://github.com/rustls/rustls) and demonstrated over a live client ↔
server handshake.

**Guiding fact:** the draft changes *only* the key schedule — no wire format, no
state machine (§1.2). So the TLS integration is a surgical diff, and the
interesting cryptography lives in one near-dependency-free crate (only `zeroize`)
that we can validate against public KATs before any TLS stack is involved.

## Current state

All planned stages are complete and validated: the core crate (Stages 0–3), the
rustls integration (Stage 4), the live demo + wire verification (Stage 5), and the
security/realism follow-ups — PSK binder + session resumption (6A), external PSK
import (6B), panic → clean failure (6C), `zeroize` hardening (6D) — plus the
Appendix A.1 permutation-count benchmark, the **informative Appendix D
FIPS-component schedule**, and a **`no_std`** core crate. `make ci` is green (fmt,
clippy `-D warnings`, all tests, the independent 73-vector reproduction, the
benchmark's assertions, and a bare-metal `no_std` build); strict
`cargo doc -D warnings` is clean.

**Open (optional stretch):** live ECH (§5.8) only. Live ECH is **blocked**:
rustls has no server-side ECH subsystem at all (no HPKE opener, no outer/inner
ClientHello decryption, no path to write the acceptance confirmation into
`ServerHello.random`), so it stays fail-closed by design — the deck
ECH-confirmation crypto exists (`derive::ech_accept_confirmation`) but has no live
server to verify against. (Separately, **0-RTT early data (§11) is not driven
live either** — it is declined at negotiation and resumes at 1-RTT, a deliberate
non-goal for this prototype, not a stretch item; see Stage 6C.) The **live external-PSK wire handshake (§10) is now
done** (see Stage 6B): two forked peers complete a 1-RTT handshake authenticated
by an out-of-band external PSK on a deck suite.

**Note for the draft author:** the benchmark independently measures **28** deck
key-schedule invocations for the representative handshake — the §7.3 schedule has
two ratchets (`early_secret`, `main_secret`) — whereas Table 4 totals **29**
(its deck column lists three "Ratchet" rows). So Table 4 *appears to overcount by
one deck invocation*, and the deck is marginally cheaper than the draft states.

## Status legend

- `[x]` done & validated
- `[~]` code drafted, not yet validated (compiles/passes structural tests, but
  no authoritative KAT/interop check yet)
- `[ ]` not started

## Architecture

```
deck-schedule/        core crate — permutation, sponge, deck ops, MAC, schedule, derivations,
                      §10 PSK import (one dep: `zeroize`; validated against public KATs + vectors)
        │
        ▼
rustls-integration/   Stage 4 — rustls fork: custom hash + suites + rewritten KeySchedule
        │
        ▼
tls-demo/             Stage 5 — client + server binaries; live handshake, keylog verification
```

Draft section ↔ module map lives in `deck-schedule/src/lib.rs`.

---

## Stage 0 — Repo & workspace scaffolding

- [x] Cargo workspace (`Cargo.toml`) with `deck-schedule` member
- [x] `deck-schedule` crate skeleton, module-per-draft-section layout
- [x] Directory stubs + READMEs for `rustls-integration/`, `tls-demo/`, `deck-schedule/vectors/`
- [x] `PLAN.md` (this file), top-level `README.md`, `.gitignore`
- [x] `cargo test` green (all tests pass, no ignored stubs)

**Done when:** `cargo test` builds and passes; every part of the tree exists. ✅

---

## Stage 1 — Primitives (permutation + sponge)

Draft §8.1, §9.1. Files: `src/keccak.rs`, `src/sponge.rs`.

- [x] `keccak_p(state, rounds)` for `rounds ∈ {12, 24}` (last-`nr` round constants)
- [x] Sponge: rate 136, capacity 512, domain byte, clone-before-squeeze, pad10*1
- [x] `absorb`-after-`squeeze` rejected (`assert!`, release-enforced, draft §7.1.1)
- [x] **SHAKE256("") KAT** → validates 24-round path + sponge (`sponge::tests`)
- [x] **TurboSHAKE256("") KAT** (RFC 9861 App. A.3) → validates the 12-round path
      (`sponge::tests::turboshake256_empty_kat`)
- [x] Multi-block + long-output KATs (> 136 octets, 10032-octet squeeze) for both
      round counts: TurboSHAKE256 `ptn(17^2)`/`ptn(17^3)` and the 10032-octet
      output from RFC 9861 App. A.3; SHAKE256 counterparts cross-checked against
      an independent Keccak (Python `hashlib`). Exercises the absorb loop across
      the rate boundary and the squeeze loop across output blocks
      (`sponge::tests::{turboshake256_multiblock_kat,turboshake256_long_output_kat,
      shake256_multiblock_kat,shake256_long_output_kat}`)
- [ ] (optional) constant-time review / `zeroize` on drop for the sponge state

**Done when:** both permutation round counts are pinned to published KATs.

---

## Stage 2 — Deck core (framing, deck ops, transcript, MAC)

Draft §2, §5.1, §5.2, §7.1. Files: `src/frame.rs`, `src/deck.rs`,
`src/transcript.rs`, `src/mac.rs`, `src/profile.rs`.

- [x] `frame`, `uint16`, `left/right_encode`, `encode_string`, `bytepad` + encoder KATs
- [x] `Init / Absorb / Fork / Squeeze / Ratchet` with rules enforced by the type
      (squeeze/ratchet consume `self`; fork clones)
- [x] `DF(S, L)` per profile (domain `0x1F`); `TranscriptHash` (`"tls13 hash"` prefix)
- [x] `MAC` byte layout (domain `0x04`, `right_encode(8L)` length binding)
- [x] **KMAC256 KAT** (SP 800-185 Sample #4) → the 24-round `MAC` is byte-for-byte
      KMAC256 (`mac::tests::kmac256_sample4`); encoders cross-checked vs the PDF's
      `Encoded K` / `Right_encoded L` / `Encoded N` intermediates
- [x] Injective-framing tests (draft §15.7.3): distinct paths ⇒ distinct `seq(S)`;
      absent vs empty input distinguished; `"tls13 hash"` (0x74…) vs keyed-prefix
      (0x00 0x17) byte-level separation; ratchet labels reserved
      (`deck::tests`, `transcript::tests`)
- [x] `TranscriptHash` HelloRetryRequest synthetic-message construction (draft §2.1,
      RFC 8446 §4.4.1): `hrr_message_hash` / `transcript_hash_after_hrr`
      (`transcript::tests`, vector `th_after_hrr`)

**Done when:** `MAC` matches KMAC256 on the SHAKE profile and the framing
injectivity invariants are covered by tests. ✅

---

## Stage 3 — Full schedule + derivations + self-generated vectors

Draft §4, §5, §7.3. Files: `src/schedule.rs`, `src/derive.rs`, `src/suites.rs`.

- [x] Three-stage schedule `E/H/T` with two ratchets (`src/schedule.rs`)
- [x] No-PSK path `Absorb(E,"psk","")`; PSK-only omits `"dh"` (draft §7.3.1)
- [x] Leaf derivations: `expand`, `record_keys` (one call + split), `key_update`,
      `finished`/`binder`, `exporter`, `resumption_psk`, `ech`*, `psk_import`
      (all emitted as vectors and reproduced independently)
- [x] Five cipher suites + Nk/Nn + placeholder code points (`src/suites.rs`)
- [x] Edge-case guards tested: non-empty `Psk` type (empty ≠ no-PSK), empty-context
      omission in `expand`, PSK-import input checks (review findings #1/#2/#5)
- [x] Per-output recorded-vs-selected suite binding threaded through the schedule
      (early leaves ← recorded, handshake/app ← selected; draft §4, §7.3) and
      pinned by vectors. NB: the PSK-compatibility and 0-RTT suite-equality
      *enforcement checks* are negotiation policy, deferred to Stage 4 where PSK
      selection lives.
- [x] Multi-component (hybrid) (EC)DHE ordering test (draft §7.3):
      `schedule::tests::hybrid_dh_component_order_is_bound` + vector
      `schedule_full_hybrid`
- [x] **Generate** the Appendix C vector sets under `0xFF01..=0xFF05`
      (`src/vectors.rs`, `examples/gen_vectors.rs` → `deck-schedule/vectors/*.json`, 31 + 28
      records / 154 expected fields; includes `schedule_suite_split`, an
      artificial recorded≠selected trace that pins the per-output suite routing
      of §4/§7.3); loaded and pinned current by `deck-schedule/tests/vectors.rs`
- [x] **Independent reproduction**: `deck-schedule/vectors/reproduce.py`, a second
      implementation written from the draft alone with its own Keccak (validated
      against RFC 9861 / FIPS 202 / SP 800-185 KATs and cross-checked vs
      `pycryptodome` + `hashlib` when installed), reproduces all 59 deck (Appendix
      C) vectors — 73 with the informative Appendix D set — byte-for-byte and runs
      a negative control proving the checker is
      non-vacuous (draft Appendix C). Wired into `make ci` via `make reproduce`.

**Done when:** a full handshake trace (§7.3) plus every §5 derivation is emitted
as vectors and reproduced independently. ✅

---

## Stage 4 — rustls integration

See `rustls-integration/README.md`.

- [x] Bring rustls in: vendored fork of **rustls 0.23.41** under
      `rustls-integration/rustls/` (plain source, own `[workspace]`), pulled in
      via `[patch.crates-io]`; **aws-lc-rs** backend (switched from ring to get
      post-quantum key exchange — pure ML-KEM `MLKEM768` and, later, hybrids;
      ring has no ML-KEM). Builds here with cc + cmake, no nasm. Workspace builds
      and `make ci` green with the `rustls-integration` crate added (M1).
- [x] `TranscriptHash` as a `crypto::hash::Hash` provider (64-octet, `fork`/clone):
      `rustls-integration/src/hash.rs` (`DeckHash`, one per profile), tested
      against the reference `transcript_hash`, the incremental/fork paths, and a
      committed vector (M2). Reports `HashAlgorithm::SHA512` (no SHAKE code point
      exists; unused by real suites so it never aliases one).
- [x] Register `0xFF01..=0xFF05` as `Tls13CipherSuite`s; reuse provider AEADs
      (`rustls-integration/src/suites.rs`). Each deck suite is `CipherSuite::Unknown(0xFF0x)`
      + the deck `DeckHash` provider + a reused aws-lc-rs AEAD (AES-128/256-GCM,
      ChaCha20-Poly1305, draft §6) + reused `hkdf_provider` (inert on the deck
      path) + `quic: None` (§13.1). Tests pin code points / order / Nk / SHA512
      tag against `deck_schedule::suites::ALL`.
- [x] Exact-suite PSK/resumption compatibility for deck suites (draft §4, §15.2):
      `DECK-FORK` patch to `rustls/src/tls13/mod.rs` `can_resume_from` — without
      it, the same-`HashAlgorithm` tag would alias the three same-profile suites,
      and both profiles, as mutually resumable. Regression test
      `deck_resumption_requires_exact_suite` (`src/lib.rs`). Server-side already
      checks exact suite (incl. 0-RTT); this closes the client seam.
- [x] Rewrite `tls13/key_schedule.rs` stage transitions to call `deck-schedule`;
      feed `TH_SH`/`TH_SF` into the ratchets (M3). Inner `KeySchedule` replaced by
      a deck state machine (`Early→Handshake→Master→Application`); `main_secret`
      ratcheted in `into_handshake` once `TH_SH` is bound, `enter_application`
      retains `TH_SF`. Two `DECK-FORK` touchpoints only. PSK binders, 0-RTT early
      secrets, and both ECH confirmations fail closed (`deck_unsupported`) —
      no-PSK/no-ECH/no-hybrid by construction. **Validated:**
      `deck_schedule_matches_reference` cross-checks every derived secret
      (handshake/application/exporter/resumption traffic secrets + Finished MAC +
      record key/iv) byte-for-byte against `deck_schedule::schedule::run`, so the
      stage-ordering is proven against the independent reference (not only M4
      agreement). Deferred: `zeroize` of stage secrets/trunks (§15.7.2.2 → Stage 6).
- [x] Finished MAC via deck `MAC`; record key = one deck expansion split key‖iv
      (`KeyScheduleSuite::{sign_verify_data, set_encrypter/decrypter}` → deck
      `finished_verify_data` / `record_keys`; key update / exporter / resumption
      PSK likewise routed to their deck derivations)
- [x] Assemble a `CryptoProvider` (`deck_provider()`, `src/lib.rs`): the five deck
      suites over `deck_kx_groups()` (pure ML-KEM `MLKEM768` + `X25519` +
      `secp256r1`; hybrids excluded), reusing aws-lc-rs's sig-verify / RNG / key
      provider via `..default_provider()`. Config helpers `deck_server_config` /
      `deck_client_config` build TLS 1.3-only configs with **tickets and client
      resumption disabled** (`send_tls13_tickets = 0`, `Resumption::disabled()`),
      closing the M4 known gap — a deck resumption PSK would hit the fail-closed
      binder guard (draft §5.5).
- [x] **Loopback interop** (`rustls-integration/tests/loopback.rs`): two forked
      endpoints complete a no-PSK 1-RTT TLS 1.3 handshake over an in-memory
      transport and exchange app data **both directions**, for each of the five
      deck suites (both profiles, all three AEADs) — the Finished exchange + AEAD
      round-trip proves identical secrets. Default handshake runs over pure
      **ML-KEM768** (asserted). NB: this proves *agreement*, not spec-correctness
      — spec validation is Stage 3's independent vector reproduction.
- [x] Audit for `hash_len`-sized buffers assuming ≤ 48 octets (we use 64): the
      fork's value types `OkmBlock` / `hash::Output` / `hmac::Tag` are all
      `MAX_LEN = 64` (exact fit for SecretLen / TranscriptHash / FLen), and
      `AeadKey::MAX_LEN = 32 ≥ Nk`. The live handshake with 64-octet secrets
      confirms it at runtime.
- [x] Confirm `CipherSuite::Unknown(u16)` survives negotiation/selection: the
      loopback negotiates `Unknown(0xFF0x)` on both peers (asserted per suite).

**Done when:** two forked rustls endpoints complete a handshake on a deck suite
and pass data. ✅ **Met** — see `tests/loopback.rs`. Remaining for Stage 6:
`zeroize` of stage secrets / cloned trunks (draft §15.7.2.2).

---

## Stage 5 — Demo + wire verification

See `tls-demo/README.md`.

- [x] Client + server binaries: `tls-demo/src/bin/{server,client}.rs`
      (`deck-server` / `deck-client`), a real TCP echo over `rustls::Stream`.
      Verified live: `deck-client` ↔ `deck-server` complete a handshake on
      `0xFF01` over ML-KEM768 and echo data.
- [x] ECDSA-P256 certs (rcgen default); ALPN (`deck-demo`, asserted on both
      peers); normal TLS features working (accept-any verifier keeps the real
      CertificateVerify signature check — auth is out of scope, draft §15.5).
- [x] `SSLKEYLOGFILE` export (`rustls::KeyLogFile`): a live run emits a standard
      NSS key-log (5 labels × 64-octet secrets) ready for Wireshark. (The
      Wireshark decrypt itself is the one manual step.)
- [x] Cross-check logged traffic secrets: the `tls-demo` integration test
      (`tests/demo.rs`) captures each peer's key log via `CapturingKeyLog` and
      asserts client and server logged **identical** 64-octet deck secrets for
      all five labels + matching `client_random`. Two separately-run binaries
      also produce byte-identical key logs.
- [x] Exercise `KeyUpdate` (§5.4) and `export_keying_material` (§5.6) live:
      `tests/demo.rs` triggers `refresh_traffic_keys()` then sends a 20 KB
      round-2 payload (crossing a record boundary) that still round-trips, and
      asserts both peers' exporter outputs agree.
- [ ] Session resumption ticket → `res_master` → `resumption_psk` (§5.7) and
      resumption binders (§5.5). **Deferred:** PSK binders are unimplemented and
      fail closed (Stage 4); the deck configs disable tickets/resumption. Belongs
      with the Stage 6 PSK work.

**Done when:** a live handshake on a deck suite is captured and decrypted, and
the derived secrets match the crate. ✅ **Met** (modulo the manual Wireshark
decrypt): live `deck-client`↔`deck-server` handshake, an NSS key log, and a
socket integration test proving both peers derive identical deck secrets
(`tests/demo.rs`). Resumption was deferred to Stage 6 here (needs binders) and is
now **done in Stage 6A** (`tests/resumption.rs`).

---

## Stage 6A — PSK binder + session resumption ✅

- [x] Deck PSK binder derivation (draft §5.5) wired into the fork: the reference
      `deck_schedule::derive::binder_verify_data` (`binder_key` → `finished_key` →
      `MAC` over `TH_CH0`) replaces the RFC-8446-shaped `derive_for_empty_hash` +
      Finished path. New `KeySchedule::resumption_binder_verify_data`; the
      `deck_unsupported` binder panic is gone. **Subtlety pinned:** the `MAC` is
      taken under the *binder* label (`"res binder"`/`"ext binder"`), NOT
      `"finished"` — flattening it onto the Finished path would silently change the
      value (regression test `binder_mac_label_is_binder_not_finished`).
- [x] 0-RTT stays deferred: a `DECK-FORK` gate (`is_deck_suite`) skips the
      server's speculative client early-traffic-secret derivation on resumption
      (draft §11) — deck resumption is 1-RTT PSK + (EC)DHE, early data never
      accepted (rejected via trial decryption, which does not use that secret).
- [x] Live resumption test (`rustls-integration/tests/resumption.rs`): a full
      handshake issues a NewSessionTicket (`resumption_psk`, §5.7), and a second
      handshake with the same client config **resumes** — client computes and
      server verifies the deck binder, both report `HandshakeKind::Resumed`, the
      resumed suite equals the ticket's recorded suite (exact-suite rule, §4/§15.2),
      and application data flows.
- [x] Deployment helpers now default to **1-RTT resumption on, 0-RTT off**:
      `deck_server_config` leaves tickets enabled + sets `max_early_data_size = 0`;
      `deck_client_config` leaves the client session store enabled + sets
      `enable_early_data = false`. The advertised defaults match the implemented
      capability. `tests/resumption.rs::resumption_via_public_helpers` resumes
      through the public helpers unmodified; the local loopback test helpers keep a
      deterministic no-ticket variant. (This retires the Stage-4 raw-provider
      "panic on misuse" footgun — resumption is now ordinary behaviour.)
- [x] External PSK **import** (§10) + `"ext binder"` — delivered as **Stage 6B**.

---

## Stage 6B — External PSK importer (§10) ✅

Derivation, encoding, **and now a live wire handshake** (see the last item).

- [x] `ImportedIdentityV2` (draft §10) in `deck-schedule/src/import.rs`:
      TLS presentation-language serialization
      (`opaque external_identity<1..2^16-1>; opaque context<0..2^16-1>; uint16
      target_protocol; uint16 target_ciphersuite`) plus `import(epsk)`, which binds
      the *serialized* identity as the derivation context (draft §5.9) so the wire
      `PskIdentity.identity` and the bound context are the same bytes. Enforces the
      §10 field bounds and `target_protocol` / `target_ciphersuite`.
- [x] The imported `ipsk` feeds the external-binder path (`"ext binder"`,
      `BinderKind::External`, §5.5), keyed by `schedule::early_secret(ipsk)` — a
      unit test pins the full offer (import → ipsk → early secret → ext binder).
- [x] Per-suite diversification, identity/context binding, and §10 input-rule
      rejections unit-tested. The Appendix C `psk_import` vectors now carry a **real
      `ImportedIdentityV2`**: `imported_identity_v2` is an expected output, so
      `deck-schedule/vectors/reproduce.py` independently reproduces the §10 encoding *and* the
      derivation (59 deck vectors / 158 fields; 73 / 193 with the Appendix D set).
- [x] **Live wire handshake — done.** rustls 0.23.41 had no external-PSK
      configuration surface (its `PresharedKey` path is resumption-only), so the
      fork gained one: a `DeckExternalPsk` type, `ClientConfig.deck_external_psk` /
      `ServerConfig.deck_external_psks`, an external-PSK offer path in the
      ClientHello, and server-side identity matching + external-binder verification.
      External PSK + (EC)DHE is structurally a 1-RTT resumption (no server
      Certificate), so it reuses the resumption offer/accept machinery, differing
      only in the PSK source (`import` vs `resumption_psk`) and the binder label
      (`BinderKind::External` vs `Resumption`, now a parameter throughout
      `key_schedule.rs`). Two forked peers complete the handshake and exchange data
      (`rustls-integration/tests/external_psk.rs`); a wrong-`epsk` variant is
      rejected at the binder.

---

## Stage 6C — Panic → clean failure ✅

The deck fork no longer panics on any peer- or config-reachable unsupported deck
feature: `grep -rn "deck_unsupported\|panic!" rustls/src/tls13` is empty.

- [x] **0-RTT (draft §11) — clean rejection.** A `DECK-FORK` gate (`is_deck_suite`)
      stops a deck **client** from offering early data (`client/tls13.rs`) and a
      deck **server** from accepting it (`decide_if_early_data_allowed`,
      `server/tls13.rs`), so the unimplemented deck early-traffic secret is never
      reached. Resumption is 1-RTT.
- [x] **ECH acceptance confirmation (draft §5.8) — clean error.** Both
      `server_ech_confirmation_secret` (typestate method) and
      `server_ech_hrr_confirmation_secret` (free fn) now return
      `Result<[u8; 8], Error>` and yield a clean `Error` for deck suites; the ECH
      callers in `client/ech.rs` propagate it with `?`. The `deck_unsupported(...) -> !`
      helper is deleted.
- [x] The remaining fail-closed markers are `unreachable!` **internal invariants**
      (typestate ordering, provider offers only deck suites, gated-off features),
      not reachable feature panics.
- [x] Regression tests (`rustls-integration/tests/hardening.rs`): a deck client
      offered an early-data-capable ticket resumes at 1-RTT with 0-RTT declined and
      no unwind; both ECH confirmation paths return an error (via a `#[doc(hidden)]`
      hook), no unwind.

**Post-review fix (6B):** `ImportedIdentityV2::serialize` is now fallible and
`import` rejects a serialization that would exceed `PskIdentity.identity<1..2^16-1>`
(`external_identity + context + 8 > 0xFFFF`) — the whole blob is offered as that
identity, so the sum, not just each field, is bounded. Boundary-tested.

---

## Stage 6D — Zeroize hardening (draft §15.7.2.2) ✅

Live secret state is no longer plain byte values relying on drop-by-convention.
One new dependency: `zeroize` (itself dependency-free, no_std).

- [x] **Accumulators (the draft's explicit call-out).** `sponge::Sponge` (the
      200-octet state = withheld capacity) and `deck::Deck` (the framed sequence,
      which holds absorbed secrets and is cloned by `Fork`) zeroize on drop;
      `Deck`'s permute scratch is erased too.
- [x] **Squeezed secrets.** A `Secret = Zeroizing<Vec<u8>>` alias; every squeezed
      key-schedule secret is returned as `Secret` — `expand` (hence `finished_key`
      / `binder_key`), `record_keys`, `key_update`, `resumption_psk`, `exporter`,
      `psk_import`/`ipsk`, `schedule::early_secret`. Wire values (`verify_data`,
      ECH confirmations, the serialized identity) stay `Vec<u8>`.
- [x] **Fork stage state.** The `DeckState` secrets (`early_secret`, `main_secret`,
      the (EC)DHE components) are `Secret`, so they and their stage-transition
      clones zeroize; the record-key scratch buffers and the squeezed leaf feeding
      `OkmBlock` are erased. (`OkmBlock`/`AeadKey`/`Iv` already zeroize in rustls.)
- [x] A compile-time test asserts `Sponge` / `Deck` / `Secret` carry the
      `ZeroizeOnDrop` marker (memory erasure isn't testable by reading freed
      storage); reference/vector structs stay plain bytes by design.

**Post-review fixes (6D):**
- **`Deck` reallocation leak (was: only the final allocation wiped).** `Deck`
  now appends through a secure `push_bytes` that, on growth, zeroizes the old
  secret-bearing buffer before it frees — a plain `Vec` reallocation (e.g. a
  `Fork` cloning then appending) would otherwise leave PSK/DHE/stage-secret
  material in freed heap. Tested via `secure_growth_preserves_framed_sequence`.
- **Same class in the MAC.** `encode_string`/`bytepad` reserve exact capacity and
  the key-bearing blocks + `mac_input` are `Zeroizing` with reserved capacity, so
  the MAC key (`finished_key`/`binder_key`) is never left in a reallocated or
  freed buffer.
- **`Sponge::permute` scratch.** The 8-octet lane buffer is now wiped too (not
  just the lane array).
- **Docs.** `schedule::run` / `ScheduleOutputs` are documented as the
  reference/vector-only path whose plain `Vec<u8>` fields are intentional (not
  live secret state).

---

## Stage 6 — Stretch

- [x] External PSK **import** (§10) + `"ext binder"` — done at the derivation/
      encoding level in Stage 6B (vector-validated). The live wire handshake is
      now being wired into the fork (see the in-progress item below).
- [x] Convert the remaining fail-closed `deck_unsupported!` panics (0-RTT, ECH)
      into clean failures — done in Stage 6C.
- [x] `zeroize` hardening pass — done in Stage 6D.
- [x] **Benchmark: permutation-call count vs HKDF-SHA3-256 (Appendix A.1).**
      `deck-schedule/examples/invocations.rs` (feature `bench`, `make bench`, in
      `make ci`) instruments Keccak-f[1600] and measures one full representative
      handshake over the shared 24-round permutation. Results:
      **HKDF-SHA3-256 = 156 permutations / 39 invocations, matching the draft
      exactly**; the deck (stateful, clone-per-fork) = **41 permutations / 28
      invocations**, a **3.80×** permutation advantage (draft claims 3.0×). It
      also reports the recompute-from-path realization the crate uses (46
      permutations; Appendix B).
      **Finding for the draft:** §7.3 defines **two** ratchets (`early_secret`,
      `main_secret`), so the measured deck invocation count is **28**, whereas
      Table 4 totals 29 (its deck column lists three "Ratchet" rows) — Table 4
      *appears to overcount by one deck invocation*, so the deck is marginally
      cheaper than the draft states.
- [x] **Appendix D: the FIPS-component (KMAC256 + SP 800-56C/108) schedule**, as
      an informative alternative for comparison (`deck-schedule/src/fips.rs`):
      RFC 8446 §7.1 with KMAC256 as the PRF throughout, Extract from SP 800-56C,
      TranscriptHash = SHAKE256(·, 64). Emitted as `deck-schedule/vectors/fips.json`
      (14 records) and independently reproduced by `reproduce.py`. The Appendix A.1 benchmark
      gained a FIPS-component row: **117 permutations / 39 invocations** — same
      invocation count as HKDF-SHA3-256 (it *is* the RFC 8446 schedule), cheaper
      than HMAC-based HKDF, but still ~2.85× the deck, isolating the deck's win as
      its stateful structure rather than its use of Keccak.
- [x] **`no_std` pass on `deck-schedule`.** The core crate is `#![no_std]` +
      `alloc`; it builds for the bare-metal `thumbv7em-none-eabi` target, guarded
      by `make no-std` (wired into `make ci`). The bench counter moved from
      `thread_local!` to a global `AtomicU64`.
- [ ] ECH acceptance confirmation live (§5.8) — **blocked**: rustls has no
      server-side ECH subsystem (no HPKE opener / outer-hello decryption / config
      / confirmation into `ServerHello.random`), so a live two-peer demo would
      mean building that subsystem from scratch. The deck confirmation crypto
      exists (`derive::ech_accept_confirmation`); it stays fail-closed by design.
- [x] **Live external-PSK wire handshake (§10) — done.** Two forked peers complete
      a 1-RTT handshake authenticated by an out-of-band external PSK on a deck
      suite. Fork seams: a `DeckExternalPsk` type + `ClientConfig.deck_external_psk`
      / `ServerConfig.deck_external_psks`; the client imports the PSK for its target
      deck suite (`ImportedIdentityV2`, draft §5.9), offers the serialized identity,
      and signs the `"ext binder"` (§5.5); the server re-imports for its selected
      suite, matches the identity, and verifies the external binder. The PSK binder
      path (`key_schedule.rs`) is now parametrized by binder label
      (`BinderKind::Resumption`/`External`). External PSK + (EC)DHE is structurally a
      1-RTT resumption (no server Certificate), so it reuses the resumption
      offer/accept machinery, differing only in the PSK source and binder label.
      Test: `rustls-integration/tests/external_psk.rs` (a happy path that resumes
      with no server cert, plus a wrong-`epsk` binder-rejection).

---

## How we track progress

Edit the checkboxes above as work lands; keep the status legend honest (`[~]`
means "written but not authoritatively validated"). Each stage names its
**Done when** gate — don't tick the stage header until that gate is met.

## Quick start

```sh
cargo test                                          # all pass, no ignored stubs
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
make vectors                                        # regenerate deck-schedule/vectors/*.json (App. C + D)
make reproduce                                      # independent cross-impl check (73 vectors)
make bench                                          # Appendix A.1 permutation-count benchmark
make no-std                                          # bare-metal no_std build of deck-schedule
make ci                                             # fmt-check + lint + test + reproduce + bench + no-std
```
