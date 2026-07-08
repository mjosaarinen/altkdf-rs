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

## Outcome

**The draft is fully and faithfully implementable, and interoperates over a live
TLS 1.3 handshake.** Every normative component reproduced cleanly and nothing in
the specification required a workaround or a judgement call to make it work:

- The complete §7.3 schedule (both profiles), the §5.2 MAC, §2 framing, the §2.1
  transcript hash (including the HelloRetryRequest synthetic message), every §5
  derivation, the §10 external-PSK importer, and all **five** §6 cipher suites are
  implemented, validated in layers: the **primitives** are pinned to public KATs
  (RFC 9861 TurboSHAKE256, FIPS 202 SHAKE256, SP 800-185 KMAC256); the **schedule
  and every derivation** are emitted as 73 test vectors and reproduced
  byte-for-byte by a second implementation written from the draft text alone; and
  the **live rustls tests** validate stack agreement and on-the-wire behaviour.
- Two forked rustls endpoints complete a **live 1-RTT handshake over ML-KEM768 on
  each of the five suites** (`tests/loopback.rs`). On a deck suite (`0xFF01`),
  session resumption (`tests/resumption.rs`), a live `KeyUpdate` and exporter
  (`tls-demo/tests/demo.rs`), and an out-of-band **external-PSK (§10) handshake**
  (`tests/external_psk.rs`) also work end to end. Separately, a direct self-test
  cross-checks **every derived secret of a no-PSK schedule on `0xFF01`**
  byte-for-byte against the independent reference (`deck_schedule_matches_reference`).
- The informative Appendix D (FIPS-component) schedule is also implemented,
  vectored, and reproduced, purely for comparison.
- The design goal holds: because the draft changes *only* the key schedule (§1.2),
  the TLS integration was confined to a few small seams, and the ~3× permutation
  advantage over an HKDF-SHA3 schedule is confirmed by measurement (in fact larger
  — see finding 2).

Live coverage is 1-RTT: the handshake (all five suites), resumption,
KeyUpdate/exporter, and external PSK. **Two features are implemented/vectored but
not driven live**, both by design rather than any draft gap:

- **0-RTT early data (§11)** is *declined*, not exercised. The deck early-stage
  leaves (`c_e_traffic`, `e_exp_master`) are implemented and vectored in the
  reference crate, but the fork gates the live early-traffic path off: a deck
  client never offers early data and a deck server never accepts it, so a
  0-RTT-capable ticket simply resumes at 1-RTT (`tests/hardening.rs`). 0-RTT was
  deferred scope for the prototype.
- **ECH acceptance confirmation (§5.8)** *fails closed* — a limitation of the host
  stack, not the draft: rustls has no server-side ECH subsystem at all to verify a
  confirmation against. The deck ECH confirmation crypto is implemented and
  vectored; the fork returns a clean error rather than a fabricated result.

The findings below are therefore all editorial / accounting — a Table 4
invocation over-count, a conservative §A.1 permutation figure, one under-specified
informative appendix, and a labelling foot-gun worth a one-line caution. None
affects security or interoperability.

## What matched the draft exactly (positive confirmations)

- **TurboSHAKE256** (12-round Keccak-p[1600,12], domain `0x1F`) matches RFC 9861
  Appendix A.3 — empty input, multi-block `ptn(17^k)`, and the 10032-octet output.
- **SHAKE256** (24-round) matches FIPS 202 and Python `hashlib.shake_256`.
- **The MAC over the 24-round permutation is byte-for-byte NIST KMAC256**
  (SP 800-185 Sample #4), confirming the §5.2 layout and the `right_encode(8L)`
  length binding. `frame(x) = uint16(len)||x` framing is injective as §15.7.3
  claims.
- **HKDF-SHA3-256 baseline** for the representative handshake measures **exactly
  156 permutations / 39 invocations**, matching §A.1 and Table 4's RFC column.
- The whole §7.3 schedule and every §5 derivation reproduce byte-for-byte under a
  second, independent implementation written from the draft text alone.
- A **live 1-RTT handshake over ML-KEM768** completes on all five deck suites
  between two forked rustls endpoints; on a deck suite, session resumption and an
  out-of-band external-PSK (§10) handshake also complete end to end.


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
