# rustls-integration (Stage 4)

Surgical integration of the deck schedule into [rustls](https://github.com/rustls/rustls).
The draft changes **only** the key schedule — no wire format, no state machine
(draft §1.2) — so the diff is confined to a few seams. The draft author reports
the port to one stack was "code motion within existing functions, with no change
to message flow" (draft Appendix B, line 2397).

## Layout

- `rustls/` — vendored fork of **rustls 0.23.41** (the published crate source,
  plus an empty `[workspace]` so it stays its own workspace root). The
  key-schedule seams are edited in place under `rustls/src/tls13/` and
  `rustls/src/crypto/`.
- `src/` — the `rustls-integration` glue crate. Done: the deck `Hash` provider
  (`hash.rs`), the five deck cipher suites (`suites.rs`), the deck
  `CryptoProvider` + TLS 1.3 config helpers (`deck_provider` / `deck_server_config`
  / `deck_client_config` in `lib.rs`), the single-component `deck_kx_groups()`
  list, the fork's schedule cross-check (`deck_schedule_matches_reference`), and
  the accept-any loopback verifier (`danger`).

Although titled "Stage 4", this crate carries all the later fork work too: the
deck PSK binder + session resumption (6A), the external-PSK (§10) importer with a
**live external-PSK handshake** (6B), the panic → clean-failure hardening (6C),
and the `DeckState` zeroize pass (6D). Tests: `tests/loopback.rs` (live 1-RTT
interop, every suite), `tests/resumption.rs` (full → resumed), `tests/external_psk.rs`
(out-of-band external-PSK handshake + wrong-secret rejection), and
`tests/hardening.rs` (0-RTT declined, ECH fails cleanly).

The workspace root pins `rustls = "=0.23.41"` and redirects it to the fork with
`[patch.crates-io] rustls = { path = "rustls-integration/rustls" }`, so the fork
is a normal dependency (not a workspace member): root `cargo
fmt`/`clippy`/`test` skip its files.

Backend is **aws-lc-rs** (feature `aws_lc_rs`; builds here with cc + cmake, no
nasm on aarch64). It is required for the post-quantum key exchange the deck
schedule targets — the ring provider has only X25519 / secp256r1 / secp384r1:

- **pure ML-KEM** (`kx_group::MLKEM768` / `MLKEM1024`, draft-ietf-tls-mlkem): a
  single KEM shared secret, which the deck absorbs as one `Absorb("dh", …)`
  (draft §7.3) — no hybrid-ordering issue. This is the clean deck key exchange.
- **hybrids** (`X25519MLKEM768`, `SECP256R1MLKEM768`) exist but rustls flattens
  their two component secrets into one `SharedSecret`, which conflicts with the
  deck's ordered per-component `Absorb("dh", …)` (draft §7.3). Deferred until the
  KX seam can expose ordered components; M4 registers single-component groups
  only (`MLKEM768`, `X25519`, `SECP256R1`).

Re-vendor (if ever needed): download `rustls-0.23.41.crate` from crates.io,
extract to `rustls/`, drop `Cargo.lock` / `.cargo_vcs_info.json` /
`Cargo.toml.orig`, and re-add the `[workspace]` table.

**Note (draft-ietf-tls-mlkem):** pure ML-KEM sends the client's encapsulation key
and the server's ciphertext as `KeyShareEntry`s; the KEM shared secret enters the
key schedule in place of `(EC)DHE`. For the deck that is a single
`input_secret` → `Absorb("dh", secret)`, so no code change beyond registering the
group. rustls exposes `MLKEM512`(0x0200)/`MLKEM768`(0x0201)/`MLKEM1024`(0x0202)/
`X25519MLKEM768`(0x11ec) in `NamedGroup`; aws-lc-rs implements `MLKEM768`,
`MLKEM1024`, and the two hybrids (not `MLKEM512`).

### Tracking our edits to the fork

Every change we make inside `rustls/` carries a `DECK-FORK` marker comment citing
the draft section it implements, so the full delta against upstream 0.23.41 is
`grep -rn DECK-FORK rustls/src/`. Edits so far:

- `rustls/src/tls13/mod.rs` `can_resume_from`: deck suites require an exact
  cipher-suite match for PSK/resumption, not RFC 8446's same-hash rule (draft §4,
  §15.2). Regression test: `deck_resumption_requires_exact_suite` in `src/lib.rs`.
- `rustls/src/tls13/key_schedule.rs` (M3): the inner `KeySchedule` is replaced by
  the deck schedule (draft §7.3) — a `DeckState` machine plus deck helpers, and
  `KeyScheduleSuite`'s leaf ops routed to `deck-schedule` (record keys §5.3,
  Finished MAC §5.5, key update §5.4, exporter §5.6, resumption PSK §5.7). Two
  outer touchpoints: `into_handshake` ratchets `main_secret` after `TH_SH`;
  `KeyScheduleBeforeFinished::new` enters the application stage with `TH_SF`.
  The **PSK binder** (§5.5) is implemented (Stage 6A/6B) via
  `KeySchedule::binder_verify_data` → `deck_schedule::derive::binder_verify_data`,
  parametrized by binder label (`BinderKind::Resumption` for a resumption ticket,
  `BinderKind::External` for an imported external PSK, draft §10).
  The unimplemented deck features fail **cleanly**, not by panic (Stage 6C): 0-RTT
  is declined at negotiation (a `DECK-FORK` `is_deck_suite` gate stops the deck
  client offering, and the deck server accepting, early data — §11), and both ECH
  acceptance confirmations (`server_ech_confirmation_secret` /
  `server_ech_hrr_confirmation_secret`) return `Result<_, Error>` with a clean
  error (§5.8). No `deck_unsupported!`/`panic!` remains in `rustls/src/tls13`; the
  leftover markers are `unreachable!` internal invariants. `rustls/Cargo.toml`
  gains a `deck-schedule` path dependency. Scope: no-0-RTT/no-ECH/no-hybrid 1-RTT,
  with session resumption.

  **Validation:** `deck_schedule_selftest` (re-exported `#[doc(hidden)]` from the
  fork's `lib.rs`) drives the schedule through the typestates' no-PSK order; the
  root test `deck_schedule_matches_reference` (`src/lib.rs`) checks every derived
  secret — c/s handshake, c/s application, exporter, resumption master, Finished
  MAC, record key/iv — byte-for-byte against `deck_schedule::schedule::run`. So
  the wiring is validated against the independent reference now, not only by M4
  peer agreement.

  **Session resumption (Stage 6A):** the deck PSK binder (§5.5) is implemented, so
  resumption works — `tests/resumption.rs` drives a full handshake + ticket, then a
  resumed handshake on a deck suite (via both hand-rolled configs and the public
  helpers). `deck_server_config`/`deck_client_config` now default to **1-RTT
  resumption on, 0-RTT off** (tickets enabled, `max_early_data_size`/
  `enable_early_data` forced off). The binder MACs under the `"res binder"` label,
  not `"finished"` — flattening that onto the Finished path would break it, so the
  distinction is pinned by a deck-schedule regression test.

  **External PSK (Stage 6B):** rustls 0.23.41 has no external-PSK config surface
  (its `PresharedKey` path is resumption-only), so the fork adds one — a
  `DeckExternalPsk` type (`rustls/src/deck_psk.rs`), a `ClientConfig.deck_external_psk`
  offer and a `ServerConfig.deck_external_psks` accept list, an external-PSK offer
  path in the ClientHello (`prepare_deck_external_psk`, `client/hs.rs`), and
  server-side identity matching + external-binder verification (`deck_external_ipsk`,
  `server/tls13.rs`). An external-PSK + (EC)DHE handshake is *structurally* a 1-RTT
  resumption (`pre_shared_key` + `psk_dhe_ke`, no server Certificate), so it reuses
  the resumption offer/accept machinery, differing only in the PSK source (import
  vs `resumption_psk`) and the binder label (`"ext binder"`, draft §5.5). The
  client imports the PSK for one target deck suite (`ImportedIdentityV2`, §5.9),
  offers the serialized identity, and enforces the **exact-suite rule** (§4/§15.2)
  on the ServerHello; the `epsk`/`ipsk` are held in zeroizing buffers. Live end to
  end in `tests/external_psk.rs` (happy path + wrong-secret binder rejection).

  **Hardening (Stage 6D — done):** live secret state is zeroized on drop
  (draft §15.7.2.2) — the sponge capacity, the deck accumulator (and cloned
  trunks), squeezed secrets (returned as `Zeroizing`), and the fork's `DeckState`
  stage secrets + record-key scratch; the external-PSK `epsk`/`ipsk` too. The
  0-RTT/ECH fail-closed panics are gone as of Stage 6C — a clean rejection / error.
  The fork's own `#[cfg(test)]` key-schedule tests assert the old HKDF/RFC 8448
  values and are superseded by the cross-check above; they are not compiled in our
  workspace.

**Fork invariant:** a `Tls13CipherSuite` whose `hash_provider.algorithm()` reports
`HashAlgorithm::SHA512` is treated as a deck suite (the sentinel used above and
wherever deck-specific policy diverges from upstream). This holds because
rustls's real TLS 1.3 suites are SHA256/SHA384 only. If a non-deck SHA512 suite
is ever added to this fork, replace the sentinel with an explicit deck-suite
marker (e.g. a field on `Tls13CipherSuite` or a code-point range check).

## The seams (see PLAN.md Stage 4)

| rustls piece | change |
|---|---|
| `crypto::hash::Hash` provider | new `TranscriptHash`, 64-octet output, `"tls13 hash"` seed, `fork`/clone (draft §2.1) |
| `Tls13AeadAlgorithm` | **reuse** aws-lc-rs AES-128/256-GCM + ChaCha20-Poly1305 (draft §6) |
| `CipherSuiteCommon.suite` | register `0xFF01..=0xFF05` as `Tls13CipherSuite`s (draft §6) |
| `tls13/key_schedule.rs` | rewrite the `KeySchedule*` stage transitions to call `deck-schedule`; feed `TH_SH`/`TH_SF` at the ratchets (draft §7.3) |
| Finished MAC path | route `sign_finish` / `check_finish` to deck `MAC` (draft §5.5) |
| record key derivation | one deck expansion split into key‖iv (draft §5.3) |
| PSK binder path | `binder_verify_data` parametrized by label — `"res binder"` (resumption) / `"ext binder"` (external PSK, draft §5.5, §10) |
| external PSK (§10) | `DeckExternalPsk` + `ClientConfig.deck_external_psk` / `ServerConfig.deck_external_psks`; client offer (`prepare_deck_external_psk`) + server accept (`deck_external_ipsk`) |
| `CryptoProvider` | assemble suites + reuse kx groups, sig-verify, RNG, key provider |

### Why a fork and not just a custom `Hkdf` provider

rustls's `crypto::tls13::Hkdf` trait models extract/expand/hmac, but the draft's
ratchets **absorb the transcript** (`main_secret` binds `TH_SH`, draft §7.3.2),
and the trait gives no seam to inject `TH_SH`/`TH_SF` into the stage transition.
So the fork touches `KeySchedule` itself. Everything above it is unchanged.
