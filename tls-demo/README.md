# tls-demo

A client and server binary that complete a real TLS 1.3 handshake negotiating
one of this document's cipher suites (`0xFF01..=0xFF05`), driven by the
`rustls-integration` fork, plus an integration test that verifies the wire
behaviour end-to-end.

## Binaries

- `deck-server` — listens on `127.0.0.1:<port>` (default 4443), echoes one line
  per connection, prints the negotiated suite / key-exchange group / ALPN.
- `deck-client` — connects, sends a line, prints the echo, then prints an
  exported keying-material value (draft §5.6).

Both honour `SSLKEYLOGFILE` (NSS key-log format), so a captured session can be
decrypted in Wireshark.

```sh
# terminal 1
SSLKEYLOGFILE=/tmp/deck.keylog cargo run -p tls-demo --bin deck-server
# terminal 2
SSLKEYLOGFILE=/tmp/deck.keylog cargo run -p tls-demo --bin deck-client
```

A live run negotiates `0xFF01` (`TLS_AES_128_GCM_TURBOSHAKE256`) over pure
**ML-KEM768** and writes a key log with the five TLS 1.3 labels, each a 64-octet
deck secret.

Certificate authentication uses an accept-any verifier
(`rustls_integration::danger`) that still performs the real CertificateVerify
signature check — the draft puts authentication out of scope and notes it
commonly uses SHA-2 (draft §1.2, §15.5). A **certificate-free, PSK-authenticated**
deck handshake (no CertificateVerify at all) is exercised by
`rustls-integration/tests/external_psk.rs` — an out-of-band external PSK (§10)
authenticates the connection; an ML-DSA-cert demo remains a later variant.

## Verification (before canonical vectors exist)

`tests/demo.rs` runs a client and server over a **real TCP loopback** and
asserts:

- the handshake completes on a deck suite, with ALPN `deck-demo` on both peers;
- a two-way echo round-trips, including a 20 KB payload across a record boundary;
- a live `KeyUpdate` (draft §5.4) — round 2 is sent after `refresh_traffic_keys()`
  and still round-trips;
- `export_keying_material` (draft §5.6) agrees on both peers;
- the **key-log cross-check**: each peer's `CapturingKeyLog` recorded identical
  64-octet secrets for all five NSS labels, with a matching `client_random`.

If a deck-schedule client and server complete the handshake and exchange
application data, both peers independently derived identical traffic secrets from
the deck schedule — the end-to-end self-consistency proof. Byte-for-byte spec
correctness comes from `deck-schedule/vectors/reproduce.py`, the independent
vector reproduction.
