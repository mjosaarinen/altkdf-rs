# DeckTLS TCP Demo

The demo uses standard TLS 1.3 AEAD code points and independently negotiates an
XOF KDF with the combined draft's `schedule_profile` extension.

```sh
SSLKEYLOGFILE=/tmp/deck-server.keylog cargo run -p tls-demo --bin deck-server
SSLKEYLOGFILE=/tmp/deck-client.keylog cargo run -p tls-demo --bin deck-client
```

Both default to `127.0.0.1:4443`; pass a port as the first argument to each
binary to change it. The default result is suite `0x1301`, KDF `0x0100`,
pure ML-KEM768, ALPN `deck-demo`, and an echoed message. The client also prints
an exporter value.

The client accepts any certificate chain, while verifying CertificateVerify.
Use this only for the loopback prototype.

`cargo test -p tls-demo` drives a real TCP exchange, including a 20 KB message
after KeyUpdate, exporter agreement and matching 64-octet traffic secrets in the
two key logs.

The logs use NSS labels and formatting. **Unmodified Wireshark does not know
this XOF key schedule**, so a standard-format log alone does not enable capture
decryption. A dissector/key-derivation implementation for the experimental
extension is still needed. The socket test verifies record encryption/decryption
through rustls, not through Wireshark.

The config helpers enable 1-RTT session tickets and decline early data.
KDF selection is available through `negotiated_schedule_profile()`; suite names
alone no longer identify the schedule.
