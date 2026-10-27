# rustls-integration

The vendored rustls 0.23.41 fork implements
[draft-sullivan-tls-xof-schedule](https://github.com/grittygrease/draft-sullivan-tls-xof-schedule-collab/blob/c6c02fbc45e5febbbc958068b4599e06f01f1dc0/draft-sullivan-tls-xof-schedule.md).
Local fork changes are marked `DECK-FORK`.

## Negotiation

`src/suites.rs` creates six internal virtual suites: the standard AEAD code
points 0x1301/0x1302/0x1303 paired with each of the two XOF KDFs. Their hash
providers expose explicit `Hash::schedule_profile()` metadata. The SHA512 tag
only represents the 64-octet output size; it does not establish compatibility.

`schedule_profile` uses experimental extension 0xffa6, with a length-prefixed
uint16 list in ClientHello and one uint16 in ServerHello or HRR. The fork
validates unoffered/unsolicited selections, required-schedule absence, and
HRR pinning before selecting the transcript provider. Providers containing only
virtual suites require an XOF; adding ordinary suites permits HKDF fallback.

Use `deck_provider()` for composition, or `deck_server_config()` and
`deck_client_config()` for TLS 1.3, 1-RTT resumption on, and early data off by
default. Set the rustls early-data configuration fields to opt in to 0-RTT.
`negotiated_schedule_profile()` returns the KDF Identifier, or None for HKDF.

## Schedule And PSKs

The fork's state variants carry the independently implemented early, handshake
and application stages. Contexts belong to leaves; stage ratchets bind no
transcript. The PSK path uses the residue jointly derived with its ebk/ibk/rbk
binder key, not the no-PSK ratchet.

Handshake records use the joint fin/key tuple; application records use upd/key.
Some joint tuples are recomputed at separate rustls call sites. The standalone
count example measures the minimal draft graph, not this live call count.

Session tickets retain the KDF Identifier in the private server session encoding,
and client sessions retain their virtual suite. A ticket may resume under a
different AEAD with the same KDF; a KDF mismatch causes a full handshake.
The new encoding intentionally does not accept old experimental tickets.

`DeckExternalPsk` imports a provisioned EPSK under RFC 9258 ImportedIdentity,
per target KDF, and uses the imported ibk binder. The public fields remain
`ClientConfig.deck_external_psk` and `ServerConfig.deck_external_psks`.
This surface supports imported external PSKs with DHE; raw external PSKs and
PSK-only handshakes have core/vector coverage, not live configuration.

## Coverage

Tests cover every supported AEAD/KDF pair, ML-KEM768, both hybrid groups,
accepted 0-RTT, transcript/schedule cross-checking, full and resumed handshakes,
imported external PSKs (including
HRR and AEAD changes), wrong binders, required-KDF and fallback policy,
unoffered/unsolicited selections, and HRR pinning. The demo adds TCP, KeyUpdate,
exporter agreement, and NSS secret-log agreement.

The client can offer XOF+ECH and computes
the ServerHello and HRR acceptance confirmations with the selected KDF. An
ordinary server's ECH rejection is tested under XOF and ordinary HKDF outer
handshakes; accepted ECH still needs an external server interoperability test.
Imported external PSKs with ECH fail before ClientHello until their binder can
be computed over ClientHelloInner. The fork has no ECH server.
Ordinary HKDF ECH retains its upstream derivation. QUIC has no defined XOF
mapping. The default groups are ML-KEM768, X25519MLKEM768,
secp256r1MLKEM768, X25519, and secp256r1. Hybrid XOF handshakes absorb their
component secrets separately in the group's specified order. XOF rejects an
unknown key exchange group or a known hybrid without component metadata.

The workspace excludes the vendor from its formatting/lint file set.
`make ci` builds it as a dependency and tests the integration behavior.
