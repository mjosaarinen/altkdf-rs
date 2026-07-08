# Implementation findings — `draft-sullivan-tls-xof-ciphers-00`

Notes for the draft author from building the prototype in this repository (a
dependency-free Rust reference of the deck key schedule, an independent Python
reproduction, a rustls fork with a live handshake, and a permutation-count
benchmark). Line numbers refer to `doc/draft-sullivan-tls-xof-ciphers-00.txt`.

Nothing here is a security concern; the construction reproduced cleanly. These
are editorial / accounting observations and one under-specified informative
appendix, offered to tighten the next revision.

## Findings

### 1. Table 4 appears to over-count the deck by one invocation

§7.3's schedule pseudocode defines **two** ratchets — `early_secret =
Ratchet(E, "early secret")` (line 1135) and `main_secret = Ratchet(H, "main
secret")` (line 1148). Table 4's deck column (line ~2338) totals **29**, and its
breakdown lists **three** "Ratchet" rows. Instrumenting the representative
handshake over the shared permutation measures **28** deck invocations, not 29.
Suggest reconciling Table 4's deck total to 28 (or clarifying which third ratchet
is intended). The RFC column (39) is unaffected and matches.

### 2. The §A.1 deck permutation figure (52) looks conservative

§A.1 (line 235) states the deck costs **52** permutations against 156 for
HKDF-SHA3-256 (a factor of three). Measured here, **both** realizations §7.1.2
permits come in well under 52: the stateful clone-per-fork realization costs
**41** permutations (a **3.80×** advantage over HKDF-SHA3-256, not 3.0×), and the
recompute-from-path realization of Appendix B (which re-absorbs each stage trunk)
costs **46** (3.39×). So 52 appears to over-state the deck's cost regardless of
which realization it refers to; the true advantage is larger than the draft
claims. (This is favourable to the draft — just worth updating the headline
number, and stating which realization it counts.)

### 3. Appendix D (the FIPS-component schedule) is under-specified to reproduce

Appendix D is explicitly informative and gives no test vectors, but three
byte-level choices are left entirely to the implementer, so two conforming
implementations need not agree:

- **The SP 800-108 counter-mode input encoding.** The counter width, the
  Label/Context separator, and the encoding of the output-length field `[L]` are
  unstated. This prototype used the textbook KDF-in-counter-mode fixed input
  `be32(i) || Label || 0x00 || Context || be32(L_bits)` (with `Context` empty per
  the next point).
- **How RFC 8446's `HkdfLabel` maps onto SP 800-108's *Label* / *Context*.** This
  prototype feeds the entire RFC 8446 `HkdfLabel` as the SP 800-108 *Label* with
  an empty *Context* (keeping the RFC 8446 labelling verbatim).
- **Counter mode vs. a single KMAC call.** The appendix says "SP 800-108 KBKDF
  counter-mode … with KMAC256 as the PRF". SP 800-108r1 derives the requested bits
  in a *single* KMAC invocation (KMAC being an XOF), whereas literal counter mode
  iterates the PRF per output block; the two produce different bytes, so it is
  worth stating which is intended.

A one-paragraph encoding note, or a single published vector, would make Appendix D
independently reproducible. (This prototype's interpretation is documented in
`deck-schedule/src/fips.rs` and pinned by `deck-schedule/vectors/fips.json`, reproduced by the
independent Python implementation — but that is one reading, not *the* reading.)

### 4. Measured cost of the Appendix D alternative, for comparison

For the same representative handshake, the FIPS-component schedule (KMAC256
Extract/Expand) costs **117 permutations / 39 invocations**. It has the *same
invocation count* as HKDF-SHA3-256 — it **is** the RFC 8446 schedule with the PRF
swapped — and lands between the deck (41) and HKDF-SHA3-256 (156): cheaper than
HMAC-based HKDF (one KMAC per site vs HMAC's two hash calls) but still **~2.85×
the deck**. Useful framing for §A / Appendix D: an approved-component schedule
recovers none of the deck's stateful savings, so the deck's advantage is its
*structure*, not merely its use of Keccak.

### 5. Minor: the PSK-binder MAC label is easy to get wrong

§5.5 takes the binder as `MAC(finished_key, suite, LABEL, TH_CH0, FLen)` where
`LABEL` is the *binder* label (`"res binder"` / `"ext binder"`), even though the
`finished_key` is expanded under `"finished"`. It is tempting to flatten this onto
the ordinary Finished path (which MACs under `"finished"`), which silently yields
a different, wrong binder. A one-line reminder in §5.5 that the MAC label is the
binder label — not `"finished"` — would help implementers. (This prototype pins
the distinction with a regression test.)

---

*Bottom line: the specification is complete and implementable as written — the
prototype realizes every normative feature of the key schedule in code (all five
cipher suites, the full §7.3 schedule, every §5 derivation, the §10 importer) and
demonstrates 1-RTT handshake, resumption, KeyUpdate/exporter, and external PSK
live over two peers; 0-RTT and ECH are implemented/vectored but not driven live
(declined / fail-closed by scope, not a draft gap). Only editorial notes remain to
feed back. See `README.md` for the validation summary and how to run it, and
`deck-schedule/vectors/reproduce.py` for the independent cross-check.*
