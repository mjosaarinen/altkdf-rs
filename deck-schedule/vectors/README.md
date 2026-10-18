# Appendix Vector Fixtures

`appendix.md` contains the two Test Vectors appendix blocks from
[draft-sullivan-tls-xof-schedule, revision 9f5554a](https://github.com/grittygrease/draft-sullivan-tls-xof-schedule-collab/blob/9f5554a7fe4d61db15f2bc467ab69fa6754ec638/draft-sullivan-tls-xof-schedule.md#test-vectors).
The full revision is `9f5554a7fe4d61db15f2bc467ab69fa6754ec638`, PR #3's
head including PR #2. There are 81 named values per KDF, 162 total.
Names, ordering and bytes are unchanged; no draft prose or local spec edits
are included. See [the crate notice](../NOTICE.md) for attribution.

`src/vectors.rs` computes the fixtures using the Rust core.
`tests/vectors.rs` reads the fixed appendix blocks and compares all names and
bytes in order. Expectations are not regenerated from Rust output.
The test is self-contained, including when the core crate is packaged.

`make vectors` emits tab-separated KDF, name and hex output.
`make reproduce` runs the appendix comparison. There are no old FIPS-component
or KMAC fixtures.

The KDF IDs 0x0100 and 0x0101 are appendix placeholders. Changing them changes
the imported identities and their imported-PSK descendants.
