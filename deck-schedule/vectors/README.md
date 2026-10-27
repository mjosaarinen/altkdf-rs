# Appendix Vector Fixtures

`appendix.md` contains the two Test Vectors appendix blocks from
[draft-sullivan-tls-xof-schedule, revision c6c02fb](https://github.com/grittygrease/draft-sullivan-tls-xof-schedule-collab/blob/c6c02fbc45e5febbbc958068b4599e06f01f1dc0/draft-sullivan-tls-xof-schedule.md#test-vectors).
The full revision is `c6c02fbc45e5febbbc958068b4599e06f01f1dc0`, the
collaborative repository's `main` through PR #15. The values have not changed
since revision 9f5554a. There are 81 named values per KDF, 162 total.
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
