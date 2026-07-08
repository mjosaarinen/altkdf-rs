//! Cross-check against published test vectors.
//!
//! Two vector families feed this harness:
//!
//!  1. **Public primitive KATs** (RFC 9861 TurboSHAKE, FIPS 202 SHAKE256,
//!     SP 800-185 KMAC256) — validate the permutation, sponge, and MAC without
//!     needing the draft's own vectors. These live in the unit tests of
//!     `src/sponge.rs` and `src/mac.rs` (PLAN.md Stages 1–2).
//!
//!  2. **Draft Appendix C vectors** — the full schedule trace and every §5
//!     derivation. Because every derived output binds the governing cipher
//!     suite, no *final* vector can exist before code points are assigned
//!     (draft §14 OPEN ISSUE); the committed sets under `vectors/` use the
//!     `0xFF01..=0xFF05` placeholders. `deck-schedule` *generates* them
//!     deterministically and an independent implementation
//!     (`vectors/reproduce.py`) reproduces them from the draft alone (draft
//!     Appendix C).
//!
//! This harness pins the committed files as current: the crate is the single
//! source of truth, so the files must equal what the generator emits. Spec
//! *correctness* comes from the primitive KATs (family 1) plus the independent
//! reproduction, not from this self-consistency check.
//!
//! See `PLAN.md` Stages 1–3.

use std::path::PathBuf;

use deck_schedule::vectors::{fips_json, shake256_json, turboshake256_json};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors")
}

/// The committed vector files match what the generator currently emits. If this
/// fails after an intentional encoding or code-point change, regenerate with
/// `cargo run -p deck-schedule --example gen_vectors` and re-run the
/// independent reproduction (`deck-schedule/vectors/reproduce.py` from the
/// workspace root, or `vectors/reproduce.py` from this crate).
#[test]
fn committed_vectors_are_current() {
    for (file, generated) in [
        ("turboshake256.json", turboshake256_json()),
        ("shake256.json", shake256_json()),
        ("fips.json", fips_json()),
    ] {
        let path = vectors_dir().join(file);
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        assert_eq!(
            committed,
            generated,
            "\n{} is stale — regenerate with `cargo run -p deck-schedule --example gen_vectors`\n",
            path.display()
        );
    }
}

/// Generation is deterministic: the same inputs yield byte-identical JSON, so
/// the committed artifact is reproducible and the diff above is meaningful.
#[test]
fn generation_is_deterministic() {
    assert_eq!(turboshake256_json(), turboshake256_json());
    assert_eq!(shake256_json(), shake256_json());
    assert_eq!(fips_json(), fips_json());
}

/// The generated sets are non-trivial and carry the expected profile markers,
/// guarding against an empty or truncated emission slipping past the equality
/// check above.
#[test]
fn generated_sets_are_well_formed() {
    let turbo = turboshake256_json();
    assert!(turbo.contains("\"profile\": \"TLS13-TURBOSHAKE256\""));
    assert!(turbo.contains("\"op\": \"schedule\""));
    assert!(turbo.contains("\"psk_import_frame_limit\""));
    // The recorded != selected wiring pin must be present in both sets (draft §4).
    assert!(turbo.contains("\"schedule_suite_split\""));
    assert!(turbo.contains("\"record_count\":"));

    let shake = shake256_json();
    assert!(shake.contains("\"profile\": \"TLS13-SHAKE256\""));
    assert!(shake.contains("\"rounds\": 24"));
    assert!(shake.contains("\"schedule_suite_split\""));

    // The informative FIPS-component set (draft Appendix D) carries no profile
    // header but has its schedule marker and the full-trace record.
    let fips = fips_json();
    assert!(fips.contains("\"schedule\": \"FIPS-component (Appendix D)\""));
    assert!(fips.contains("\"informative\": true"));
    assert!(fips.contains("\"op\": \"fips_schedule\""));
}
