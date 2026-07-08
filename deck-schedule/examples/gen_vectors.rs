//! Regenerate the Appendix C test-vector files under `deck-schedule/vectors/`.
//!
//! ```sh
//! cargo run -p deck-schedule --example gen_vectors
//! ```
//!
//! The output is deterministic: `deck-schedule::vectors::generate_json` is the
//! single source of truth, and `tests/vectors.rs` asserts the committed files
//! match it byte-for-byte, so this example only needs to be re-run when the
//! draft's encoding or the placeholder code points change. The generated JSON is
//! reproduced independently by `deck-schedule/vectors/reproduce.py` (draft
//! Appendix C).

use deck_schedule::vectors::{fips_json, shake256_json, turboshake256_json};
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    // Package-local layout, so the vector tests also work from a packaged crate.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors");

    for (file, json) in [
        ("turboshake256.json", turboshake256_json()),
        ("shake256.json", shake256_json()),
        ("fips.json", fips_json()),
    ] {
        let path = dir.join(file);
        std::fs::write(&path, &json)?;
        println!("wrote {} ({} bytes)", path.display(), json.len());
    }
    Ok(())
}
