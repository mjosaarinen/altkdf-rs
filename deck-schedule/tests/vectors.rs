//! Compare all appendix entries against fixtures extracted from the specification.
use deck_schedule::{hex, vectors};
#[test]
fn all_162_appendix_values_match() {
    let draft = include_str!("../vectors/appendix.md");
    let mut checked = 0;
    for k in [deck_schedule::SHAKE256, deck_schedule::TURBOSHAKE256] {
        let heading = format!("## {} Vectors", k.name);
        let section = draft.split_once(&heading).unwrap().1;
        let section = section
            .split_once("~~~~")
            .unwrap()
            .1
            .split_once("~~~~")
            .unwrap()
            .0;
        let mut parsed: Vec<(String, Vec<u8>)> = Vec::new();
        for line in section.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_suffix(':') {
                parsed.push((name.to_string(), Vec::new()));
            } else if let Some(h) = line.strip_prefix("  ") {
                parsed.last_mut().unwrap().1.extend(hex::decode(h));
            } else {
                panic!("unexpected vector line: {line}");
            }
        }
        let actual = vectors::build(k);
        assert_eq!(actual.len(), 81);
        assert_eq!(actual.len(), parsed.len());
        for ((name, got), (expected_name, expected)) in actual.iter().zip(parsed) {
            assert_eq!(*name, expected_name);
            assert_eq!(*got, expected, "{} / {}", k.name, name);
            checked += 1;
        }
    }
    assert_eq!(checked, 162);
}
