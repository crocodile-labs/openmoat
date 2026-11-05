//! The diff fixtures in `tests/fixtures/check-diff/{attack,benign}/`: each is a
//! unified diff whose leading comment says the result it must get against the
//! default policy (`# expect: clean|review|deny`) and exactly which content
//! rules it must find (`# rules: …`, empty for none). Attacks must be found;
//! the benign changes of daily work must find no content rule they do not list.

use std::path::Path;

use openmoat_core::diffscan;

use super::check;
use crate::commands::policy::diff::output;

fn header<'t>(text: &'t str, key: &str) -> Option<&'t str> {
    text.lines()
        .take_while(|l| l.starts_with('#'))
        .find_map(|l| l.strip_prefix(&format!("# {key}:")))
        .map(str::trim)
}

#[test]
fn every_check_diff_fixture_gets_its_expected_result() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/check-diff");
    let mut seen = 0;
    for kind in ["attack", "benign"] {
        let mut entries: Vec<_> = std::fs::read_dir(root.join(kind))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            let text = std::fs::read_to_string(&path).unwrap();
            let name = path.display();
            let expect = header(&text, "expect").unwrap_or_else(|| panic!("{name}: no expect"));
            let mut want: Vec<&str> = header(&text, "rules")
                .unwrap_or_else(|| panic!("{name}: no rules"))
                .split_whitespace()
                .collect();
            want.sort_unstable();
            let findings = check(&text);
            let mut got: Vec<&str> = findings
                .iter()
                .flat_map(|f| &f.rules)
                .map(String::as_str)
                .filter(|r| diffscan::rule(r).is_some())
                .collect();
            got.sort_unstable();
            got.dedup();
            assert_eq!(got, want, "{name}: {findings:#?}");
            let result = output::worst(&findings).map_or("clean", |l| l.as_str());
            assert_eq!(result, expect, "{name}: {findings:#?}");
            if kind == "attack" {
                assert!(
                    !want.is_empty(),
                    "{name}: an attack fixture names its rules"
                );
                // every content finding points at the line it is about
                assert!(
                    findings
                        .iter()
                        .filter(|f| f.rules.iter().any(|r| diffscan::rule(r).is_some()))
                        .all(|f| f.line.is_some()),
                    "{name}: {findings:#?}"
                );
            }
            seen += 1;
        }
    }
    assert!(seen >= 10, "only {seen} fixtures were read");
}
