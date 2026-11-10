//! What each OWASP agentic risk of `docs/COVERAGE.md` is tested by (ADR-079):
//! the attack and review fixtures of the threat classes that map to it, and
//! the end-to-end tests of `crates/openmoat-cli/tests/e2e/` marked for it.
//!
//! A test is marked by a line `// coverage: ASI01, ASI06` above its `#[test]`;
//! the test's path (`taint::fetched_content_makes_…`) is the evidence. A risk
//! with no fixture and no marked test is `not tested`, whatever it claims.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// The marker a test is tagged with.
const MARKER: &str = "// coverage:";

/// The marked end-to-end tests, by risk id, each as `module::test`.
pub(super) type Tests = BTreeMap<String, Vec<String>>;

/// Every `.rs` file under `dir`, sorted, so the output does not depend on the
/// order the file system lists them in.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
}

/// `e2e/hosts/rows.rs` as `hosts::rows`.
fn module_of(file: &Path, e2e: &Path) -> String {
    let relative = file.strip_prefix(e2e).unwrap().with_extension("");
    relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("::")
}

/// The marks of one file's `text`: each marked test with its risks, or why a
/// mark is wrong (it names no risk, or no `#[test] fn` follows it).
fn marks(text: &str, module: &str) -> (Vec<(String, String)>, Vec<String>) {
    let (mut found, mut problems) = (Vec::new(), Vec::new());
    let mut pending: Option<(usize, Vec<String>, bool)> = None;
    for (n, line) in (1..).zip(text.lines()) {
        let line = line.trim();
        if let Some(list) = line.strip_prefix(MARKER) {
            let risks: Vec<String> = list
                .split(',')
                .map(|r| r.trim().to_owned())
                .filter(|r| !r.is_empty())
                .collect();
            if risks.is_empty() {
                problems.push(format!("{module}:{n}: `{MARKER}` names no risk"));
            }
            pending = Some((n, risks, false));
            continue;
        }
        let Some((at, risks, is_test)) = pending.as_mut() else {
            continue;
        };
        if line == "#[test]" {
            *is_test = true;
        } else if let Some(rest) = line.strip_prefix("fn ") {
            let name = rest.split(['(', '<']).next().unwrap_or_default();
            if *is_test {
                for risk in risks.iter() {
                    found.push((risk.clone(), format!("{module}::{name}")));
                }
            } else {
                problems.push(format!(
                    "{module}:{at}: `{MARKER}` is above `fn {name}`, not a test"
                ));
            }
            pending = None;
        } else if !(line.is_empty() || line.starts_with("//") || line.starts_with("#[")) {
            problems.push(format!(
                "{module}:{at}: `{MARKER}` is not followed by a test"
            ));
            pending = None;
        }
    }
    if let Some((at, ..)) = pending {
        problems.push(format!(
            "{module}:{at}: `{MARKER}` is not followed by a test"
        ));
    }
    (found, problems)
}

/// Every marked end-to-end test under `e2e`, by risk, or the problems found.
pub(super) fn e2e_tests(e2e: &Path, known: &[&str]) -> Result<Tests, Vec<String>> {
    let mut files = Vec::new();
    rust_files(e2e, &mut files);
    assert!(
        !files.is_empty(),
        "no end-to-end tests in {}",
        e2e.display()
    );
    let (mut tests, mut problems) = (Tests::new(), Vec::new());
    for file in files {
        let module = module_of(&file, e2e);
        let (found, wrong) = marks(&fs::read_to_string(&file).unwrap(), &module);
        problems.extend(wrong);
        for (risk, test) in found {
            if known.contains(&risk.as_str()) {
                tests.entry(risk).or_default().push(test);
            } else {
                problems.push(format!("{test}: `{MARKER}` names unknown risk `{risk}`"));
            }
        }
    }
    if problems.is_empty() {
        Ok(tests)
    } else {
        Err(problems)
    }
}

/// The `docs/COVERAGE.md` section that lists, for each risk in `risks`
/// (id and name), its marked tests and the ids of `fixtures(risk)`.
pub(super) fn section(
    risks: &[(&str, &str)],
    tests: &Tests,
    fixtures: impl Fn(&str) -> Vec<String>,
) -> String {
    let mut out = String::from(
        "\n## Evidence by OWASP agentic risk\n\n\
         What each risk above is tested by: the end-to-end tests marked for it (`// coverage: \
         ASI<nn>` above a test in `crates/openmoat-cli/tests/e2e/`) and the attack and review \
         fixtures of the threat classes that map to it, whose verdicts are listed under each \
         class below. A risk with neither is not tested.\n",
    );
    for (id, name) in risks {
        let _ = write!(out, "\n### {id}: {name}\n\n");
        let marked = tests.get(*id).map_or(&[][..], Vec::as_slice);
        let ids = fixtures(id);
        if marked.is_empty() && ids.is_empty() {
            out.push_str("Not tested.\n");
            continue;
        }
        let names = |list: &[String]| {
            list.iter()
                .map(|t| format!("`{t}`"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let _ = writeln!(
            out,
            "- End-to-end tests ({}): {}",
            marked.len(),
            if marked.is_empty() {
                "none".to_owned()
            } else {
                names(marked)
            }
        );
        let _ = writeln!(
            out,
            "- Fixtures ({}): {}",
            ids.len(),
            if ids.is_empty() {
                "none".to_owned()
            } else {
                names(&ids)
            }
        );
    }
    out
}

#[test]
fn a_mark_above_a_test_names_it_with_its_module() {
    let text = "// coverage: ASI01, ASI06\n/// Doc.\n#[test]\nfn some_test() {}\n";
    let (found, problems) = marks(text, "taint");
    assert_eq!(problems, Vec::<String>::new());
    assert_eq!(
        found,
        [
            ("ASI01".to_owned(), "taint::some_test".to_owned()),
            ("ASI06".to_owned(), "taint::some_test".to_owned())
        ]
    );
}

#[test]
fn a_mark_with_no_test_after_it_is_a_problem() {
    for text in [
        "// coverage: ASI01\nfn helper() {}\n",
        "// coverage: ASI01\nconst X: u8 = 1;\n#[test]\nfn t() {}\n",
        "// coverage: ASI01\n",
        "// coverage:\n#[test]\nfn t() {}\n",
    ] {
        let (_, problems) = marks(text, "m");
        assert_eq!(problems.len(), 1, "{text:?}: {problems:?}");
    }
}

#[test]
fn a_risk_without_evidence_reads_not_tested() {
    let tests = Tests::from([("ASI02".to_owned(), vec!["m::t".to_owned()])]);
    let text = section(&[("ASI01", "A"), ("ASI02", "B")], &tests, |_| Vec::new());
    assert!(text.contains("### ASI01: A\n\nNot tested.\n"), "{text}");
    assert!(
        text.contains("- End-to-end tests (1): `m::t`\n- Fixtures (0): none\n"),
        "{text}"
    );
}
