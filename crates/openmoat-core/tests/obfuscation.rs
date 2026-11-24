//! Calibration of the obfuscation score (ADR-116): no everyday command among
//! the conformance suite's allowed fixtures and `MoatBench`'s allowed or
//! deferred steps reaches [`THRESHOLD`], and every attack fixture written to
//! hide what it runs does.

use std::fs;
use std::path::{Path, PathBuf};

use openmoat_core::obfuscation::{Dialect, THRESHOLD, assess};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    id: String,
    action: FixtureAction,
    expect: Expect,
}

#[derive(Deserialize)]
struct FixtureAction {
    shell: Option<String>,
    foreign_shell: Option<ForeignShell>,
}

#[derive(Deserialize)]
struct ForeignShell {
    shell: String,
    command: String,
}

#[derive(Deserialize)]
struct Expect {
    verdict: String,
}

#[derive(Deserialize)]
struct Scenario {
    id: String,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    shell: Option<String>,
    expect: String,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    files
}

fn fixtures() -> Vec<Fixture> {
    yaml_files(&repo_root().join("tests/conformance"))
        .iter()
        .flat_map(|file| {
            let text = fs::read_to_string(file).expect("fixture file");
            openmoat_core::yaml::from_str::<Vec<Fixture>>(&text)
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()))
        })
        .collect()
}

/// The line of a fixture and the dialect it is written in.
fn line(action: &FixtureAction) -> Option<(&str, Dialect)> {
    if let Some(shell) = &action.shell {
        return Some((shell, Dialect::Posix));
    }
    let foreign = action.foreign_shell.as_ref()?;
    foreign
        .shell
        .eq_ignore_ascii_case("powershell")
        .then_some((foreign.command.as_str(), Dialect::PowerShell))
}

#[test]
fn no_allowed_fixture_reaches_the_threshold() {
    let mut checked = 0;
    let mut flagged = Vec::new();
    for fixture in fixtures() {
        if fixture.expect.verdict != "allow" {
            continue;
        }
        let Some((line, dialect)) = line(&fixture.action) else {
            continue;
        };
        checked += 1;
        let a = assess(line, dialect);
        if a.obfuscated() {
            flagged.push(format!("{}: {line} {a:?}", fixture.id));
        }
    }
    assert!(checked > 300, "only {checked} allowed fixtures were scored");
    assert!(
        flagged.is_empty(),
        "allowed fixtures at or above {THRESHOLD}:\n{}",
        flagged.join("\n")
    );
}

#[test]
fn no_moatbench_step_that_runs_reaches_the_threshold() {
    let dir = repo_root().join("crates/openmoat-cli/moatbench");
    let mut checked = 0;
    let mut flagged = Vec::new();
    for file in yaml_files(&dir) {
        let text = fs::read_to_string(&file).expect("scenario file");
        let scenarios: Vec<Scenario> = openmoat_core::yaml::from_str(&text)
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        for scenario in scenarios {
            for step in &scenario.steps {
                let Some(shell) = &step.shell else { continue };
                if !matches!(step.expect.as_str(), "allow" | "defer") {
                    continue;
                }
                checked += 1;
                let a = assess(shell, Dialect::Posix);
                if a.obfuscated() {
                    flagged.push(format!("{}: {shell} {a:?}", scenario.id));
                }
            }
        }
    }
    assert!(checked > 50, "only {checked} MoatBench steps were scored");
    assert!(
        flagged.is_empty(),
        "MoatBench steps at or above {THRESHOLD}:\n{}",
        flagged.join("\n")
    );
}

/// The attack fixtures that exist for the signal (`attack-obfuscated-…`)
/// reach it on the score alone, whatever else holds them.
#[test]
fn obfuscation_fixtures_reach_the_threshold() {
    let mut checked = 0;
    for fixture in fixtures() {
        if !fixture.id.contains("obfuscated") {
            continue;
        }
        let Some((line, dialect)) = line(&fixture.action) else {
            continue;
        };
        checked += 1;
        let a = assess(line, dialect);
        assert!(a.obfuscated(), "{}: {line} {a:?}", fixture.id);
    }
    assert!(checked >= 5, "only {checked} obfuscation fixtures");
}
