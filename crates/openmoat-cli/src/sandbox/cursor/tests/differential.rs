//! Cursor's `sandbox.json` against the IR's reference semantics
//! (`sandbox/differential.rs`), read the way Cursor documents it (`cursor.rs`
//! says what the generator relies on): every sampled path the checker denies
//! must be denied there too or named by the report. The reading models only
//! what the file says: Cursor's system paths, which Cursor adds itself, grant
//! nothing here, so a path the checker allows there may read as narrower,
//! which needs a loss.

use openmoat_core::Kind;
use openmoat_core::ir::Effect;

use crate::sandbox::differential::{host_ir, policies, samples_in, under, unreported};
use crate::sandbox::{PROJECT as HOST_PROJECT, Report};

/// `report` with `${project}` in its patterns spelled as the placeholder the
/// samples use, as Cursor's report names the workspace.
fn spelled(report: &Report) -> Report {
    let mut report = report.clone();
    for allowance in &mut report.allowances {
        for pattern in &mut allowance.patterns {
            *pattern = pattern.replace("${project}", HOST_PROJECT);
        }
    }
    report
}

/// `sandbox.json` as Cursor documents it: commands read and write the
/// workspace, read the read and read-write lists and write the read-write
/// list and the temp directory; no key denies a path.
fn cursor_effect(
    settings: &serde_json::Map<String, serde_json::Value>,
    kind: Kind,
    path: &str,
) -> Effect {
    let list = |key: &str| -> Vec<String> {
        settings[key]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let (reads, writes) = (
        list("additionalReadPaths"),
        list("additionalReadwritePaths"),
    );
    // Cursor's own temp directory is not one of the samples' paths; its
    // grant is the `cursor.workspace` allowance.
    let granted = under(path, HOST_PROJECT)
        || writes.iter().any(|w| under(path, w))
        || (kind == Kind::FsRead && reads.iter().any(|r| under(path, r)));
    if granted { Effect::Allow } else { Effect::Deny }
}

#[test]
fn cursor_settings_deny_every_sampled_path_the_checker_denies_or_report_it() {
    for yaml in policies() {
        let ir = host_ir(yaml);
        let generated = super::super::generate(&ir, None).expect("generates");
        let checker = ir.checker().expect("compiles");
        let wrong = unreported(
            &checker,
            &spelled(&generated.report),
            &samples_in(&ir, HOST_PROJECT),
            false,
            |kind, path| cursor_effect(&generated.settings, kind, path),
        );
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}
