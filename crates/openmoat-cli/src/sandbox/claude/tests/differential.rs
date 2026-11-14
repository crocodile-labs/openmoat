//! Claude Code's settings against the IR's reference semantics
//! (`sandbox/differential.rs`): every deny pattern is listed or reported.

use openmoat_core::Kind;
use openmoat_core::Policy;

use crate::sandbox::differential::{HOME, policies};
use crate::sandbox::patterns::Spot;

/// Each deny pattern of the IR is in Claude Code's `denyRead`/`denyWrite`
/// (macOS, globs kept), or the report names it.
#[test]
fn claude_code_settings_deny_every_pattern_the_ir_denies_or_report_it() {
    for yaml in policies() {
        let policy = Policy::parse(yaml).expect("test policy lints");
        let ir = crate::sandbox::lower_for_hosts(&policy, HOME, None, Vec::new(), false)
            .expect("lowers");
        let generated = super::super::generate(&ir, None, false).expect("generates");
        let list = |key: &str| -> Vec<String> {
            generated.sandbox["filesystem"][key]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut missing = Vec::new();
        for (access, key, kind) in [
            (&ir.fs.read, "denyRead", Kind::FsRead),
            (&ir.fs.write, "denyWrite", Kind::FsWrite),
        ] {
            let listed = list(key);
            for rule in &access.deny {
                for pattern in crate::sandbox::patterns::split(&rule.patterns).0 {
                    // `**/x` is written `/**/x`: a relative path would resolve
                    // against `~/.claude`. User settings cannot name the
                    // project, so a project path is denied in every directory.
                    let absolute = match crate::sandbox::patterns::spot(pattern) {
                        Spot::Project("" | "**") => "/".to_owned(),
                        Spot::Project(rest) | Spot::Anywhere(rest) => format!("/**/{rest}"),
                        Spot::Absolute(path) => path.to_owned(),
                    };
                    let bare = absolute.strip_suffix("/**").unwrap_or(&absolute);
                    let named =
                        listed.iter().any(|l| l == &absolute || l == bare)
                            || generated.report.allowances.iter().any(|a| {
                                a.kind == kind && a.patterns.iter().any(|p| p == &absolute)
                            })
                            || generated
                                .report
                                .losses
                                .iter()
                                .any(|l| l.kind == kind && l.rule == rule.id);
                    if !named {
                        missing.push(format!("{key} {} {pattern}", rule.id));
                    }
                }
            }
        }
        assert!(missing.is_empty(), "{}", missing.join("\n"));
    }
}
