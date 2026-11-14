//! Codex's permissions profile against the IR's reference semantics
//! (`sandbox/differential.rs`), read the way Codex documents it (`codex.rs`
//! says what the generator relies on): every sampled path the checker denies
//! must be denied there too or named by the report. The reading models only
//! what the file says: Codex's `:minimal`, which Codex adds itself, grants
//! nothing here, so a path the checker allows there may read as narrower,
//! which needs a loss.

use openmoat_core::Kind;
use openmoat_core::ir::Effect;

use crate::sandbox::PROJECT as HOST_PROJECT;
use crate::sandbox::differential::{
    HOME, allowance_matches, host_ir, policies, samples_in, under, unreported,
};
use crate::sandbox::patterns::has_glob;

/// A Codex profile as Codex reads it: a deny entry or deny glob that matches
/// wins over every grant, and otherwise the longest path entry holding the
/// path decides (`read` reads, `write` reads and writes). `:workspace_roots`
/// entries are relative to the project; `.git` there stays read-only.
fn codex_effect(profile: &toml_edit::Table, kind: Kind, path: &str) -> Effect {
    let fs = profile["filesystem"]
        .as_table()
        .expect("a filesystem table");
    let mut entries: Vec<(String, &str)> = Vec::new();
    for (key, item) in fs {
        if let Some(mode) = item.as_str() {
            entries.push((key.to_owned(), mode));
        }
    }
    if let Some(roots) = fs.get(":workspace_roots").and_then(|i| i.as_table()) {
        for (key, item) in roots {
            let key = match key {
                "." => HOST_PROJECT.to_owned(),
                rest => format!("{HOST_PROJECT}/{rest}"),
            };
            entries.push((key, item.as_str().unwrap_or("deny")));
        }
    }
    let holds = |key: &str| {
        if key.starts_with(':') {
            return false;
        }
        if has_glob(key) {
            return allowance_matches(key, path);
        }
        under(path, key)
    };
    if entries.iter().any(|(k, m)| *m == "deny" && holds(k)) {
        return Effect::Deny;
    }
    if kind == Kind::FsWrite && under(path, &format!("{HOST_PROJECT}/.git")) {
        return Effect::Deny;
    }
    let decided = entries
        .iter()
        .filter(|(k, _)| !has_glob(k) && holds(k))
        .max_by_key(|(k, _)| k.len())
        .map(|(_, m)| *m);
    match (decided, kind) {
        (Some("write"), _) | (Some("read"), Kind::FsRead) => Effect::Allow,
        _ => Effect::Deny,
    }
}

#[test]
fn codex_profiles_deny_every_sampled_path_the_checker_denies_or_report_it() {
    for yaml in policies() {
        let ir = host_ir(yaml);
        let generated = super::super::generate(&ir, &[HOME.to_owned()], None).expect("generates");
        let checker = ir.checker().expect("compiles");
        let wrong = unreported(
            &checker,
            &generated.report,
            &samples_in(&ir, HOST_PROJECT),
            false,
            |kind, path| codex_effect(&generated.profile, kind, path),
        );
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}
