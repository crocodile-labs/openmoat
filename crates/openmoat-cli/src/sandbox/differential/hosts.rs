//! The same differential for the outputs a host applies itself, and for the
//! masks `moat run` adds inside its grants: Codex's permissions profile,
//! Cursor's `sandbox.json` and [`bwrap::grant_masks`]. Each output is read
//! the way its host documents it (`codex.rs`, `cursor.rs`, `bwrap.rs` say
//! what each generator relies on), and every sampled path the checker denies
//! must be denied there too or named by the backend's report.
//!
//! The readings model only what the files say: Codex's `:minimal` and
//! Cursor's system paths, which the hosts add themselves, grant nothing here,
//! so a path the checker allows there may read as narrower, which needs a loss.

use openmoat_core::ir::{Effect, Enforcement};
use openmoat_core::{Kind, Policy};

use super::super::patterns::{has_glob, is_below};
use super::super::{Grants, PROJECT as HOST_PROJECT, Report, bwrap, codex, cursor, landlock};
use super::{GLOBS, HOME, READ_ALL, allowance_matches, policies, samples_in, unreported};

/// The policies lowered as for the hosts: the project is the placeholder each
/// host maps to its workspace.
fn host_ir(yaml: &str) -> Enforcement {
    let policy = Policy::parse(yaml).expect("test policy lints");
    super::super::lower_for_hosts(&policy, HOME, None, Vec::new(), false).expect("lowers")
}

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

fn under(path: &str, root: &str) -> bool {
    root == "/" || path == root || is_below(path, root)
}

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
        let generated = codex::generate(&ir, &[HOME.to_owned()], None).expect("generates");
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
        let generated = cursor::generate(&ir, None).expect("generates");
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

/// Each sample below `root`, made on disk: a directory where another sample
/// lies below it, else a file. `grant_masks` masks only what exists; a sample
/// that cannot be made (a sandbox around the test may refuse `.git` or an
/// agent's folder) stays missing, which the comparison covers as well: a
/// missing path is not masked, so the backend's report must name it.
fn plant(root: &str, paths: &[String]) {
    for path in paths.iter().filter(|p| is_below(p, root)) {
        let dir = paths.iter().any(|other| is_below(other, path));
        if dir {
            let _ = std::fs::create_dir_all(path);
        } else if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent).and_then(|()| std::fs::write(path, ""));
        }
    }
}

/// The view `moat run` gives with the network namespace: Landlock's rules,
/// then `masks` over them (the last mount holding a path decides). A path
/// bound onto itself read-write is a mount point: what is below it stays
/// writable, but the path itself cannot be removed, renamed or replaced.
fn masked_effect(
    rules: &landlock::Rules,
    masks: &[bwrap::Mount],
    kind: Kind,
    path: &str,
) -> Effect {
    let below = |list: &[String]| list.iter().any(|g| under(path, g));
    let granted = match kind {
        Kind::FsWrite => below(&rules.write),
        _ => below(&rules.read) || below(&rules.write),
    };
    let mask = masks.iter().rev().find(|m| {
        let p = match m {
            bwrap::Mount::ReadOnly(p) | bwrap::Mount::ReadWrite(p) | bwrap::Mount::Tmpfs(p) => p,
            bwrap::Mount::Hide { path, .. } => path,
        };
        under(path, p)
    });
    let allowed = granted
        && match mask {
            Some(bwrap::Mount::Hide { .. }) => false,
            Some(bwrap::Mount::ReadOnly(_)) => kind == Kind::FsRead,
            Some(bwrap::Mount::ReadWrite(p)) => kind == Kind::FsRead || p != path,
            _ => true,
        };
    if allowed { Effect::Allow } else { Effect::Deny }
}

/// With the masks, every sampled path a deny rule names without a glob inside
/// a grant is denied, not only reported, and nothing the checker allows is
/// masked away unreported.
#[test]
fn grant_masks_deny_inside_grants_what_the_checker_denies() {
    for yaml in [GLOBS, READ_ALL, openmoat_core::DEFAULT_POLICY] {
        let dir = tempfile::tempdir().expect("a temp dir");
        let root = std::fs::canonicalize(dir.path()).expect("resolves");
        let root = crate::context::path_string(&root);
        let home = format!("{root}/home/me");
        let project = format!("{home}/proj");
        let policy = Policy::parse(yaml).expect("test policy lints");
        let ctx = openmoat_core::EvalContext {
            home: home.clone(),
            project: Some(project.clone()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: project.clone(),
            case_insensitive_paths: false,
        };
        let ir = openmoat_core::ir::lower(&policy, &ctx).expect("lowers");
        let paths: Vec<String> = samples_in(&ir, &project)
            .into_iter()
            .filter(|p| is_below(p, &root))
            .collect();
        plant(&root, &paths);
        let grants = Grants {
            proxy_port: Some(18080),
            tmpdir: Some(format!("{root}/tmp/session")),
            program: None,
            writes: vec![format!("{home}/.config")],
            terminals: Vec::new(),
            trust: None,
            tool_shell: None,
        };
        let generated = landlock::generate(&ir, &grants).expect("generates");
        let masks =
            bwrap::grant_masks(&ir, &generated.rules, std::slice::from_ref(&project)).unwrap();
        let checker = ir.checker().expect("compiles");
        let effect = |kind, path: &str| masked_effect(&generated.rules, &masks, kind, path);
        let wrong = unreported(&checker, &generated.report, &paths, true, effect);
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        let mut open = Vec::new();
        for (path, kind) in denied_literals_outside(&ir, &project) {
            let exists = std::fs::symlink_metadata(&path).is_ok();
            let atom = super::atom(kind, &path);
            if exists
                && checker.check_os(&atom) == Some(Effect::Deny)
                && effect(kind, &path) == Effect::Allow
            {
                open.push(format!("{kind:?} {path}"));
            }
        }
        assert!(
            open.is_empty(),
            "left open inside a grant: {}",
            open.join(", ")
        );
    }
}

/// The literal paths `ir`'s deny rules name outside `project`, each with the
/// access it denies: the ones `grant_masks` covers.
fn denied_literals_outside(ir: &Enforcement, project: &str) -> Vec<(String, Kind)> {
    let mut out = Vec::new();
    for (access, kind) in [(&ir.fs.read, Kind::FsRead), (&ir.fs.write, Kind::FsWrite)] {
        for rule in &access.deny {
            for pattern in super::super::patterns::split(&rule.patterns).0 {
                let path = pattern.strip_suffix("/**").unwrap_or(pattern);
                if path.starts_with('/') && !has_glob(path) && !under(path, project) {
                    out.push((path.to_owned(), kind));
                }
            }
        }
    }
    out
}
