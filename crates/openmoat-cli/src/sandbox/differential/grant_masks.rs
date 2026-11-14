//! The same differential for the masks `moat run` adds inside its grants
//! ([`bwrap::grant_masks`]), read the way `bwrap.rs` says bubblewrap applies
//! them: every sampled path the checker denies must be denied there too or
//! named by the report. The host sandboxes' own differentials are with their
//! backends' tests.

use openmoat_core::ir::{Effect, Enforcement};
use openmoat_core::{Kind, Policy};

use super::super::patterns::{has_glob, is_below};
use super::super::{Grants, bwrap, landlock};
use super::{GLOBS, READ_ALL, samples_in, under, unreported};

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
