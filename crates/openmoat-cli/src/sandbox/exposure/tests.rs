use openmoat_core::{DEFAULT_POLICY, EvalContext, Policy};

use super::*;
use crate::sandbox::{Grants, landlock};

fn shown(path: &str) -> Grant {
    Grant {
        path: path.to_owned(),
        shown: true,
    }
}

fn empty(path: &str) -> Grant {
    Grant {
        path: path.to_owned(),
        shown: false,
    }
}

#[test]
fn within_ignores_trailing_slashes_and_needs_whole_components() {
    assert!(within("/tmp/x/.moat", "/tmp", false));
    assert!(within("/tmp/x/.moat/", "/tmp/", false));
    assert!(within("/tmp", "/tmp/", false));
    assert!(within("/tmp/", "/tmp", false));
    assert!(within("/anything", "/", false));
    assert!(within("/", "/", false));
    assert!(!within("/tmpfoo/.moat", "/tmp", false));
    assert!(!within("/tmp", "/tmp/x", false));
    assert!(!within("/", "/tmp", false));
}

#[test]
fn within_follows_the_file_systems_case() {
    assert!(
        !within("/Proj/.moat", "/proj", false),
        "Linux: a different path"
    );
    assert!(
        within("/Proj/.moat", "/proj", true),
        "macOS, Windows: the same"
    );
    assert!(within("/proj/STATE", "/PROJ/", true));
}

#[test]
fn a_tree_holding_the_state_directory_exposes_it() {
    let grants = [shown("/usr"), shown("/tmp"), shown("/home/me/proj")];
    assert_eq!(
        exposing("/tmp/ci/.moat", &grants, false),
        Some(Exposure::Inside("/tmp".into()))
    );
    assert_eq!(
        exposing("/home/me/proj/state/", &grants, false),
        Some(Exposure::Inside("/home/me/proj".into()))
    );
    assert_eq!(exposing("/home/me/.moat", &grants, false), None);
    assert_eq!(exposing("/home/me/projects/.moat", &grants, false), None);
}

#[test]
fn a_grant_inside_the_state_directory_exposes_it() {
    let grants = [shown("/usr"), shown("/home/me/.moat/mcp")];
    assert_eq!(
        exposing("/home/me/.moat", &grants, false),
        Some(Exposure::Holds("/home/me/.moat/mcp".into()))
    );
    let itself = [shown("/home/me/.moat/")];
    assert_eq!(
        exposing("/home/me/.moat", &itself, false),
        Some(Exposure::Inside("/home/me/.moat/".into()))
    );
}

#[test]
fn an_empty_tmpfs_hides_it_unless_something_is_bound_over_it() {
    // `--isolate`: the read root `/tmp` and the temp directory `/tmp` are one
    // `tmpfs`; a temp directory deeper than a shown read root hides it too.
    let same = [shown("/tmp"), empty("/tmp")];
    assert_eq!(exposing("/tmp/ci/.moat", &same, false), None);
    let deeper = [shown("/tmp"), empty("/tmp/user")];
    assert_eq!(exposing("/tmp/user/.moat", &deeper, false), None);
    assert_eq!(
        exposing("/tmp/other/.moat", &deeper, false),
        Some(Exposure::Inside("/tmp".into()))
    );
    let bound = [empty("/tmp"), shown("/tmp/ci/.moat/mcp")];
    assert_eq!(
        exposing("/tmp/ci/.moat", &bound, false),
        Some(Exposure::Holds("/tmp/ci/.moat/mcp".into()))
    );
}

#[test]
fn grants_are_compared_with_their_symlinks_resolved() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir_all(real.join("state")).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let rules = Rules {
        read: vec![path_string(&link)],
        ..Rules::default()
    };
    // The state directory spelled through the link, the grant through the
    // target, or the other way round: one tree.
    let (state, exposure) = find(&link.join("state"), &rules, None).unwrap();
    let real = resolved(&real);
    assert_eq!(state, format!("{real}/state"));
    assert_eq!(exposure, Exposure::Inside(real.clone()));
    let rules = Rules {
        read: vec![real.clone()],
        ..Rules::default()
    };
    assert!(find(&link.join("state"), &rules, None).is_some());
    assert!(find(&dir.path().join("elsewhere"), &rules, None).is_none());
}

fn default_rules(moved_dirs: Vec<(String, String)>) -> Rules {
    let policy = Policy::parse(DEFAULT_POLICY).unwrap();
    let ctx = EvalContext {
        home: "/home/me".into(),
        project: Some("/home/me/proj".into()),
        real_home: None,
        real_project: None,
        moved_dirs,
        cwd: "/home/me/proj".into(),
        case_insensitive_paths: false,
    };
    let grants = Grants {
        proxy_port: Some(18080),
        tmpdir: Some("/tmp".into()),
        program: Some("/home/me/.local/bin/agent".into()),
        writes: Vec::new(),
        terminals: Vec::new(),
        trust: None,
    };
    let ir = openmoat_core::ir::lower(&policy, &ctx).unwrap();
    landlock::generate(&ir, &grants).unwrap().rules
}

/// The common case: `MOAT_HOME` unset is `~/.moat`, and no default read root
/// is the home directory or holds it, so a normal user's `moat run` starts.
#[test]
fn the_default_state_directory_is_outside_the_default_grants() {
    let rules = default_rules(Vec::new());
    let grants: Vec<Grant> = rules
        .read
        .iter()
        .chain(&rules.write)
        .map(|p| shown(p))
        .collect();
    assert_eq!(exposing("/home/me/.moat", &grants, false), None);
    // Moved into the project or the temp directory, it is exposed.
    let moved = |dir: &str| vec![("~/.moat".to_owned(), dir.to_owned())];
    for (dir, root) in [("/home/me/proj/state", "/home/me/proj"), ("/tmp/m", "/tmp")] {
        let rules = default_rules(moved(dir));
        let grants: Vec<Grant> = rules
            .read
            .iter()
            .chain(&rules.write)
            .map(|p| shown(p))
            .collect();
        assert_eq!(
            exposing(dir, &grants, false),
            Some(Exposure::Inside(root.into())),
            "{dir}"
        );
    }
    // Moved elsewhere, it is not.
    let rules = default_rules(moved("/srv/moat"));
    let grants: Vec<Grant> = rules
        .read
        .iter()
        .chain(&rules.write)
        .map(|p| shown(p))
        .collect();
    assert_eq!(exposing("/srv/moat", &grants, false), None);
}

#[test]
fn the_refusal_names_the_root_and_offers_isolate_only_where_it_hides() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = resolved(dir.path());
    let project = format!("{tmp}/proj");
    std::fs::create_dir_all(format!("{project}/state")).unwrap();
    let rules = Rules {
        read: vec!["/usr".into()],
        write: vec![tmp.clone(), project.clone()],
        connect_port: None,
    };
    let in_project = Path::new(&project).join("state");
    let message = refusal(&in_project, &rules, Some(&tmp), false).unwrap();
    assert!(
        message.contains(&format!("Move MOAT_HOME out of {project}")),
        "{message}"
    );
    assert!(!message.contains("--isolate"), "{message}");
    assert!(refusal(&in_project, &rules, Some(&tmp), true).is_some());
    // Directly in the temp directory: `--isolate` covers it with a `tmpfs`.
    let in_tmp = dir.path().join("moat");
    let message = refusal(&in_tmp, &rules, Some(&tmp), false).unwrap();
    assert!(
        message.contains(&format!("Move MOAT_HOME out of {tmp}")),
        "{message}"
    );
    assert!(message.contains("`openmoat run --isolate`"), "{message}");
    assert_eq!(refusal(&in_tmp, &rules, Some(&tmp), true), None);
    assert_eq!(
        refusal(Path::new("/nowhere/granted"), &rules, Some(&tmp), false),
        None
    );
}

fn home_ctx() -> EvalContext {
    EvalContext {
        home: "/home/me".into(),
        project: Some("/home/me/proj".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/home/me/proj".into(),
        case_insensitive_paths: false,
    }
}

/// Without a network namespace on Linux, a `--write` path that holds what
/// `kernel-self` protects (the documented `--write ~/.claude` holds Claude
/// Code's `settings.json`) refuses the run, naming the paths and both fixes.
#[test]
fn a_write_path_holding_kernel_self_paths_is_refused_without_a_namespace() {
    let policy = Policy::parse(DEFAULT_POLICY).unwrap();
    let held = |writes: &[&str]| {
        let writes: Vec<String> = writes.iter().map(|w| (*w).to_owned()).collect();
        crate::sandbox::kernel_self_in_writes(&policy, &home_ctx(), &writes).unwrap()
    };
    let claude = held(&["/home/me/.claude"]);
    let paths: Vec<&str> = claude.iter().map(|(_, p)| p.as_str()).collect();
    for expected in [
        "/home/me/.claude/settings.json",
        "/home/me/.claude/settings.local.json",
    ] {
        assert!(paths.contains(&expected), "{expected}: {claude:?}");
    }
    assert!(claude.iter().all(|(w, _)| w == "/home/me/.claude"));
    let why = "bubblewrap is not installed";
    let refusal = kernel_self_refusal(&claude, why).unwrap();
    for expected in [
        "`openmoat run --write /home/me/.claude`",
        "/home/me/.claude/settings.json",
        why,
        "refuses to start",
        "apt install bubblewrap",
        "unprivileged user namespaces",
        "paths inside the project",
    ] {
        assert!(refusal.contains(expected), "{expected}: {refusal}");
    }
    // The state directory, its audit log beside it whatever exists yet.
    let home = held(&["/home/me/.cache/agent", "/home/me"]);
    assert!(
        home.iter()
            .any(|(w, p)| w == "/home/me" && p == "/home/me/.moat/audit.db*"),
        "{home:?}"
    );
    // A path inside the project holds none: the hook decides there, and the
    // run starts with Landlock alone.
    for narrow in ["/home/me/proj", "/home/me/proj/target"] {
        assert_eq!(held(&[narrow]), Vec::new(), "{narrow}");
    }
    assert_eq!(kernel_self_refusal(&[], why), None);
}

/// A `**/` rule matches at any depth, so a write path outside the project
/// holds it: `--write ~/work` would open the other repositories' hook
/// settings there. A write path inside a tree `kernel-self` denies whole is
/// held too.
#[test]
fn nested_rules_and_denied_trees_hold_write_paths_outside_the_project() {
    let policy = Policy::parse(DEFAULT_POLICY).unwrap();
    let held = |write: &str| {
        crate::sandbox::kernel_self_in_writes(&policy, &home_ctx(), &[write.to_owned()]).unwrap()
    };
    let work = held("/home/me/work");
    for expected in [
        "/home/me/work/**/.claude/settings.json",
        "/home/me/work/**/.cursor/hooks.json",
        "/home/me/work/**/.moat/**",
    ] {
        assert!(
            work.iter()
                .any(|(w, p)| w == "/home/me/work" && p == expected),
            "{expected}: {work:?}"
        );
    }
    for (inside, tree) in [
        ("/home/me/.codex/sessions", "/home/me/.codex/**"),
        ("/home/me/.openclaw/state/x", "/home/me/.openclaw/state/**"),
        ("/home/me/.copilot/hooks/x", "/home/me/.copilot/hooks/**"),
    ] {
        let found = held(inside);
        assert!(
            found.iter().any(|(w, p)| w == inside && p == tree),
            "{inside}: {found:?}"
        );
    }
    // A denied node or file is no tree: what is below `~/.claude` is not
    // held by the rule for `~/.claude` itself.
    let projects = held("/home/me/.claude/projects");
    assert!(
        !projects.iter().any(|(_, p)| p == "/home/me/.claude"),
        "{projects:?}"
    );
}
