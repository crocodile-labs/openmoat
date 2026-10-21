use std::path::Path;

use openmoat_core::{DEFAULT_POLICY, EvalContext, Policy};

use super::*;

fn generated(home: &Path) -> Generated {
    let home = home.to_string_lossy().into_owned();
    let project = format!("{home}/proj");
    let ctx = EvalContext {
        home: home.clone(),
        project: Some(project.clone()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: project.clone(),
        case_insensitive_paths: false,
    };
    let grants = Grants {
        proxy_port: Some(18080),
        // The home is in the temp directory, which the session gets empty.
        tmpdir: Path::new(&home)
            .parent()
            .map(|t| t.to_string_lossy().into_owned()),
        program: Some("/usr/bin/agent".into()),
        writes: vec![format!("{home}/.claude"), format!("{home}/.cargo")],
    };
    let mut policy = Policy::parse(DEFAULT_POLICY).expect("default policy");
    // No read roots: the temp directory holding the test home is one.
    policy.sandbox = None;
    let ir = openmoat_core::ir::lower(&policy, &ctx).expect("lowers");
    generate(&ir, &grants, &[project]).expect("generates")
}

fn tree(home: &Path) {
    for dir in [
        "proj/src",
        "proj/.env.d",
        "proj/.git/hooks",
        "proj/vendor/lib/.git/hooks",
        "proj/sub",
        "proj/.claude/worktrees",
        ".claude",
        ".cargo",
    ] {
        std::fs::create_dir_all(home.join(dir)).unwrap();
    }
    for file in [
        "proj/.env",
        "proj/.env.example",
        "proj/src/.env.local",
        "proj/src/main.rs",
        "proj/sub/.git",
        "proj/.env.d/inner",
        "proj/.claude/settings.json",
        ".claude/settings.json",
        ".cargo/credentials.toml",
    ] {
        std::fs::write(home.join(file), "x").unwrap();
    }
}

#[test]
fn denied_paths_in_the_project_and_the_grants_are_masked() {
    let dir = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(dir.path()).unwrap();
    tree(&home);
    let out = generated(&home);
    let p = |rel: &str| format!("{}/{rel}", home.display());
    let hide = |rel: &str| Mount::Hide {
        path: p(rel),
        dir: false,
    };
    for expected in [
        hide("proj/.env"),
        hide("proj/src/.env.local"),
        Mount::Hide {
            path: p("proj/.env.d"),
            dir: true,
        },
        hide("proj/.envrc"),
        hide("proj/.moat"),
        Mount::ReadOnly(p("proj/.git")),
        // a nested repository's `.git`, directory or `gitdir:` file, is git's too
        Mount::ReadOnly(p("proj/vendor/lib/.git")),
        Mount::ReadOnly(p("proj/sub/.git")),
        Mount::ReadOnly(p("proj/.claude/settings.json")),
        // The node is pinned; Claude Code may still write its worktrees.
        Mount::ReadWrite(p("proj/.claude")),
        Mount::ReadWrite(p(".claude")),
        Mount::ReadOnly(p(".claude/settings.json")),
        hide(".cargo/credentials.toml"),
    ] {
        assert!(
            out.mounts.contains(&expected),
            "{expected:?}: {:#?}",
            out.mounts
        );
    }
    assert!(!out.mounts.contains(&hide("proj/.env.example")));
    assert!(
        !out.mounts.contains(&hide("proj/.env.d/inner")),
        "a hidden directory is not entered"
    );
    assert!(
        !out.mounts
            .contains(&Mount::ReadOnly(p("proj/.claude/worktrees")))
    );
    assert_eq!(out.placeholders, vec![p("proj/.envrc"), p("proj/.moat")]);
    // Trees first, outermost first; the home itself is never mounted.
    let first_mask = out
        .mounts
        .iter()
        .position(|m| matches!(m, Mount::Hide { .. }));
    let project = out
        .mounts
        .iter()
        .position(|m| m == &Mount::ReadWrite(p("proj")));
    assert!(
        project.is_some() && project < first_mask,
        "{:#?}",
        out.mounts
    );
    assert!(out.rules.write.contains(&p("proj")), "{:?}", out.rules);
    let tmp = home.parent().unwrap().to_string_lossy().into_owned();
    assert!(
        out.mounts.contains(&Mount::Tmpfs(tmp.clone())),
        "{:#?}",
        out.mounts
    );
    assert!(!out.mounts.contains(&Mount::ReadOnly(tmp)));
    let home_path = home.to_string_lossy().into_owned();
    assert!(!out.mounts.iter().any(|m| path_of(m) == home_path));
    let rules = out
        .report
        .allowances
        .iter()
        .map(|a| a.rule.as_str())
        .collect::<Vec<_>>();
    assert!(rules.contains(&"bwrap.created-later"), "{rules:?}");
    assert!(!rules.contains(&"landlock.inside-grants") && !rules.contains(&"landlock.tcp-port"));
}

#[test]
fn masks_repeat_under_every_spelling_of_the_project() {
    let mut masks = vec![
        Mount::Hide {
            path: "/real/p/.env".into(),
            dir: false,
        },
        Mount::ReadOnly("/real/p/.git/hooks".into()),
    ];
    let all = respelled(&masks, &["/real/p".into(), "/link/p".into()]);
    masks.extend([
        Mount::Hide {
            path: "/link/p/.env".into(),
            dir: false,
        },
        Mount::ReadOnly("/link/p/.git/hooks".into()),
    ]);
    assert_eq!(all, masks);
}

#[test]
fn args_bind_the_placeholders_over_hidden_paths() {
    let mounts = [
        Mount::ReadOnly("/usr".into()),
        Mount::ReadWrite("/p".into()),
        Mount::Tmpfs("/tmp".into()),
        Mount::Hide {
            path: "/p/.env".into(),
            dir: false,
        },
        Mount::Hide {
            path: "/p/secrets".into(),
            dir: true,
        },
    ];
    let args = args(&mounts, "/b/file", "/b/dir").join(" ");
    assert_eq!(
        args,
        "--ro-bind-try /usr /usr --bind-try /p /p --tmpfs /tmp --ro-bind /b/file /p/.env \
         --ro-bind /b/dir /p/secrets"
    );
}

/// `moat run`'s network namespace binds the whole root, where Landlock alone
/// cannot deny inside a grant: `--write ~/.agent` left the agent's denied
/// `settings.json` writable, and a read root `~/.tools` its denied token
/// readable, to every command.
#[test]
fn the_network_namespace_masks_denied_paths_inside_its_grants() {
    let dir = tempfile::tempdir().unwrap();
    let home = std::fs::canonicalize(dir.path()).unwrap();
    let p = |rel: &str| format!("{}/{rel}", home.display());
    for d in ["proj", ".agent", ".tools"] {
        std::fs::create_dir_all(p(d)).unwrap();
    }
    for f in ["proj/token", ".agent/settings.json", ".tools/token"] {
        std::fs::write(p(f), "x").unwrap();
    }
    let ctx = EvalContext {
        home: home.to_string_lossy().into_owned(),
        project: Some(p("proj")),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: p("proj"),
        case_insensitive_paths: false,
    };
    let policy = Policy::parse(
        r#"
version: 1
defaults: { "*": deny }
deny:
  - id: own
    fs.read: ["~/.tools/token", "${project}/token"]
    fs.write: ["~/.agent", "~/.agent/settings.json"]
allow:
  - id: work
    fs.write: ["${project}/**"]
"#,
    )
    .expect("test policy");
    let ir = openmoat_core::ir::lower(&policy, &ctx).expect("lowers");
    let rules = Rules {
        read: vec![p(".tools"), "/dev/null".into()],
        write: vec![p("proj"), p(".agent")],
        connect_port: Some(18080),
    };
    let masks = grant_masks(&ir, &rules, &[p("proj")]);
    assert_eq!(
        masks,
        [
            // outermost first: the directory node pinned before the file
            // inside it is made read-only
            Mount::ReadWrite(p(".agent")),
            Mount::Hide {
                path: p(".tools/token"),
                dir: false,
            },
            Mount::ReadOnly(p(".agent/settings.json")),
        ],
        "the project stays the hook's and Landlock's, as without a namespace"
    );
}
