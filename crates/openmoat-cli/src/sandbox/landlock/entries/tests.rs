use std::path::Path;

use openmoat_core::ir::Enforcement;
use openmoat_core::{DEFAULT_POLICY, EvalContext, Policy};

use super::*;
use crate::sandbox::bwrap::project_masks;

/// The default policy lowered for a session in `project`.
fn session_ir(project: &str) -> Enforcement {
    let ctx = EvalContext {
        home: "/nowhere/home".into(),
        project: Some(project.to_owned()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: project.to_owned(),
        case_insensitive_paths: false,
    };
    let policy = Policy::parse(DEFAULT_POLICY).expect("default policy");
    openmoat_core::ir::lower(&policy, &ctx).expect("lowers")
}

/// A project in `root` with the paths the policy denies at its top and below.
fn project(root: &Path) -> String {
    let p = root.join("proj");
    for dir in [
        ".git/hooks",
        ".moat",
        ".claude/commands",
        ".github/workflows",
        ".github/hooks",
        ".husky",
        "src",
        "sub",
    ] {
        std::fs::create_dir_all(p.join(dir)).unwrap();
    }
    for file in [
        ".env",
        ".env.example",
        ".git/hooks/pre-commit",
        ".moat/policy.yaml",
        ".moat/policy.lock",
        ".claude/settings.json",
        ".github/workflows/ci.yml",
        "src/main.rs",
        "sub/.env",
    ] {
        std::fs::write(p.join(file), "x").unwrap();
    }
    std::os::unix::fs::symlink("/etc", p.join("link")).unwrap();
    std::fs::create_dir_all(root.join("other")).unwrap();
    p.display().to_string()
}

fn rules_with(read: &[&str], write: &[&str]) -> Rules {
    let own = |l: &[&str]| l.iter().map(|s| (*s).to_owned()).collect();
    Rules {
        read: own(read),
        write: own(write),
        ..Rules::default()
    }
}

#[test]
fn the_project_is_granted_entry_by_entry_without_what_the_policy_denies() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let real = project(&root);
    let at = |rel: &str| format!("{real}/{rel}");
    let ir = session_ir(&real);
    let mut rules = rules_with(&[&real, "/usr"], &[&real]);
    let mut report = Report::default();
    split_project(&ir, &mut rules, &mut report, std::slice::from_ref(&real)).unwrap();

    assert!(
        !rules.read.contains(&real) && !rules.write.contains(&real),
        "{rules:?}"
    );
    assert!(rules.read.contains(&"/usr".to_owned()), "other grants stay");
    for listed in [real.clone(), at(".claude"), at(".github"), at(".moat")] {
        assert!(rules.list.contains(&listed), "{listed}: {rules:?}");
    }
    for readable in [".env.example", ".git", "src", "sub", ".moat/policy.yaml"] {
        assert!(rules.read.contains(&at(readable)), "{readable}: {rules:?}");
    }
    for writable in ["src", "sub", ".github/workflows", ".husky"] {
        assert!(rules.write.contains(&at(writable)), "{writable}: {rules:?}");
    }
    // Agent configuration a host runs later (ADR-091): readable, never writable.
    let config = at(".claude/commands");
    assert!(rules.read.contains(&config), "{rules:?}");
    assert!(!rules.write.contains(&config), "{rules:?}");
    // No rule at all: unreadable, and a link's target is decided where it points.
    for hidden in [".env", ".moat/policy.lock", "link"] {
        let path = at(hidden);
        assert!(
            !rules.read.contains(&path) && !rules.write.contains(&path),
            "{hidden}: {rules:?}"
        );
    }
    for read_only in [
        ".git",
        ".moat/policy.yaml",
        ".claude/settings.json",
        ".github/hooks",
    ] {
        assert!(
            !rules.write.contains(&at(read_only)),
            "{read_only}: {rules:?}"
        );
    }
    // Nothing grants the project itself or a holder for writing: nothing can
    // be created, renamed or removed directly in them.
    for holder in [real.clone(), at(".claude"), at(".github"), at(".moat")] {
        assert!(!rules.write.contains(&holder), "{holder}");
    }
    assert!(
        report.losses.iter().any(|l| l.rule == ENTRIES_LOSS),
        "{report:?}"
    );

    // What lies deeper in a granted entry stays open, and is named.
    let masks = project_masks(&ir, std::slice::from_ref(&real)).unwrap();
    let open = open(&masks.mounts, &rules);
    assert!(open.contains(&at("sub/.env")), "{open:?}");
    for covered in [".env", ".git", ".moat", ".envrc", ".claude/settings.json"] {
        assert!(!open.contains(&at(covered)), "{covered}: {open:?}");
    }
}

/// A read root that holds the project (`/tmp`) is granted around it: its
/// other entries as before, the folders on the way down for listing only.
#[test]
fn a_tree_holding_the_project_is_granted_around_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let real = project(&root);
    let root = root.display().to_string();
    let ir = session_ir(&real);
    let mut rules = rules_with(&[&root], &[&real]);
    let mut report = Report::default();
    split_project(&ir, &mut rules, &mut report, std::slice::from_ref(&real)).unwrap();
    assert!(!rules.read.contains(&root), "{rules:?}");
    assert!(rules.list.contains(&root), "{rules:?}");
    assert!(rules.read.contains(&format!("{root}/other")), "{rules:?}");
    assert!(!rules.write.contains(&format!("{root}/other")), "{rules:?}");
    assert!(!rules.read.contains(&format!("{real}/.env")), "{rules:?}");
    assert!(rules.read.contains(&format!("{real}/src")), "{rules:?}");
}

#[test]
fn a_project_no_rule_grants_is_left_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let real = project(&root);
    let ir = session_ir(&real);
    let mut rules = rules_with(&["/usr"], &["/dev/null"]);
    let before = rules.clone();
    let mut report = Report::default();
    split_project(&ir, &mut rules, &mut report, std::slice::from_ref(&real)).unwrap();
    assert_eq!(rules, before);
    assert_eq!(report.losses.len(), 0, "{report:?}");
}

#[test]
fn open_names_masks_a_rule_still_covers() {
    let rules = rules_with(&["/p/sub"], &["/p/src", "/p/.claude/commands"]);
    let masks = [
        Mount::Hide {
            path: "/p/sub/.env".into(),
            dir: false,
        },
        Mount::Hide {
            path: "/p/.env".into(),
            dir: false,
        },
        Mount::ReadOnly("/p/src/.git".into()),
        Mount::ReadOnly("/p/.git".into()),
        Mount::ReadWrite("/p/src/.claude".into()),
        Mount::ReadWrite("/p/.claude".into()),
    ];
    assert_eq!(
        open(&masks, &rules),
        ["/p/sub/.env", "/p/src/.git", "/p/src/.claude"]
    );
}

/// A read root that reaches the project's parent through a link (`~/go`
/// linked to `/data/go`, the project in `/data/go/src/app`) holds the project
/// as Landlock resolves it: it is granted around the project from where it
/// resolves, never whole, and its own spelling gets no rule.
#[test]
fn a_linked_tree_holding_the_project_is_compared_where_it_resolves() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let parent = root.join("data/go/src");
    std::fs::create_dir_all(parent.join("app/src")).unwrap();
    std::fs::create_dir_all(parent.join("other")).unwrap();
    std::fs::write(parent.join("app/top.txt"), "x").unwrap();
    std::os::unix::fs::symlink(root.join("data/go"), root.join("go")).unwrap();
    let link = root.join("go").display().to_string();
    let real = parent.join("app").display().to_string();
    let src = parent.display().to_string();
    assert_eq!(resolved(&format!("{link}/src")), src);
    let ir = session_ir(&real);
    let mut rules = rules_with(&[&link], &[&real]);
    let mut report = Report::default();
    split_project(&ir, &mut rules, &mut report, std::slice::from_ref(&real)).unwrap();
    assert!(
        !rules.read.contains(&link),
        "the link's whole grant is gone: {rules:?}"
    );
    let data = root.join("data/go").display().to_string();
    for listed in [&data, &src, &real] {
        assert!(rules.list.contains(listed), "{listed}: {rules:?}");
    }
    assert!(rules.read.contains(&format!("{src}/other")), "{rules:?}");
    assert!(rules.read.contains(&format!("{real}/top.txt")), "{rules:?}");
    assert!(!rules.read.contains(&real), "{rules:?}");
    // What stays open is judged from the resolved grants too.
    let masks = [Mount::Hide {
        path: format!("{src}/other/.env"),
        dir: false,
    }];
    let whole = rules_with(&[&link], &[]);
    assert_eq!(open(&masks, &whole), [format!("{src}/other/.env")]);
}
