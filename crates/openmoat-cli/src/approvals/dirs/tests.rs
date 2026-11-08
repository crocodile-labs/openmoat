use openmoat_core::{Action, CompiledPolicy, DEFAULT_POLICY, EvalContext, Verdict};

use super::*;
use crate::approvals::Overlay;

const DIR: &str = "/w/shared";
const HOME: &str = "/h";

fn default_policy() -> Policy {
    Policy::parse(DEFAULT_POLICY).unwrap()
}

fn places() -> Places {
    Places {
        homes: vec![HOME.to_owned()],
        moved: Vec::new(),
    }
}

fn grant(dir: &str) -> DirGrant {
    DirGrant {
        id: "approved-1".to_owned(),
        reason: Some("approved with `openmoat allow --dir` on 2026-11-07 10:00".to_owned()),
        dir: vec![dir.to_owned()],
        except: Vec::new(),
    }
}

/// `policy` with `rules` appended to its allow list, decided for a project
/// elsewhere, as the hook decides after merging the overlay.
fn verdict(policy: &Policy, rules: &[RuleGroup], action: &Action) -> Verdict {
    let mut merged = policy.clone();
    merged.allow.extend(rules.iter().cloned());
    let ctx = EvalContext {
        home: HOME.to_owned(),
        project: Some("/p".to_owned()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".to_owned(),
        case_insensitive_paths: false,
    };
    CompiledPolicy::compile(&merged, &ctx)
        .unwrap()
        .decide(action)
        .verdict
}

fn write(path: &str) -> Action {
    Action::FsWrite {
        path: path.to_owned(),
    }
}

#[test]
fn a_grant_leaves_out_what_the_policy_holds_for_review_in_it() {
    let found = exclusions(&default_policy(), &[DIR.to_owned()], &places());
    for left_out in [
        "/w/shared/.git/**",
        "/w/shared/**/.git/**",
        "/w/shared/**/.github/workflows/**",
        "/w/shared/**/.vscode/**",
        "/w/shared/**/.idea/**",
        "/w/shared/**/*.code-workspace",
        "/w/shared/**/.npmrc",
        "/w/shared/**/.cargo/config.toml",
        "/w/shared/**/.venv/bin/**",
        "/w/shared/**/.devcontainer/**",
    ] {
        assert!(found.iter().any(|p| p == left_out), "{left_out}: {found:?}");
    }
    // a folder whose contents are left out is left out with them
    assert!(
        !found.iter().any(|p| p == "/w/shared/**/.vscode"),
        "{found:?}"
    );
    assert!(!found.iter().any(|p| p == "/w/shared/.git"), "{found:?}");
    // fixed paths elsewhere name nothing in the directory
    assert!(!found.iter().any(|p| p.starts_with('~')), "{found:?}");
}

/// Fixed paths (`persistence`, `runs-later`'s home files) where the grant is
/// among them, through `~` and through a moved agent directory.
#[test]
fn fixed_paths_in_the_directory_are_left_out_too() {
    let policy = default_policy();
    let config = exclusions(&policy, &["/h/.config".to_owned()], &places());
    for left_out in ["~/.config/git/**", "~/.config/opencode/plugins/**"] {
        assert!(
            config.iter().any(|p| p == left_out),
            "{left_out}: {config:?}"
        );
    }
    assert!(!config.iter().any(|p| p == "~/.local/bin/**"), "{config:?}");
    let moved = Places {
        moved: vec![("~/.claude".to_owned(), "/srv/claude".to_owned())],
        ..places()
    };
    let claude = exclusions(&policy, &["/srv/claude".to_owned()], &moved);
    assert!(
        claude.iter().any(|p| p == "~/.claude/plugins/**"),
        "{claude:?}"
    );
    // a pattern reaching into the directory from above it
    let usr = exclusions(&policy, &["/usr/local/bin/tools".to_owned()], &places());
    assert!(usr.iter().any(|p| p == "/usr/local/bin/**"), "{usr:?}");
}

#[test]
fn a_dir_grant_never_answers_a_review_or_a_deny() {
    let policy = default_policy();
    let rule = grant(DIR).rule(&policy, &places());
    let rules = [rule];
    assert_eq!(
        verdict(&policy, &rules, &write("/w/shared/notes.md")),
        Verdict::Allow
    );
    for held in [
        "/w/shared/.vscode/settings.json",
        "/w/shared/app/.idea/workspace.xml",
        "/w/shared/.npmrc",
        "/w/shared/.github/workflows/ci.yml",
    ] {
        assert_eq!(
            verdict(&policy, &rules, &write(held)),
            Verdict::Review,
            "{held}"
        );
    }
    // `git-internals` names the project's `.git`; one here is left to the
    // policy's default, as without the grant
    let hook = write("/w/shared/.git/hooks/pre-commit");
    assert_eq!(
        verdict(&policy, &rules, &hook),
        verdict(&policy, &[], &hook)
    );
    assert_ne!(verdict(&policy, &rules, &hook), Verdict::Allow);
    let key = Action::FsRead {
        path: "/w/shared/.env".to_owned(),
    };
    assert_eq!(verdict(&policy, &rules, &key), Verdict::Deny);
}

/// A protection a later policy adds holds in a grant made before it.
#[test]
fn a_protection_added_later_holds_in_an_earlier_grant() {
    let mut policy = default_policy();
    let stored = grant(DIR);
    let later = "**/.newtool/**";
    let path = "/w/shared/.newtool/run.sh";
    assert_eq!(
        verdict(&policy, &[stored.rule(&policy, &places())], &write(path)),
        Verdict::Allow
    );
    let runs_later = policy.review.iter_mut().find(|g| g.id == "runs-later");
    runs_later.unwrap().fs_write.push(later.to_owned());
    assert_eq!(
        verdict(&policy, &[stored.rule(&policy, &places())], &write(path)),
        Verdict::Review
    );
}

/// A grant of one exact path (`openmoat allow --last --always`) still answers
/// the review it was approved for (ADR-007).
#[test]
fn an_exact_path_grant_still_answers_its_review() {
    let policy = default_policy();
    let settings = "/w/shared/.vscode/settings.json";
    let mut overlay = Overlay::default();
    let exact = overlay
        .allow_files(&[], &[settings.to_owned()])
        .unwrap()
        .clone();
    assert_eq!(verdict(&policy, &[], &write(settings)), Verdict::Review);
    assert_eq!(verdict(&policy, &[exact], &write(settings)), Verdict::Allow);
}

/// What earlier releases wrote for `--dir`: the `.git` and `runs-later` paths
/// of the day, `**/.vscode/tasks.json` among them, copied in.
fn old_rule(extra: &[&str]) -> RuleGroup {
    let mut fs_write = vec![DIR.to_owned(), format!("{DIR}/**")];
    fs_write.extend(
        [
            ".git/**",
            "**/.git/**",
            "**/.github/workflows/**",
            "**/.vscode/tasks.json",
        ]
        .iter()
        .chain(extra)
        .map(|p| format!("!{DIR}/{p}")),
    );
    RuleGroup {
        id: "approved-1".to_owned(),
        reason: Some("approved with `moat allow --dir` on 2026-10-15 09:12".to_owned()),
        fs_read: vec![DIR.to_owned(), format!("{DIR}/**")],
        fs_write,
        ..RuleGroup::default()
    }
}

#[test]
fn an_old_dir_rule_becomes_a_grant_that_never_allows_more() {
    let policy = default_policy();
    let old = old_rule(&[]);
    let made = DirGrant::from_rule(&old, &policy, &places()).unwrap();
    assert_eq!(made.id, "approved-1");
    assert_eq!(made.reason, old.reason);
    assert_eq!(made.dir, [DIR]);
    assert!(made.except.is_empty(), "{made:?}");
    let (tasks, settings) = (
        write("/w/shared/.vscode/tasks.json"),
        write("/w/shared/.vscode/settings.json"),
    );
    let old = [old];
    assert_eq!(verdict(&policy, &old, &tasks), Verdict::Review);
    assert_eq!(
        verdict(&policy, &old, &settings),
        Verdict::Allow,
        "the snapshot of its day misses what the policy added since"
    );
    // what the snapshot left out is still left out, and what it missed is now
    let rules = [made.rule(&policy, &places())];
    for held in [&tasks, &settings] {
        assert_eq!(verdict(&policy, &rules, held), Verdict::Review, "{held:?}");
    }

    // one the policy no longer names stays left out
    let dropped = old_rule(&["**/.oldtool/**"]);
    let made = DirGrant::from_rule(&dropped, &policy, &places()).unwrap();
    assert_eq!(made.except, ["/w/shared/**/.oldtool/**"]);
    let rules = [made.rule(&policy, &places())];
    assert_ne!(
        verdict(&policy, &rules, &write("/w/shared/.oldtool/x")),
        Verdict::Allow
    );

    // the first `--dir` left nothing out
    let first = RuleGroup {
        fs_write: vec![DIR.to_owned(), format!("{DIR}/**")],
        ..old_rule(&[])
    };
    assert!(is_old_rule(&first));
}

#[test]
fn only_a_rule_of_the_old_shape_is_taken_for_a_grant() {
    let mut rules = vec![
        // written by hand: no `--dir` reason
        RuleGroup {
            reason: Some("my build folder".to_owned()),
            ..old_rule(&[])
        },
        // a person added to it
        RuleGroup {
            shell: vec!["make".to_owned()],
            ..old_rule(&[])
        },
        // an exclusion outside the directory
        RuleGroup {
            fs_write: [old_rule(&[]).fs_write, vec!["!/elsewhere/**".to_owned()]].concat(),
            ..old_rule(&[])
        },
        // reads only
        RuleGroup {
            fs_write: Vec::new(),
            ..old_rule(&[])
        },
    ];
    let mut files = Overlay::default();
    rules.push(
        files
            .allow_files(&[], &[format!("{DIR}/a")])
            .unwrap()
            .clone(),
    );
    for rule in &rules {
        assert!(!is_old_rule(rule), "{rule:?}");
    }

    let mut overlay = Overlay {
        allow: [
            rules.clone(),
            vec![RuleGroup {
                id: "approved-9".to_owned(),
                ..old_rule(&[])
            }],
        ]
        .concat(),
        ..Overlay::default()
    };
    let made = overlay.migrate_dirs(&default_policy(), &places());
    assert_eq!(made.len(), 1);
    assert_eq!(overlay.dirs[0].id, "approved-9");
    assert_eq!(overlay.allow, rules, "every other rule is left as it was");
    assert!(overlay.old_dir_rules().next().is_none());
    assert_eq!(overlay.allow_dir(&["/w/b".to_owned()]).id, "approved-10");
}
