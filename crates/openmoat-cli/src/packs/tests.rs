use std::path::Path;

use openmoat_core::{Action, CompiledPolicy, EvalContext, Verdict};

use super::*;

const USER: &str = "version: 1\ndefaults: { '*': defer }\n\
    deny:\n  - id: secrets\n    fs.read: ['~/.ssh/**']\n\
    allow:\n  - id: dev\n    shell: ['cargo *']\n";

const PACK: &str = "version: 1\n\
    deny:\n  - id: no-publish\n    shell: ['cargo publish*']\n\
    ask:\n  - id: careful\n    shell: ['cargo run*']\n\
    allow:\n  - id: make\n    shell: ['make *', 'cat ~/.ssh/id_rsa']\n";

fn decide(policy: &Policy, command: &str) -> (Verdict, Vec<String>) {
    let ctx = EvalContext {
        home: "/h".into(),
        project: Some("/p".into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: "/p".into(),
        case_insensitive_paths: false,
    };
    let d = CompiledPolicy::compile(policy, &ctx)
        .unwrap()
        .decide(&Action::Shell {
            command: command.into(),
        });
    (d.verdict, d.rules)
}

#[test]
fn a_pack_merges_under_its_prefix_and_never_past_a_deny() {
    let mut policy = Policy::parse(USER).unwrap();
    apply(&mut policy, "team", &parse(PACK).unwrap()).unwrap();
    assert_eq!(
        decide(&policy, "cargo publish"),
        (Verdict::Deny, vec!["pack:team:no-publish".into()])
    );
    assert_eq!(
        decide(&policy, "cargo run"),
        (Verdict::Ask, vec!["pack:team:careful".into()])
    );
    assert_eq!(
        decide(&policy, "make deploy"),
        (Verdict::Allow, vec!["pack:team:make".into()])
    );
    assert_eq!(decide(&policy, "cat ~/.ssh/id_rsa").0, Verdict::Deny);
}

#[test]
fn a_pack_with_anything_but_rules_is_refused() {
    for bad in [
        "version: 1\ndefaults: allow\n",
        "version: 1\nsandbox:\n  read_roots: ['/etc']\n",
        "version: 1\nrequire_signed_repo_policy: true\n",
        "version: 2\n",
    ] {
        assert!(parse(bad).is_err(), "{bad}");
    }
    for bad in ["", "Team", "a/b", "../x", "a.b"] {
        assert!(check_name(bad).is_err(), "{bad:?}");
    }
    check_name("team-rules_2").unwrap();
}

/// A state directory with `PACK` installed as `team`, its record pinned
/// when `pinned`.
fn installed(dir: &Path, pinned: bool) -> Home {
    let home = Home::at(dir.join("state"));
    write_private(&pack_path(&home, "team"), PACK.as_bytes()).unwrap();
    let mut packs = Packs::default();
    packs.packs.insert(
        "team".into(),
        Installed {
            sha256: sha256_hex(PACK.as_bytes()),
            signer: "alice@x".into(),
            at_ms: 1,
        },
    );
    packs.save(&home.packs_path()).unwrap();
    let pins = if pinned {
        vec![home.packs_path(), pack_path(&home, "team")]
    } else {
        Vec::new()
    };
    Lock::pin(Path::new("/bin/moat"), &pins)
        .unwrap()
        .save(&home.lock_path())
        .unwrap();
    home
}

#[test]
fn only_a_pinned_record_of_unchanged_packs_is_merged() {
    let dir = tempfile::tempdir().unwrap();
    let home = installed(dir.path(), true);
    let mut policy = Policy::parse(USER).unwrap();
    merge_installed(&home, &mut policy).unwrap();
    assert!(policy.deny.iter().any(|g| g.id == "pack:team:no-publish"));
    assert_eq!(
        installed_files(&home),
        [pack_path(&home, "team"), sig_path(&home, "team")]
    );

    std::fs::write(pack_path(&home, "team"), "version: 1\n").unwrap();
    let error = merge_installed(&home, &mut Policy::parse(USER).unwrap()).unwrap_err();
    assert!(format!("{error:#}").contains("changed since"), "{error:#}");

    let other = tempfile::tempdir().unwrap();
    let planted = installed(other.path(), false);
    let mut policy = Policy::parse(USER).unwrap();
    merge_installed(&planted, &mut policy).unwrap();
    assert_eq!(policy, Policy::parse(USER).unwrap(), "an unpinned record");
}
