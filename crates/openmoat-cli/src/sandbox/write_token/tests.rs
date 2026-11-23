use openmoat_core::{DEFAULT_POLICY, EvalContext, Policy};

use super::*;

const PROJECT: &str = "C:/Users/me/proj";
const TEMP: &str = "C:/Users/me/AppData/Local/Temp/openmoat-run-0011";
const WRITE: &str = "C:/Users/me/.agent";

fn generated_with(yaml: &str, exists: &dyn Fn(&str) -> bool) -> anyhow::Result<Generated> {
    let policy = Policy::parse(yaml).expect("test policy lints");
    let ctx = EvalContext {
        home: "C:/Users/me".into(),
        project: Some(PROJECT.into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: PROJECT.into(),
        case_insensitive_paths: true,
    };
    let grants = Grants {
        proxy_port: Some(18080),
        tmpdir: Some(TEMP.into()),
        program: Some("C:/Users/me/bin/agent.exe".into()),
        writes: vec![WRITE.into()],
        terminals: Vec::new(),
        trust: None,
        tool_shell: None,
    };
    let ir = openmoat_core::ir::lower(&policy, &ctx).expect("lowers");
    generate(&ir, &grants, exists)
}

/// Everything the tests name exists, except `missing`.
fn generated(yaml: &str) -> Generated {
    generated_with(yaml, &|path| !path.contains("missing")).expect("generates")
}

fn entry<'a>(g: &'a Generated, path: &str, allows: bool) -> Option<&'a Entry> {
    g.plan
        .entries
        .iter()
        .find(|e| e.path == path && e.allows == allows)
}

fn allowance<'a>(g: &'a Generated, kind: Kind, rule: &str) -> Option<&'a [String]> {
    let found = g.report.allowances.iter();
    let mut found = found.filter(|a| a.kind == kind && a.rule == rule);
    found.next().map(|a| a.patterns.as_slice())
}

/// The default policy grants the project, the run's temp directory and the
/// `--write` path, each to its own SID, and nothing else: not the home, not
/// a drive.
#[test]
fn the_default_policy_grants_the_project_temp_and_write_paths_only() {
    let g = generated(DEFAULT_POLICY);
    let roots: Vec<&str> = g.plan.roots.iter().map(|(r, _)| r.as_str()).collect();
    assert_eq!(roots, [PROJECT, TEMP, WRITE]);
    for (root, sid) in &g.plan.roots {
        assert_eq!(sid, &root_sid(root));
        let grant = entry(&g, root, true).unwrap();
        assert_eq!((grant.mask, grant.inherit), (GRANT_MASK, true));
    }
    assert_eq!(g.plan.sids().len(), 3);
    assert!(g.plan.entries.iter().all(|e| e.path != "C:/Users/me"));
}

/// The project's `.git` and `.moat` are refused to the project's SID with a
/// deny on the place itself, inherited, and nothing on the project's top;
/// a deny below the top denies `DELETE` on the folders above it.
#[test]
fn the_projects_protected_places_get_deny_entries() {
    let g = generated(DEFAULT_POLICY);
    let sid = root_sid(PROJECT);
    for place in [".git", ".moat", ".vscode"] {
        let path = format!("{PROJECT}/{place}");
        let deny = entry(&g, &path, false).unwrap_or_else(|| panic!("{path}: {:?}", g.plan));
        assert_eq!((deny.mask, deny.inherit), (DENY_MASK, true), "{path}");
        assert_eq!(deny.sid, sid);
    }
    assert!(entry(&g, PROJECT, false).is_none(), "{:?}", g.plan);

    let yaml = format!(
        "{DEFAULT_POLICY}\n" // the default, plus one deny two folders down
    )
    .replace(
        "deny:\n",
        "deny:\n  - id: deep\n    fs.write: [\"${project}/a/b/c\"]\n",
    );
    let g = generated(&yaml);
    let deep = entry(&g, &format!("{PROJECT}/a/b/c"), false).unwrap();
    assert_eq!(deep.mask, DENY_MASK);
    for folder in ["a", "a/b"] {
        let above = entry(&g, &format!("{PROJECT}/{folder}"), false).unwrap();
        assert_eq!((above.mask, above.inherit), (DELETE, false), "{folder}");
    }
}

/// A glob no single place stands for, a `.git` below the top and a place
/// that does not exist yet are named as the hook's, as is every read deny
/// and the network.
#[test]
fn what_the_token_cannot_hold_is_named() {
    let yaml = DEFAULT_POLICY.replace(
        "deny:\n",
        "deny:\n  - id: later\n    fs.write: [\"${project}/missing-dir\"]\n",
    );
    let g = generated(&yaml);
    let unheld = allowance(&g, Kind::FsWrite, UNHELD).unwrap();
    for named in [
        format!("{PROJECT}/**/*.code-workspace"),
        format!("{PROJECT}/**/.git/**"),
        format!("{PROJECT}/missing-dir"),
    ] {
        assert!(unheld.contains(&named), "{named}: {unheld:?}");
    }
    assert!(entry(&g, &format!("{PROJECT}/missing-dir"), false).is_none());
    let reads = allowance(&g, Kind::FsRead, "windows.reads").unwrap();
    assert!(reads.iter().any(|r| r.contains(".ssh")), "{reads:?}");
    assert!(allowance(&g, Kind::Net, "windows.network").is_some());
}

/// A write root that does not exist is not granted, and said so.
#[test]
fn a_missing_write_root_is_a_loss() {
    let g = generated_with(DEFAULT_POLICY, &|path| path != WRITE).unwrap();
    assert!(g.plan.roots.iter().all(|(r, _)| r != WRITE));
    assert!(
        g.report.losses.iter().any(|l| l.message.contains(WRITE)),
        "{:?}",
        g.report.losses
    );
}

/// A policy that allows every write, or a whole drive as a write root, is
/// refused: the token would hold nothing.
#[test]
fn every_write_allowed_or_a_drive_is_refused() {
    let open = DEFAULT_POLICY.replacen("defaults:\n", "defaults:\n  fs.write: allow\n", 1);
    if Policy::parse(&open).is_ok() {
        let error = generated_with(&open, &|_| true).unwrap_err();
        assert!(
            format!("{error:#}").contains("allows every write"),
            "{error:#}"
        );
    }
    let drive = DEFAULT_POLICY.replace(
        "allow:\n  - id: project-fs\n",
        "allow:\n  - id: drive\n    fs.write: [\"D:/**\"]\n  - id: project-fs\n",
    );
    let error = generated_with(&drive, &|_| true).unwrap_err();
    assert!(format!("{error:#}").contains("whole drive"), "{error:#}");
}

/// A root's SID is stable across runs and letter case, differs per root,
/// and has the form of a domain SID, never a capability SID.
#[test]
fn root_sids_are_stable_per_folder() {
    let sid = root_sid(PROJECT);
    assert_eq!(sid, root_sid(&PROJECT.to_uppercase()));
    assert_ne!(sid, root_sid(WRITE));
    assert_ne!(sid, objects_sid());
    for sid in [sid, objects_sid()] {
        assert!(sid.starts_with("S-1-5-21-"), "{sid}");
        assert_eq!(sid.split('-').count(), 8, "{sid}");
    }
}

/// An entry already set on the place itself is not set again; an inherited
/// one, a narrower one or one without inheritance is.
#[test]
fn an_entry_already_there_is_not_set_again() {
    let wanted = Entry {
        path: PROJECT.into(),
        sid: root_sid(PROJECT),
        allows: true,
        mask: GRANT_MASK,
        inherit: true,
    };
    let ace = |flags: u8, mask: u32| RawAce {
        allows: true,
        flags,
        mask,
        sid: wanted.sid.to_lowercase(),
    };
    assert!(needs_change(&[], &wanted));
    assert!(!needs_change(&[ace(INHERIT, GRANT_MASK)], &wanted));
    assert!(!needs_change(&[ace(INHERIT, 0x001F_01FF)], &wanted));
    assert!(needs_change(
        &[ace(INHERIT | INHERITED, GRANT_MASK)],
        &wanted
    ));
    assert!(needs_change(&[ace(INHERIT, DELETE)], &wanted));
    assert!(needs_change(&[ace(0, GRANT_MASK)], &wanted));
    let deny = RawAce {
        allows: false,
        ..ace(INHERIT, GRANT_MASK)
    };
    assert!(needs_change(&[deny], &wanted));
}

/// The masks hold what the plan says: the grant has no right over the
/// access list, the owner or a child's deletion; the deny has no read right.
#[test]
fn the_masks_hold_no_more_than_they_say() {
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const FILE_DELETE_CHILD: u32 = 0x40;
    const FILE_READ_DATA: u32 = 0x1;
    assert_eq!(
        GRANT_MASK & (WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD),
        0
    );
    assert_eq!(DENY_MASK & FILE_READ_DATA, 0);
    assert_eq!(
        DENY_MASK & (WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD | DELETE),
        WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD | DELETE
    );
}

#[test]
fn only_windows_paths_below_a_drive_or_share_are_roots() {
    assert!(windows_path("C:/x"));
    assert!(windows_path("//server/share/x"));
    assert!(!windows_path("C:/"));
    assert!(!windows_path("/tmp"));
    assert!(!windows_path("//?/C:/x"));
    assert!(drive_root("C:/") && drive_root("c:") && drive_root("/"));
    assert!(!drive_root("C:/x"));
}
