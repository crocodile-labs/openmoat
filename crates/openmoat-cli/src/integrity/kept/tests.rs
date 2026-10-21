//! Each pinned state file the guard uses is parsed from the bytes the lock
//! check matched, even when the file is rewritten after the check.

use std::fs;
use std::path::{Path, PathBuf};

use openmoat_core::Action;

use super::*;
use crate::approvals::{Grants, Overlay, Scope};
use crate::environment::Snapshot;
use crate::home::write_private;
use crate::install::Recorded;
use crate::packs::{Installed, Packs, pack_path};
use crate::trust::Trust;

const POLICY: &str = "version: 1\ndefaults: { '*': defer }\n";
const PACK: &str = "version: 1\ndeny:\n  - id: no-publish\n    shell: ['cargo publish*']\n";

/// The session the kept grant is for.
const S1: Scope<'static> = Scope {
    host: "claude-code",
    session_id: "s1",
    project: "/code/app",
};

/// Every state file the guard reads, with one pack, all pinned.
fn installed(dir: &Path) -> (Home, Lock) {
    let home = Home::at(dir.join("state"));
    write_private(&home.policy_path(), POLICY.as_bytes()).unwrap();
    let mut overlay = Overlay::default();
    overlay.allow_command("make test").unwrap();
    overlay.save(&home.overlay_path()).unwrap();
    let mut grants = Grants::default();
    let make = Action::Shell {
        command: "make".into(),
    };
    let now = crate::time::now_ms();
    grants.grant(S1, &make, now, None);
    grants.save(&home.grants_path(), now).unwrap();
    let snapshot = r#"{"version":1,"captured_at_ms":1,"path":["/kept"],"programs":{}}"#;
    write_private(&home.environment_path(), snapshot.as_bytes()).unwrap();
    let mut trust = Trust::default();
    trust.repos.insert("/code/app".into(), "aa".into());
    trust.save(&home.trust_path()).unwrap();
    let hosts = r#"{"version":1,"dirs":{"claude-code":"/kept"}}"#;
    write_private(&home.hosts_path(), hosts.as_bytes()).unwrap();
    write_private(&pack_path(&home, "team"), PACK.as_bytes()).unwrap();
    let mut packs = Packs::default();
    let record = Installed {
        sha256: super::super::sha256_hex(PACK.as_bytes()),
        signer: "alice@x".into(),
        at_ms: 1,
    };
    packs.packs.insert("team".into(), record);
    packs.save(&home.packs_path()).unwrap();
    let mut pins = super::super::state_files(&home);
    pins.extend(super::super::signing_files(&home));
    let lock = Lock::pin(Path::new("/x/moat"), &pins).unwrap();
    lock.save(&home.lock_path()).unwrap();
    (home, lock)
}

/// Each state file rewritten after the check, as an agent racing it would.
fn rewrite_all(home: &Home) {
    let files: [(PathBuf, &str); 8] = [
        (home.policy_path(), "version: 1\ndefaults: { '*': allow }\n"),
        (home.overlay_path(), "version: 1\nallow: []\n"),
        (home.grants_path(), r#"{"version":2,"entries":[]}"#),
        (
            home.environment_path(),
            r#"{"version":1,"captured_at_ms":1,"path":["/disk"],"programs":{}}"#,
        ),
        (home.trust_path(), r#"{"version":1,"repos":{}}"#),
        (
            home.hosts_path(),
            r#"{"version":1,"dirs":{"claude-code":"/disk"}}"#,
        ),
        (home.packs_path(), r#"{"version":1,"packs":{}}"#),
        (pack_path(home, "team"), "version: 1\n"),
    ];
    for (path, text) in files {
        fs::write(path, text).unwrap();
    }
}

#[test]
fn every_state_file_the_guard_uses_is_the_one_checked() {
    let dir = tempfile::tempdir().unwrap();
    let (home, lock) = installed(dir.path());
    let (drift, kept) = verify_state(&home, &lock);
    assert!(drift.is_empty(), "{drift:?}");
    rewrite_all(&home);

    let policy = kept.load_policy().unwrap();
    assert_eq!(
        policy.defaults,
        openmoat_core::Policy::parse(POLICY).unwrap().defaults
    );
    assert!(
        policy.allow.iter().any(|g| g.id == "approved-1"),
        "the overlay as checked"
    );
    assert!(
        policy.deny.iter().any(|g| g.id == "pack:team:no-publish"),
        "the pack record and the pack as checked"
    );
    let make = Action::Shell {
        command: "make".into(),
    };
    let now = crate::time::now_ms();
    assert!(Grants::load_in(&kept).unwrap().matches(S1, &make, now));
    assert_eq!(
        Snapshot::load_in(&kept).unwrap().path,
        [PathBuf::from("/kept")]
    );
    assert!(crate::repo::trust(&kept).unwrap().trusts("/code/app", "aa"));
    let recorded = Recorded::load(&kept).unwrap();
    assert_eq!(recorded.dirs["claude-code"], PathBuf::from("/kept"));

    // A home that keeps nothing reads the files as they are now.
    assert_eq!(
        Snapshot::load_in(&home).unwrap().path,
        [PathBuf::from("/disk")]
    );
    assert_eq!(
        Recorded::load(&home).unwrap().dirs["claude-code"],
        PathBuf::from("/disk")
    );
    assert!(Grants::load_in(&home).unwrap().entries.is_empty());
}

#[test]
fn a_drifted_state_file_is_not_kept() {
    let dir = tempfile::tempdir().unwrap();
    let (home, lock) = installed(dir.path());
    fs::write(home.hosts_path(), r#"{"version":1,"dirs":{}}"#).unwrap();
    let (drift, kept) = verify_state(&home, &lock);
    assert_eq!(drift.len(), 1, "{drift:?}");
    assert_eq!(kept.kept().get(&home.hosts_path()), None);
    assert!(kept.kept().get(&home.policy_path()).is_some());
}

#[test]
fn an_unpinned_state_file_is_read_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let (home, _) = installed(dir.path());
    let lock = Lock::pin(Path::new("/x/moat"), &[home.policy_path()]).unwrap();
    let (drift, kept) = verify_state(&home, &lock);
    assert!(drift.is_empty(), "{drift:?}");
    rewrite_all(&home);
    assert_eq!(
        Snapshot::load_in(&kept).unwrap().path,
        [PathBuf::from("/disk")]
    );
    assert_eq!(
        kept.load_policy().unwrap().allow.len(),
        0,
        "the overlay on disk"
    );
}
