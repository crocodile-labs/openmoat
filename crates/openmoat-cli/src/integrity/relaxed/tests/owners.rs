//! Which host's keys a pinned file takes: the one the lock records as its
//! owner, never one chosen by the file's name.

use super::*;

/// The host whose relaxed keys are compared one by one (Claude Code), and a
/// host whose spec lists no relaxed or unpinned keys, from the specs.
fn hosts() -> (openmoat_hosts::Host, openmoat_hosts::Host) {
    let install = |h: &openmoat_hosts::Host| h.spec().install.as_ref();
    let by_key = openmoat_hosts::Host::ALL
        .into_iter()
        .find(|h| install(h).is_some_and(|i| i.relaxed_check == RelaxedCheck::ByKey))
        .unwrap();
    let plain = openmoat_hosts::Host::ALL
        .into_iter()
        .find(|h| {
            install(h).is_some_and(|i| i.relaxed_keys.is_empty() && i.unpinned_keys.is_empty())
        })
        .unwrap();
    (by_key, plain)
}

/// Changes Claude Code's spec lets drift, each relaxed in its own file.
const RELAXED_IN_CLAUDES: [fn(&mut Value); 4] = [
    |s| s["theme"] = json!("light"),
    |s| s["language"] = json!("french"),
    |s| s["model"] = json!("claude-opus-4"),
    |s| s["permissions"]["allow"] = json!(["Bash(*)"]),
];

/// A `settings.json` the lock pins as the hook file of a host whose spec
/// lists no relaxed keys, or as no host's hook file, drifts on any change:
/// it never takes Claude Code's allowlist by its name. Each change denies
/// every call, and the file's bytes on disk are the changed ones the deny
/// names.
#[test]
fn another_hosts_settings_json_denies_on_any_drift() {
    let (_, plain) = hosts();
    for owner in [Some(plain), None] {
        for change in RELAXED_IN_CLAUDES {
            let setup = installed_for("settings.json", &baseline(), true, |_| owner);
            let lock = Lock::load(&setup.home.lock_path()).unwrap();
            let stored = crate::integrity::key(&setup.settings);
            assert_eq!(lock.hook_owner(&stored), owner);
            let mut settings = baseline();
            change(&mut settings);
            fs::write(&setup.settings, settings.to_string()).unwrap();
            let checked = check(&setup.home).unwrap();
            assert_denied(&checked);
            let deny = checked.deny.unwrap();
            assert!(
                deny.reasons
                    .iter()
                    .any(|r| r.contains("settings.json was modified")),
                "{owner:?}: {:?}",
                deny.reasons
            );
        }
    }
}

/// Claude Code's keys follow the host the lock pinned the file for, whatever
/// the file's name (`CLAUDE_CONFIG_DIR` may put it anywhere), and the owner
/// survives a re-pin that keeps the hook files.
#[test]
fn the_owner_not_the_name_selects_the_allowlist() {
    let (by_key, _) = hosts();
    for change in RELAXED_IN_CLAUDES {
        let setup = installed_for("agent-settings.json", &baseline(), true, |_| Some(by_key));
        let mut settings = baseline();
        change(&mut settings);
        fs::write(&setup.settings, settings.to_string()).unwrap();
        let checked = check(&setup.home).unwrap();
        if checked.relaxed.is_empty() {
            // `theme` is no drift at all.
            assert!(checked.deny.is_none(), "{:?}", checked.deny);
        } else {
            assert_relaxed(&checked);
        }
    }
    let setup = installed_for("agent-settings.json", &baseline(), true, |_| Some(by_key));
    let mut settings = baseline();
    settings["sandbox"]["enabled"] = json!(false);
    fs::write(&setup.settings, settings.to_string()).unwrap();
    assert_denied(&check(&setup.home).unwrap());
}

/// A lock written before the owners were recorded reads a `settings.json`
/// outside `.gemini` as Claude Code's, as it always did, so an install from
/// an older version keeps deciding through a new model.
#[test]
fn a_lock_without_owners_reads_settings_json_as_before() {
    let setup = installed(&baseline(), true);
    let mut lock = Lock::load(&setup.home.lock_path()).unwrap();
    lock.hook_owners = None;
    lock.save(&setup.home.lock_path()).unwrap();
    let mut settings = baseline();
    settings["model"] = json!("claude-opus-4");
    fs::write(&setup.settings, settings.to_string()).unwrap();
    assert_relaxed(&check(&setup.home).unwrap());
}

/// A re-pin of a lock from before the owners were recorded keeps a guessed
/// owner only where it is more than a name. Claude Code's file here is in no
/// `.claude` folder and not this shell's hook file, so after the re-pin it is
/// no host's: pinned by its bytes, a new model denies every call.
#[test]
fn a_repin_does_not_record_an_owner_guessed_from_a_name() {
    let setup = installed(&baseline(), true);
    let mut lock = Lock::load(&setup.home.lock_path()).unwrap();
    lock.hook_owners = None;
    lock.save(&setup.home.lock_path()).unwrap();
    let stored = crate::integrity::key(&setup.settings);
    let lock = Lock::load(&setup.home.lock_path()).unwrap();
    let (by_key, _) = hosts();
    assert_eq!(
        lock.hook_owner(&stored),
        Some(by_key),
        "still read as before"
    );
    assert_eq!(lock.owners(), Vec::new());
    assert_eq!(
        lock.owners_with(&[(setup.settings.clone(), by_key)]),
        [(PathBuf::from(&stored), by_key)],
        "kept for this shell's own hook file"
    );
    crate::integrity::unpin(&setup.home, &[], &[]).unwrap();
    let lock = Lock::load(&setup.home.lock_path()).unwrap();
    assert_eq!(lock.hook_owner(&stored), None);
    let mut settings = baseline();
    settings["model"] = json!("claude-opus-4");
    fs::write(&setup.settings, settings.to_string()).unwrap();
    assert_denied(&check(&setup.home).unwrap());
}
