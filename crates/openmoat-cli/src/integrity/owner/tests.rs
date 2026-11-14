use std::collections::BTreeMap;
use std::path::Path;

use openmoat_hosts::{Host, RelaxedCheck};

use super::*;

/// The host whose relaxed keys are compared by the rest of the file and
/// whose variable names the home its directory is in (Gemini CLI), and the
/// one compared key by key whose variable names the directory itself (Claude
/// Code), from the specs.
fn hosts() -> (Host, Host) {
    let find = |check: RelaxedCheck| {
        Host::ALL
            .into_iter()
            .find(|h| {
                install(*h).is_some_and(|i| !i.relaxed_keys.is_empty() && i.relaxed_check == check)
            })
            .unwrap()
    };
    (find(RelaxedCheck::Rest), find(RelaxedCheck::ByKey))
}

/// A lock from before the owners were recorded reads each file as the older
/// version did: one in `.gemini` as Gemini CLI's, any other `settings.json`
/// as Claude Code's, any other name as no host's.
#[test]
fn a_lock_without_owners_reads_each_file_by_its_place() {
    let (rest, by_key) = hosts();
    for (path, owner) in [
        ("/home/me/.gemini/settings.json", Some(rest)),
        ("/srv/agent-home/.gemini/settings.json", Some(rest)),
        ("/home/me/.claude/settings.json", Some(by_key)),
        ("/srv/claude-config/settings.json", Some(by_key)),
        ("/home/me/.gemini/extensions/x/settings.json", Some(by_key)),
        ("/home/me/.gemini/settings.json.bak", None),
        ("/home/me/.codex/hooks.json", None),
    ] {
        assert_eq!(legacy_owner(Path::new(path)), owner, "{path}");
        let lock = Lock::parse(
            br#"{"version":1,"pinned_at_ms":0,"binary":"","entries":{}}"#,
            Path::new("policy.lock"),
        )
        .unwrap();
        assert_eq!(lock.hook_owner(path), owner, "{path}");
    }
}

/// A lock that records the owners reads only them: a `settings.json` it does
/// not name is no host's, whatever its name and place.
#[test]
fn a_lock_with_owners_reads_only_them() {
    let (rest, _) = hosts();
    let text = format!(
        r#"{{"version":1,"pinned_at_ms":0,"binary":"","entries":{{}},
            "hook_owners":{{"/a/custom.json":"{}"}}}}"#,
        rest.id()
    );
    let lock = Lock::parse(text.as_bytes(), Path::new("policy.lock")).unwrap();
    assert_eq!(lock.hook_owner("/a/custom.json"), Some(rest));
    assert_eq!(lock.hook_owner("/home/me/.claude/settings.json"), None);
    assert_eq!(
        lock.unpinned("/home/me/.claude/settings.json"),
        &[] as &[&str]
    );
    assert!(lock.relaxing("/home/me/.claude/settings.json").is_none());
    assert_eq!(
        lock.hook_owners,
        Some(BTreeMap::from([(
            "/a/custom.json".into(),
            rest.id().into()
        )]))
    );
}
