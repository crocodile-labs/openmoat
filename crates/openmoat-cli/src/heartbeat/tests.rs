use std::fs;

use openmoat_hosts::{Activity, Host};

use super::*;

fn since(at_ms: i64) -> Since {
    Since {
        change: Change::PluginWritten,
        at_ms,
    }
}

fn facts(reported: Option<i64>, decided: Option<i64>, active: Option<i64>) -> Facts {
    Facts {
        since: since(100),
        reported_ms: reported,
        decided_ms: decided,
        active_ms: active,
    }
}

#[test]
fn a_report_or_a_call_since_the_change_is_a_loaded_plugin() {
    let reported = Loaded::Reported {
        since: since(100),
        at_ms: 150,
    };
    assert_eq!(judge(&facts(Some(150), None, Some(900))), reported);
    // A call the guard decided proves it as well (inside `openmoat run`,
    // where the plugin cannot write its report).
    assert_eq!(judge(&facts(None, Some(150), Some(900))), reported);
    assert_eq!(
        judge(&facts(Some(120), Some(150), None)),
        Loaded::Reported {
            since: since(100),
            at_ms: 150
        }
    );
}

/// No false alarm on a fresh `init`: the host has not run since.
#[test]
fn nothing_since_the_change_and_no_run_is_not_yet_loaded() {
    let not_yet = Loaded::NotYet { since: since(100) };
    assert_eq!(judge(&facts(None, None, None)), not_yet);
    // A report from before the plugin was written is not one for it.
    assert_eq!(judge(&facts(Some(99), None, Some(50))), not_yet);
    let (mark, text) = line("pi", &not_yet);
    assert_eq!(mark, Mark::Note);
    assert!(
        text.starts_with("plugin not loaded yet since OpenMoat wrote it"),
        "{text}"
    );
    assert_eq!(not_loaded("pi", &not_yet), None);
}

#[test]
fn a_run_since_the_change_without_a_report_is_a_missing_plugin() {
    let missing = judge(&facts(Some(99), None, Some(500)));
    assert_eq!(
        missing,
        Loaded::Missing {
            since: since(100),
            active_ms: 500
        }
    );
    let (mark, text) = line("pi", &missing);
    assert_eq!(mark, Mark::Warning);
    assert!(text.contains("pi has run since"), "{text}");
    assert!(text.contains("may run unchecked"), "{text}");
    let why = not_loaded("pi", &missing).unwrap();
    assert!(
        why.starts_with("plugin not loaded since it was written"),
        "{why}"
    );
    let updated = Loaded::Missing {
        since: Since {
            change: Change::HostUpdated,
            at_ms: 100,
        },
        active_ms: 500,
    };
    assert!(line("pi", &updated).1.contains("pi was updated"));
}

#[test]
fn a_report_is_written_owner_only_and_read_back_for_its_host_only() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("moat"));
    // No state directory: the plugin was not installed by `init`.
    assert!(report(&home, Host::Pi, 1).is_err());
    home.ensure().unwrap();
    // A host that runs a hook command has no plugin to report.
    assert!(report(&home, Host::Codex, 1).is_err());
    report(&home, Host::Pi, 1234).unwrap();
    assert_eq!(last(&home, Host::Pi), Some(1234));
    assert_eq!(last(&home, Host::OpenCode), None);
    let text = fs::read_to_string(path(&home, Host::Pi)).unwrap();
    assert!(text.contains(r#""host":"pi""#), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path(&home, Host::Pi))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Another host's record under this host's name, or a long file, is no report.
    fs::write(path(&home, Host::OpenCode), &text).unwrap();
    assert_eq!(last(&home, Host::OpenCode), None);
    fs::write(path(&home, Host::Pi), vec![b' '; 5000]).unwrap();
    assert_eq!(last(&home, Host::Pi), None);
}

#[test]
fn activity_is_the_newest_file_in_the_named_directories() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let sessions = [Activity::new(&["agents", Activity::ANY, "sessions"])];
    assert_eq!(newest_activity(root, &sessions), None);
    fs::create_dir_all(root.join("agents/main/sessions")).unwrap();
    fs::create_dir_all(root.join("agents/main/agent")).unwrap();
    // A file outside the sessions (an agent's sign-in) is no activity.
    fs::write(root.join("agents/main/agent/auth-profiles.json"), "{}").unwrap();
    assert_eq!(newest_activity(root, &sessions), None);
    fs::write(root.join("agents/main/sessions/s.jsonl"), "{}").unwrap();
    let seen = newest_activity(root, &sessions).unwrap();
    assert!(seen > 0);
    assert_eq!(newest_activity(root, &[]), None);
}
