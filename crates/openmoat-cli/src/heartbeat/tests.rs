use std::fs;

use openmoat_hosts::{Activity, Host, Sessions};

use super::*;

fn since(at_ms: i64) -> Since {
    Since {
        change: Change::PluginWritten,
        at_ms,
    }
}

fn facts(reported: Option<i64>, decided: Option<i64>, last: Option<i64>) -> Facts {
    Facts {
        since: since(100),
        reported_ms: reported,
        decided_ms: decided,
        active: last.map(|last_ms| Active {
            last_ms,
            sessions: 1,
        }),
    }
}

/// A host of each kind, read from the specs.
fn plugin_host() -> Host {
    Host::ALL.into_iter().find(|h| has_plugin(*h)).unwrap()
}

fn hook_host(known: bool) -> Host {
    Host::ALL
        .into_iter()
        .find(|h| {
            h.spec()
                .install
                .as_ref()
                .and_then(|i| i.liveness.as_ref())
                .is_some_and(|l| matches!(l.sessions, Sessions::Known(_)) == known)
        })
        .unwrap()
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
    let host = plugin_host();
    let not_yet = Loaded::NotYet { since: since(100) };
    assert_eq!(judge(&facts(None, None, None)), not_yet);
    // A report from before the plugin was written is not one for it.
    assert_eq!(judge(&facts(Some(99), None, Some(50))), not_yet);
    let (mark, text) = line(host, &not_yet);
    assert_eq!(mark, Mark::Note);
    assert!(
        text.starts_with("plugin not loaded yet since OpenMoat wrote it"),
        "{text}"
    );
    assert_eq!(not_loaded(host, &not_yet), None);
}

#[test]
fn a_run_since_the_change_without_a_report_is_a_missing_plugin() {
    let host = plugin_host();
    let name = host.display_name();
    let missing = judge(&facts(Some(99), None, Some(500)));
    assert_eq!(
        missing,
        Loaded::Missing {
            since: since(100),
            active_ms: 500,
            sessions: 1,
        }
    );
    let (mark, text) = line(host, &missing);
    assert_eq!(mark, Mark::Warning);
    assert!(text.contains(&format!("{name} has run since")), "{text}");
    assert!(text.contains("may run unchecked"), "{text}");
    let why = not_loaded(host, &missing).unwrap();
    assert!(
        why.starts_with("plugin not loaded since it was written"),
        "{why}"
    );
    // A plugin's warning carries its own advice, not a hook's fix.
    assert_eq!(fix(host, &missing), None);
    let updated = Loaded::Missing {
        since: Since {
            change: Change::HostUpdated,
            at_ms: 100,
        },
        active_ms: 500,
        sessions: 1,
    };
    assert!(
        line(host, &updated)
            .1
            .contains(&format!("{name} was updated"))
    );
}

/// A hook host's call since the change shows the hook runs, whatever its
/// sessions; `status` leaves that out, `doctor` notes it.
#[test]
fn a_call_since_the_change_is_a_running_hook() {
    let host = hook_host(true);
    let change = Since {
        change: Change::HookWritten,
        at_ms: 100,
    };
    let loaded = judge(&Facts {
        since: change,
        reported_ms: None,
        decided_ms: Some(300),
        active: Some(Active {
            last_ms: 900,
            sessions: 4,
        }),
    });
    assert_eq!(
        loaded,
        Loaded::Reported {
            since: change,
            at_ms: 300
        }
    );
    let (mark, text) = line(host, &loaded);
    assert_eq!(mark, Mark::Detail);
    assert!(text.starts_with("hook runs: last call "), "{text}");
    assert_eq!(fix(host, &loaded), None);
    // A call from before the change says nothing about after it.
    let before = judge(&Facts {
        since: change,
        reported_ms: None,
        decided_ms: Some(99),
        active: None,
    });
    assert_eq!(before, Loaded::NotYet { since: change });
}

/// Sessions since the change and no call: a warning that counts them, says
/// what OpenMoat saw and no more, and gives the fix; never a lower
/// protection level, since the sessions may have needed no tool.
#[test]
fn sessions_since_the_change_without_a_call_warn_with_the_fix() {
    let host = hook_host(true);
    let name = host.display_name();
    let missing = judge(&Facts {
        since: Since {
            change: Change::SettingsChanged,
            at_ms: 100,
        },
        reported_ms: None,
        decided_ms: None,
        active: Some(Active {
            last_ms: 500,
            sessions: 3,
        }),
    });
    assert!(matches!(missing, Loaded::Missing { sessions: 3, .. }));
    let (mark, text) = line(host, &missing);
    assert_eq!(mark, Mark::Warning);
    assert!(
        text.starts_with(&format!("{name} ran 3 sessions since its settings changed")),
        "{text}"
    );
    assert!(text.contains("OpenMoat saw no call from it"), "{text}");
    assert!(text.contains("if they used tools"), "{text}");
    let fix = fix(host, &missing).unwrap();
    assert!(fix.contains("`openmoat init`"), "{fix}");
    assert!(
        fix.contains(host.spec().hook_failure.turned_off_by),
        "{fix}"
    );
    if let Some(step) = crate::install::trust_note::step(host) {
        assert!(fix.ends_with(step), "{fix}");
    }
    assert_eq!(not_loaded(host, &missing), None);
    let one = Loaded::Missing {
        since: since(100),
        active_ms: 500,
        sessions: 1,
    };
    assert!(line(host, &one).1.contains("ran 1 session since"));
    assert!(line(host, &one).1.contains("if it used tools"));
}

/// Where a host's sessions are unknown, no call since the change is only a
/// note that says why OpenMoat cannot tell more.
#[test]
fn an_unknown_session_place_is_only_a_note() {
    let host = hook_host(false);
    let not_yet = Loaded::NotYet {
        since: Since {
            change: Change::HostUpdated,
            at_ms: 100,
        },
    };
    let (mark, text) = line(host, &not_yet);
    assert_eq!(mark, Mark::Detail);
    assert!(text.contains("OpenMoat cannot tell whether"), "{text}");
    assert!(
        text.contains(&format!("{} was updated", host.display_name())),
        "{text}"
    );
    let known = hook_host(true);
    let (_, text) = line(known, &not_yet);
    assert!(text.contains("has not run a session since"), "{text}");
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
    assert_eq!(scan::sessions(root, &sessions, 0, i64::MAX), None);
    fs::create_dir_all(root.join("agents/main/sessions")).unwrap();
    fs::create_dir_all(root.join("agents/main/agent")).unwrap();
    // A file outside the sessions (an agent's sign-in) is no activity.
    fs::write(root.join("agents/main/agent/auth-profiles.json"), "{}").unwrap();
    assert_eq!(scan::sessions(root, &sessions, 0, i64::MAX), None);
    fs::write(root.join("agents/main/sessions/s.jsonl"), "{}").unwrap();
    let seen = scan::sessions(root, &sessions, 0, i64::MAX).unwrap();
    assert!(seen.last_ms > 0);
    assert_eq!(seen.sessions, 1);
    assert_eq!(scan::sessions(root, &[], 0, i64::MAX), None);
    // Written before the change: not a session since it.
    assert_eq!(
        scan::sessions(root, &sessions, seen.last_ms + 1, i64::MAX),
        None
    );
}

/// Only files of a session's name count, one each; a session that started
/// too recently to have needed a tool yet is not counted.
#[test]
fn sessions_are_counted_by_name_once_they_are_old_enough() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let sessions = [Activity::new(&["projects", Activity::ANY]).ending(".jsonl")];
    for project in ["a", "b"] {
        fs::create_dir_all(root.join("projects").join(project)).unwrap();
        fs::write(root.join("projects").join(project).join("s.jsonl"), "{}").unwrap();
        fs::write(root.join("projects").join(project).join("notes.md"), "").unwrap();
    }
    let seen = scan::sessions(root, &sessions, 0, i64::MAX).unwrap();
    assert_eq!(seen.sessions, 2);
    // Every one of them started after this point.
    assert_eq!(scan::sessions(root, &sessions, 0, 0), None);
}

/// The hook host check end to end on files: the hook written, a session of
/// the host's since, no call: missing; the specs' places drive it.
#[test]
fn a_hook_host_with_a_session_and_no_call_is_missing() {
    let host = hook_host(true);
    let Some(Sessions::Known(activity)) = host
        .spec()
        .install
        .as_ref()
        .and_then(|i| i.liveness.as_ref())
        .map(|l| l.sessions)
    else {
        unreachable!("hook_host(true) has known sessions")
    };
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Build the session path the spec names, every `*` one directory.
    let first = activity[0];
    let folder = first.dir.iter().fold(root.to_path_buf(), |at, part| {
        at.join(if *part == Activity::ANY { "x" } else { part })
    });
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join(format!("session{}", first.ending)), "{}").unwrap();
    let found = scan::sessions(root, activity, 0, i64::MAX).unwrap();
    let loaded = judge(&Facts {
        since: since(0),
        reported_ms: None,
        decided_ms: None,
        active: Some(found),
    });
    assert!(matches!(loaded, Loaded::Missing { sessions: 1, .. }));
}
