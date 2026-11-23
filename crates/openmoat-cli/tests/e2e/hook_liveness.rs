//! Hook liveness (ADR-104), end to end for every agent that runs a hook
//! command and whose spec names where it writes its sessions: after `init`, a
//! session written since and no call is a warning in `status` and `doctor`
//! (never a lower protection level), and a call the guard decides clears it.
//! An agent whose session place is unknown stays a note.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use openmoat_hosts::{Activity, Host, Sessions};
use serde_json::Value;

use crate::common::{Sandbox, fixture, json as parse, text};
use crate::hosts::{dir_of, guard, hook_file, row};

fn status(sb: &Sandbox) -> Value {
    parse(&sb.moat(&["status", "--format", "json"]))
}

fn entry<'a>(doc: &'a Value, key: &str, host: Host) -> &'a Value {
    doc[key]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["host"] == host.id())
        .unwrap_or_else(|| panic!("no {host} under {key} in {doc}"))
}

/// Make `path` look written `minutes` ago.
fn age(path: &Path, minutes: u64) {
    let then = SystemTime::now() - Duration::from_secs(minutes * 60);
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .set_modified(then)
        .unwrap();
}

/// [`age`] that keeps the file's birth time. A real file is never last
/// written before it was made, so macOS moves the birth time back with an
/// older modification time unless it is set too; Linux cannot set it and
/// leaves it.
fn age_keeping_birth(path: &Path, minutes: u64) {
    let born = fs::metadata(path).and_then(|m| m.created()).ok();
    let then = SystemTime::now() - Duration::from_secs(minutes * 60);
    let times = fs::FileTimes::new().set_modified(then);
    #[cfg(target_vendor = "apple")]
    let times = match born {
        Some(born) => std::os::darwin::fs::FileTimesExt::set_created(times, born),
        None => times,
    };
    #[cfg(not(target_vendor = "apple"))]
    let _ = born;
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .set_times(times)
        .unwrap();
}

/// Make every file `init` wrote that liveness reads for `host` (the hook file
/// and the spec's settings files, such as Codex's `config.toml`) look written
/// `minutes` ago, and the lock `minutes - 10` ago, as if `init` ran then and
/// pinned them after. Ageing the hook file alone would leave a settings file
/// newer than the lock, which reads as a change after OpenMoat's write.
fn install_aged(sb: &Sandbox, host: Host, minutes: u64) {
    age(&hook_file(sb, host), minutes);
    let settings = host
        .spec()
        .install
        .as_ref()
        .and_then(|install| install.liveness.as_ref())
        .map_or(&[][..], |liveness| liveness.settings);
    for file in settings {
        let path = sb.home.join(dir_of(host)).join(file);
        if path.exists() {
            age(&path, minutes);
        }
    }
    age(&sb.home.join(".moat/policy.lock"), minutes - 10);
}

/// Where `host` writes its sessions; `None` for a host that runs a plugin.
fn liveness(host: Host) -> Option<Sessions> {
    host.spec()
        .install
        .as_ref()
        .and_then(|install| install.liveness.as_ref())
        .map(|l| l.sessions)
}

/// A session file where `activity` says, every `*` one directory.
fn session_file(dir: &Path, activity: &Activity) -> PathBuf {
    let folder = activity.dir.iter().fold(dir.to_path_buf(), |at, part| {
        at.join(if *part == Activity::ANY { "x" } else { part })
    });
    fs::create_dir_all(&folder).unwrap();
    let file = folder.join(format!("session{}", activity.ending));
    fs::write(&file, "{}\n").unwrap();
    file
}

/// The hook hosts whose session place is known, with it.
fn known() -> impl Iterator<Item = (Host, &'static [Activity])> {
    Host::ALL
        .into_iter()
        .filter_map(|host| match liveness(host)? {
            Sessions::Known(activity) => Some((host, activity)),
            Sessions::Unknown(_) => None,
        })
}

#[test]
fn a_session_without_a_call_warns_and_a_call_clears_it() {
    for (host, activity) in known() {
        let sb = Sandbox::installed(&[&dir_of(host)]);
        // OpenMoat wrote the hook two hours ago and pinned it after.
        install_aged(&sb, host, 120);
        let doc = status(&sb);
        assert_eq!(entry(&doc, "hooks", host)["state"], "not-yet", "{doc}");
        assert_eq!(
            entry(&doc, "hooks", host)["since"]["change"],
            "hook-written",
            "{doc}"
        );
        let level = entry(&doc, "agents", host)["level"].clone();

        // A session an hour old, written since, and no call.
        let file = session_file(&sb.home.join(dir_of(host)), &activity[0]);
        age(&file, 60);
        let doc = status(&sb);
        let hook = entry(&doc, "hooks", host);
        assert_eq!(hook["state"], "missing", "{host}: {doc}");
        assert_eq!(hook["sessions"], 1, "{host}: {doc}");
        // A warning, never a lower protection level.
        assert_eq!(entry(&doc, "agents", host)["level"], level, "{host}: {doc}");
        let shown = crate::common::squash(&text(&sb.moat(&["status"])));
        assert!(
            shown.contains("OpenMoat saw no call from it"),
            "{host}: {shown}"
        );
        assert!(shown.contains("`openmoat init`"), "{host}: {shown}");
        let checks = parse(&sb.moat(&["doctor", "--format", "json"]));
        assert!(
            checks["checks"].as_array().unwrap().iter().any(|row| {
                row["status"] == "warning"
                    && row["detail"]
                        .as_str()
                        .is_some_and(|d| d.contains("ran 1 session since"))
            }),
            "{host}: {checks}"
        );

        // A call the guard decides shows the hook runs.
        let row = row(host.id());
        guard(&row, &sb, &fixture(row.governed));
        let doc = status(&sb);
        assert_eq!(
            entry(&doc, "hooks", host)["state"],
            "reported",
            "{host}: {doc}"
        );
        let shown = text(&sb.moat(&["status"]));
        assert!(!shown.contains("saw no call"), "{host}: {shown}");
    }
}

/// A session that started only minutes ago may not have needed a tool yet.
#[test]
fn a_session_too_new_for_a_call_is_no_warning() {
    let (host, activity) = known().next().expect("a hook host with known sessions");
    let sb = Sandbox::installed(&[&dir_of(host)]);
    install_aged(&sb, host, 120);
    session_file(&sb.home.join(dir_of(host)), &activity[0]);
    let doc = status(&sb);
    assert_eq!(entry(&doc, "hooks", host)["state"], "not-yet", "{doc}");
}

/// Where the session place is unknown, `doctor` notes that no call came and
/// why it cannot tell more; `status` says nothing.
#[test]
fn an_unknown_session_place_is_a_note_in_doctor() {
    for host in Host::ALL {
        let Some(Sessions::Unknown(why)) = liveness(host) else {
            continue;
        };
        let sb = Sandbox::installed(&[&dir_of(host)]);
        let doc = status(&sb);
        assert_eq!(
            entry(&doc, "hooks", host)["state"],
            "not-yet",
            "{host}: {doc}"
        );
        let checks = parse(&sb.moat(&["doctor", "--format", "json"]));
        assert!(
            checks["checks"].as_array().unwrap().iter().any(|row| {
                row["status"] == "note" && row["detail"].as_str().is_some_and(|d| d.contains(why))
            }),
            "{host}: {checks}"
        );
        let shown = text(&sb.moat(&["status"]));
        assert!(
            !shown.contains("OpenMoat cannot tell whether"),
            "{host}: {shown}"
        );
    }
}

/// The hook hosts whose session start reaches the guard (ADR-109), with
/// where they write their sessions.
fn started() -> impl Iterator<Item = (Host, &'static Activity, &'static openmoat_hosts::Started)> {
    Host::ALL.into_iter().filter_map(|host| {
        let liveness = host.spec().install.as_ref()?.liveness.as_ref()?;
        let Sessions::Known(activity) = liveness.sessions else {
            return None;
        };
        Some((host, activity.first()?, liveness.started.as_ref()?))
    })
}

/// A session whose start reached the guard and whose own transcript names a
/// covered tool, with no call of it, warns at once; a call clears it.
#[test]
fn a_started_session_that_called_a_tool_without_a_call_warns_at_once() {
    let mut seen = 0;
    for (host, activity, started) in started() {
        seen += 1;
        let sb = Sandbox::installed(&[&dir_of(host)]);
        let cwd = sb.project();
        let start = serde_json::json!({
            "session_id": "fast1", "cwd": cwd.to_string_lossy(),
            "hook_event_name": started.tool, "source": "startup"
        });
        let out = sb.guard(host.id(), &start.to_string());
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        let folder = activity
            .dir
            .iter()
            .fold(sb.home.join(dir_of(host)), |at, part| {
                at.join(if *part == Activity::ANY { "p" } else { part })
            });
        fs::create_dir_all(&folder).unwrap();
        let file = folder.join(format!("fast1{}", activity.ending));
        let line = serde_json::json!({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}}
        ]}});
        fs::write(&file, format!("{line}\n")).unwrap();
        // Written a minute ago: the guard had its budget to record a call.
        // The file was made after the start, which tells it from a resumed
        // session's: its birth time stays.
        age_keeping_birth(&file, 1);
        let doc = status(&sb);
        let hook = entry(&doc, "hooks", host);
        assert_eq!(hook["state"], "unchecked", "{host}: {doc}");
        assert_eq!(hook["tool"], "Bash", "{host}: {doc}");
        let shown = crate::common::squash(&text(&sb.moat(&["status"])));
        assert!(
            shown.contains("tool-call hook did not run"),
            "{host}: {shown}"
        );

        let call = crate::common::bash_payload("fast1", &cwd, "ls");
        sb.guard(host.id(), &call);
        let doc = status(&sb);
        assert_ne!(
            entry(&doc, "hooks", host)["state"],
            "unchecked",
            "{host}: {doc}"
        );
    }
    assert!(seen > 0, "no host's session start reaches the guard");
}
