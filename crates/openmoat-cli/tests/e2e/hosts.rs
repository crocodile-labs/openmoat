//! One suite for every agent: each test runs for every host in `Host::ALL`
//! (or `Host::EVERY`), reading what it needs from the host's spec and its row
//! in [`rows`]. A host's row is the fixture convention: the payloads it sends
//! and where its reply holds the verdict and the reason. A case a row leaves
//! out is covered for that host by the test file the row names. What only one
//! host does stays in that host's own test file (`codex.rs`, `pi.rs`, …).

use std::fs;
use std::path::PathBuf;
use std::process::Output;

use openmoat_hosts::{Host, HostSpec, InstallSpec};
use serde_json::Value;

use crate::common::{DENY, OK, Sandbox, output, stdout, text};

pub mod rows;

use rows::Row;

/// The row for the host whose id is `id`.
pub fn row(id: &str) -> Row {
    rows::rows()
        .into_iter()
        .find(|row| row.id == id)
        .unwrap_or_else(|| panic!("no row for {id} in hosts/rows.rs"))
}

fn install(host: Host) -> &'static InstallSpec {
    host.spec()
        .install
        .as_ref()
        .unwrap_or_else(|| panic!("{host} installs no hook"))
}

/// The file `moat init` writes `host`'s hook into, under the home's default
/// directory for it.
fn hook_file(sb: &Sandbox, host: Host) -> PathBuf {
    let install = install(host);
    sb.home.join(install.dir_name).join(install.config_file)
}

/// `moat guard` for `row`'s hook, as its host runs it, with `payload`.
pub fn guard(row: &Row, sb: &Sandbox, payload: &str) -> Output {
    let mut cmd = sb.command();
    cmd.args(["guard", "--host", row.hook]);
    if let Some(var) = row.env {
        cmd.env(var, &sb.home);
    }
    output(&mut cmd, Some(payload))
}

/// The reply as JSON: `Value::Null` when the hook printed nothing.
pub fn reply(out: &Output) -> Value {
    serde_json::from_str(stdout(out).trim()).unwrap_or(Value::Null)
}

/// The verdict in `row`'s reply format; empty when there is none.
pub fn verdict(row: &Row, out: &Output) -> String {
    reply(out)
        .pointer(row.verdict_at)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Assert that every reason field of `row`'s reply contains `needle`.
#[track_caller]
pub fn assert_reason(row: &Row, out: &Output, needle: &str, what: &str) {
    let doc = reply(out);
    for at in row.reason_at {
        let reason = doc.pointer(at).map(Value::to_string).unwrap_or_default();
        assert!(
            reason.contains(needle),
            "{} {what}: {at} lacks {needle:?}: {}",
            row.id,
            text(out)
        );
    }
}

/// The protection level `moat doctor` prints for a freshly installed `spec`;
/// `None` where this platform's level is not fixed by the spec.
fn installed_level(spec: &HostSpec) -> Option<String> {
    match &spec.sandbox {
        None => Some("hook only".to_owned()),
        Some(_) if !cfg!(windows) => Some("hook + OS sandbox".to_owned()),
        Some(sandbox) => sandbox
            .unavailable_on_windows
            .map(|why| format!("hook only: {}", why.split(';').next().unwrap_or(why))),
    }
}

/// The table is the host list: a new host needs its row.
#[test]
fn every_host_has_one_row_in_the_host_lists_order() {
    let ids: Vec<&str> = rows::rows().iter().map(|row| row.id).collect();
    let every: Vec<&str> = Host::EVERY.iter().map(|host| host.id()).collect();
    assert_eq!(ids, every);
}

#[test]
fn init_writes_its_entries_once_and_status_and_doctor_name_it() {
    for host in Host::ALL {
        let (id, name) = (host.id(), host.display_name());
        let install = install(host);
        let sb = Sandbox::installed(&[install.dir_name]);
        let hook = hook_file(&sb, host);
        let first = fs::read(&hook).unwrap_or_else(|e| panic!("{id}: {e}"));

        let again = sb.moat(&["init", "--yes"]);
        assert_eq!(again.status.code(), Some(OK), "{id}: {}", text(&again));
        let events: Vec<&str> = install.hooks.iter().map(|hook| hook.event).collect();
        let unchanged = format!("unchanged: {} →", events.join(", "));
        assert!(text(&again).contains(&unchanged), "{id}: {}", text(&again));
        assert_eq!(
            fs::read(&hook).unwrap(),
            first,
            "{id}: init rewrote the hook"
        );

        let status = sb.moat(&["status"]);
        assert_eq!(status.status.code(), Some(OK), "{id}: {}", text(&status));
        assert!(text(&status).contains(name), "{id}: {}", text(&status));
        let doctor = text(&sb.moat(&["doctor"]));
        let line = match installed_level(host.spec()) {
            Some(level) => format!("{name:<16} protection: {level}"),
            None => format!("{name:<16} protection: "),
        };
        assert!(doctor.contains(&line), "{id}: {line:?} in {doctor}");
        assert!(
            !doctor.contains("is pinned but not this shell's"),
            "{id}: {doctor}"
        );
    }
}

/// A file of the person's where the hook goes comes back byte for byte; a
/// file OpenMoat owns whole is deleted, and its directory stays.
#[test]
fn uninstall_gives_back_the_persons_file() {
    for host in Host::ALL {
        let (id, row) = (host.id(), row(host.id()));
        let dir = install(host).dir_name;
        if let Some(original) = row.persons_file {
            let sb = Sandbox::bare(&[dir]);
            let hook = hook_file(&sb, host);
            fs::create_dir_all(hook.parent().unwrap()).unwrap();
            fs::write(&hook, original).unwrap();
            let out = sb.moat(&["init", "--yes", "--hosts", id]);
            assert_eq!(out.status.code(), Some(OK), "{id}: {}", text(&out));
            assert_ne!(fs::read_to_string(&hook).unwrap(), original, "{id}");

            let out = sb.moat_as_person(&["uninstall"]);
            assert_eq!(out.status.code(), Some(OK), "{id}: {}", text(&out));
            assert_eq!(
                fs::read_to_string(&hook).unwrap(),
                original,
                "{id}: {}",
                text(&out)
            );
            if let Some(extra) = row.extra_dir {
                let extra = sb.home.join(dir).join(extra);
                assert!(!extra.exists(), "{id}: {}", text(&out));
            }
        }
        if row.owns_file {
            let sb = Sandbox::installed(&[dir]);
            let hook = hook_file(&sb, host);
            assert!(hook.is_file(), "{id}");
            let out = sb.moat_as_person(&["uninstall"]);
            assert_eq!(out.status.code(), Some(OK), "{id}: {}", text(&out));
            assert!(!hook.exists(), "{id}: {}", text(&out));
            assert!(sb.home.join(dir).is_dir(), "{id}: the directory stays");
        }
    }
}

/// The lock pins the hook file: once it is edited on disk, every call is
/// denied until a person re-pins.
#[test]
fn an_edited_hook_file_denies_every_call() {
    for host in Host::ALL {
        let row = row(host.id());
        let Some(edit) = &row.edited else { continue };
        let sb = Sandbox::installed(&[install(host).dir_name]);
        let hook = hook_file(&sb, host);
        let before = fs::read_to_string(&hook).unwrap();
        let after = (edit.change)(&before);
        assert_ne!(after, before, "{}: the edit changed nothing", row.id);
        fs::write(&hook, after).unwrap();
        let out = guard(&row, &sb, &(edit.call)(&sb));
        assert_eq!(out.status.code(), Some(DENY), "{}: {}", row.id, text(&out));
        assert_eq!(verdict(&row, &out), "deny", "{}: {}", row.id, text(&out));
        assert_reason(&row, &out, "kernel-integrity", "edited hook file");
    }
}
