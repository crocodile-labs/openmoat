//! Hooks inside `moat run` (ADR-028): a `moat guard` the agent starts runs in
//! the run's sandbox, without OpenMoat's home, and gets its decision from the
//! `moat run` process over the proxy's port. The scripts stand in for an
//! agent that runs its hook; the sandbox is the real one.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Output;

use serde_json::{Value, json};

use crate::common::{DENY, OK, Sandbox, json as json_of, output, stderr, stdout, text};
use crate::run::confined::{ran, retried};
use crate::run::{installed_with_secret, run_sh_with};
use crate::taint::call;

/// The `moat` binary, copied into the project: the sandbox reads the project.
fn moat_in(project: &Path) -> PathBuf {
    let copy = project.join("moat-bin");
    std::fs::copy(env!("CARGO_BIN_EXE_openmoat"), &copy).unwrap();
    copy
}

/// The audit session `moat run` named in its notice.
fn run_session(out: &Output) -> String {
    stderr(out)
        .split("audit session ")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .unwrap_or_else(|| panic!("no audit session in {}", text(out)))
        .to_owned()
}

/// The rows of `session`, oldest first.
fn rows(sb: &Sandbox, session: &str) -> Vec<Value> {
    let shown = sb.moat(&["show", "--session", session, "--format", "json"]);
    json_of(&shown).as_array().cloned().unwrap_or_default()
}

fn rules(row: &Value) -> Vec<String> {
    row["rules"]
        .as_array()
        .map(|r| {
            r.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// A script that pipes `$PAYLOAD` into the copied guard and prints its exit
/// code, `extra` first in the guard's environment.
fn hook_script(extra: &str) -> String {
    format!(
        "printf '%s' \"$PAYLOAD\" | {extra} ./moat-bin guard --host claude-code > hook.out; \
         echo \"hook=$?\"; cat hook.out"
    )
}

#[test]
fn a_hook_inside_moat_run_gets_a_real_decision_and_a_row() {
    let (sb, project) = installed_with_secret();
    moat_in(&project);
    let key = json!({"file_path": sb.home.join(".ssh/id_rsa").to_string_lossy()});
    let payload = call("in-run", &project, "Read", &key);
    let out = run_sh_with(&sb, &project, &hook_script(""), &[("PAYLOAD", &payload)]);
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    // Before ADR-028 this was a kernel-error deny: the guard could not read the lock.
    assert!(stdout(&out).contains(&format!("hook={DENY}")), "{shown}");
    assert!(shown.contains("secrets-paths"), "{shown}");
    assert!(!shown.contains("kernel-error"), "{shown}");
    let decided = rows(&sb, "in-run");
    assert_eq!(decided.len(), 1, "{decided:?}");
    assert_eq!(rules(&decided[0]), ["secrets-paths"]);
    // The run's link row ties the hook session to the run's proxy (ADR-027).
    let run = rows(&sb, &run_session(&out));
    assert!(
        run.iter()
            .any(|r| r["host"] == "moat-run" && r["call_id"] == "in-run"),
        "{run:?}"
    );
}

#[test]
fn a_wrong_token_is_denied_and_recorded_but_not_decided() {
    let (sb, project) = installed_with_secret();
    moat_in(&project);
    let payload = crate::common::bash_payload("wrong-token", &project, "ls");
    let script = hook_script("MOAT_GUARD_TOKEN=not-the-runs-token");
    let out = run_sh_with(&sb, &project, &script, &[("PAYLOAD", &payload)]);
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    assert!(stdout(&out).contains(&format!("hook={DENY}")), "{shown}");
    assert!(shown.contains("did not decide"), "{shown}");
    assert!(rows(&sb, "wrong-token").is_empty(), "never decided");
    let run = rows(&sb, &run_session(&out));
    assert!(
        run.iter().any(|r| rules(r) == ["run-guard-token"]),
        "{run:?}"
    );
}

/// A secret read decided through the relay taints the run's proxy: a request
/// to an allowed registry is refused before it is sent anywhere.
#[test]
fn a_secret_read_inside_the_run_taints_its_egress() {
    let (sb, project) = installed_with_secret();
    moat_in(&project);
    // An untrusted repository policy may tighten: it makes this file a secret
    // whose read asks, and an asked read may have run.
    std::fs::create_dir_all(project.join(".moat")).unwrap();
    std::fs::write(
        project.join(".moat/policy.yaml"),
        "version: 1\nask:\n  - id: secrets-paths\n    fs.read: ['${project}/creds/**']\n",
    )
    .unwrap();
    std::fs::create_dir_all(project.join("creds")).unwrap();
    std::fs::write(project.join("creds/token"), "FAKE-TOKEN").unwrap();
    let read = json!({"file_path": project.join("creds/token").to_string_lossy()});
    let payload = call("tainted", &project, "Read", &read);
    let script = format!(
        "{}\ncurl -sS -m 30 -w '\\negress=%{{http_code}}\\n' http://crates.io/",
        hook_script("")
    );
    let out = retried(|| run_sh_with(&sb, &project, &script, &[("PAYLOAD", &payload)]));
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    assert!(stdout(&out).contains(&format!("hook={OK}")), "{shown}");
    assert!(stdout(&out).contains("\"ask\""), "{shown}");
    assert!(stdout(&out).contains("egress=403"), "{shown}");
    let run = rows(&sb, &run_session(&out));
    assert!(
        run.iter()
            .any(|r| r["host"] == "proxy" && rules(r).contains(&"session-taint".to_owned())),
        "{run:?}"
    );
}

/// The sandbox still keeps the agent and its hooks from changing OpenMoat's
/// home, and nothing in it can take over the port the decisions come from.
#[test]
fn the_sandbox_still_cannot_touch_the_home_or_take_the_port() {
    let (sb, project) = installed_with_secret();
    let lock = std::fs::read(sb.home.join(".moat/policy.lock")).unwrap();
    // `kernel-self` denies writing OpenMoat's home wherever it is, and reading
    // the audit log and the lock. On macOS this test's home is in the temp
    // directory, a read root, so only that read deny keeps them from the
    // agent; on Linux it is outside every grant, where `moat run` must keep it.
    let script = r#"echo forged >> "$HOME/.moat/audit.db" 2>/dev/null; echo "audit=$?"
         echo forged > "$HOME/.moat/policy.lock" 2>/dev/null; echo "lock=$?"
         cat "$HOME/.moat/audit.db" > /dev/null 2>&1; echo "read_audit=$?"
         cat "$HOME/.moat/policy.lock" > /dev/null 2>&1; echo "read_lock=$?"
         cat "$HOME/.moat/policy.yaml" > /dev/null 2>&1; echo "read_policy=$?"
         python3 -c '
import os, socket
host, port = os.environ["MOAT_GUARD_SOCKET"].rsplit(":", 1)
s = socket.socket()
try:
    s.bind((host, int(port)))
    print("bind=open")
except OSError:
    print("bind=refused")
'"#;
    let out = run_sh_with(&sb, &project, script, &[]);
    if !ran(&out) {
        return;
    }
    let shown = text(&out);
    // Held by `moat run` and outside what the sandbox lets anything bind.
    // Seatbelt denies a path inside a granted tree; Landlock only grants, so on
    // Linux `moat run` refuses to start where a grant holds the state directory
    // (`a_state_directory_inside_the_project_is_refused`): either way the agent
    // cannot read the audit log or the lock.
    for refused in [
        "bind=open",
        "audit=0",
        "lock=0",
        "read_audit=0",
        "read_lock=0",
    ] {
        assert!(!stdout(&out).contains(refused), "{refused}: {shown}");
    }
    // Seatbelt keeps the policy readable; outside every Landlock grant it is not.
    if cfg!(target_os = "macos") {
        assert!(stdout(&out).contains("read_policy=0"), "{shown}");
    }
    assert_eq!(
        std::fs::read(sb.home.join(".moat/policy.lock")).unwrap(),
        lock
    );
    let doctor = sb.moat(&["doctor"]);
    assert!(
        stdout(&doctor).contains("hash chain intact"),
        "{}",
        text(&doctor)
    );
}

/// Landlock cannot deny inside a granted tree: with OpenMoat's state directory
/// in the project, `moat run` refuses to start rather than leave the audit log
/// and the lock readable to the agent, and names the way out.
#[cfg(target_os = "linux")]
#[test]
fn a_state_directory_inside_the_project_is_refused() {
    use crate::common::USAGE;

    let sb = Sandbox::bare_in(Path::new(env!("CARGO_TARGET_TMPDIR")), &[]);
    let project = sb.project();
    let state = project.join("state");
    let moved = state.to_string_lossy().into_owned();
    let init = output(
        sb.command()
            .env("MOAT_HOME", &state)
            .args(["init", "--yes"]),
        None,
    );
    assert_eq!(
        init.status.code(),
        Some(OK),
        "openmoat init: {}",
        text(&init)
    );
    let out = run_sh_with(&sb, &project, "echo ran", &[("MOAT_HOME", moved.as_str())]);
    let shown = text(&out);
    assert_eq!(out.status.code(), Some(USAGE), "{shown}");
    assert!(stderr(&out).contains("Move MOAT_HOME out of"), "{shown}");
    assert!(!stdout(&out).contains("ran"), "{shown}");
}

/// A server at the address that does not answer as this run's service: a
/// reply for another request, an exit code the guard never gives, or an
/// HTTP answer. Each is a deny, and none is recorded as a decision.
#[test]
fn a_forged_reply_is_a_deny() {
    let sb = Sandbox::installed(&[".claude"]);
    let project = sb.project();
    let forged: [&[u8]; 3] = [
        // Magic, then a nonce no request sent, exit 0 and an allow.
        b"MOAT-GUARD-REPLY/1\n\x00\x00\x00\x20ffffffffffffffffffffffffffffffff\
          \x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"",
    ];
    for reply in forged {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            if let Ok((mut client, _)) = listener.accept() {
                let mut request = vec![0u8; 64];
                let _ = client.read(&mut request);
                let _ = client.write_all(reply);
            }
        });
        let mut cmd = sb.command();
        cmd.env("MOAT_GUARD_SOCKET", &addr)
            .env("MOAT_GUARD_TOKEN", "any")
            .args(["guard", "--host", "claude-code"]);
        let payload = crate::common::bash_payload("forged", &project, "ls");
        let out = output(&mut cmd, Some(&payload));
        server.join().unwrap();
        assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
        assert!(text(&out).contains("did not decide"), "{}", text(&out));
    }
    assert!(rows(&sb, "forged").is_empty());
}

/// Half the settings, an address off this machine or one nothing listens on:
/// the guard denies without deciding, and never falls back to its own home.
#[test]
fn a_guard_with_broken_relay_settings_denies() {
    let sb = Sandbox::installed(&[".claude"]);
    let project = sb.project();
    let cases: [&[(&str, &str)]; 4] = [
        &[("MOAT_GUARD_SOCKET", "127.0.0.1:9")],
        &[("MOAT_GUARD_TOKEN", "t")],
        &[
            ("MOAT_GUARD_SOCKET", "192.0.2.1:9"),
            ("MOAT_GUARD_TOKEN", "t"),
        ],
        &[
            ("MOAT_GUARD_SOCKET", "127.0.0.1:1"),
            ("MOAT_GUARD_TOKEN", "t"),
        ],
    ];
    for env in cases {
        let mut cmd = sb.command();
        cmd.envs(env.iter().copied())
            .args(["guard", "--host", "claude-code"]);
        let payload = crate::common::bash_payload("broken", &project, "ls");
        let out = output(&mut cmd, Some(&payload));
        assert_eq!(out.status.code(), Some(DENY), "{env:?}: {}", text(&out));
        assert!(text(&out).contains("did not decide"), "{}", text(&out));
    }
    assert!(rows(&sb, "broken").is_empty());
}
