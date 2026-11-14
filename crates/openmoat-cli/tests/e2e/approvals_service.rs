//! `openmoat approvals install`/`uninstall` and `listen --service` (ADR-094),
//! and the credential prompt of `connect`: the service file runs the listener
//! from the pinned binary, owner-only; the listener refuses to run as a
//! service from a changed file, a steered environment, or a launch the
//! service manager did not make; an agent's call of any of them is denied;
//! a credential typed at `connect` is never shown back. No network, and
//! `launchctl`/`systemctl` are never run (`MOAT_SERVICE_SKIP_EXEC=1`, debug
//! builds only).

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

use crate::common::{DENY, Sandbox, USAGE, text};

/// `cmd` as a person at a terminal runs it, without touching the real
/// service manager.
fn as_person(cmd: &mut Command) -> &mut Command {
    cmd.env("MOAT_ASSUME_TTY", "1")
        .env("MOAT_SERVICE_SKIP_EXEC", "1")
}

fn run(sb: &Sandbox, args: &[&str]) -> Output {
    as_person(sb.command().args(args)).output().unwrap()
}

#[test]
fn an_agent_cannot_install_or_run_the_listener_service() {
    let sb = Sandbox::installed(&[]);
    // The installed policy's decision on each, as every agent's hook gets it.
    for command in [
        "openmoat approvals install",
        "openmoat approvals uninstall",
        "openmoat approvals listen --service",
        "moat approvals listen --service",
        // Started by the service manager, to have it as its parent instead.
        "launchctl submit -l x -- openmoat approvals listen --service",
        "systemd-run --user openmoat approvals listen --service",
    ] {
        let out = sb.moat(&["policy", "check", command]);
        assert_eq!(out.status.code(), Some(DENY), "{command}: {}", text(&out));
        assert!(
            text(&out).contains("kernel-self"),
            "{command}: {}",
            text(&out)
        );
    }
    // Without a terminal the commands refuse, and nothing is written.
    for args in [&["approvals", "install"][..], &["approvals", "uninstall"]] {
        let out = sb.command().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(USAGE), "{args:?}");
        assert!(
            text(&out).contains("must be run by a person"),
            "{}",
            text(&out)
        );
    }
}

#[test]
fn install_needs_a_connected_channel() {
    let sb = Sandbox::installed(&[]);
    let out = run(&sb, &["approvals", "install"]);
    assert_eq!(out.status.code(), Some(USAGE));
    assert!(
        text(&out).contains("no channel is connected"),
        "{}",
        text(&out)
    );
}

/// A credential pasted at `connect` is read, checked and refused without any
/// of it appearing in the output.
#[test]
fn a_credential_typed_at_connect_is_never_shown() {
    let sb = Sandbox::installed(&[]);
    // Made at run time; not a token's shape, so nothing is sent anywhere.
    let secret = format!("not{}a{}token", "-quite-", 4_711);
    let mut child = as_person(sb.command().args(["approvals", "connect", "telegram"]))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{secret}").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
    let shown = text(&out);
    assert!(shown.contains("not a valid token"), "{shown}");
    assert!(!shown.contains(&secret), "{shown}");
    assert!(!shown.contains("-quite-"), "{shown}");
    assert!(!sb.home.join(".moat/remote/telegram/credential").exists());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod service {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use super::{Sandbox, USAGE, as_person, run, text};
    use crate::common::OK;

    #[cfg(target_os = "macos")]
    fn service_file(sb: &Sandbox) -> PathBuf {
        sb.home
            .join("Library/LaunchAgents/dev.openmoat.approvals.plist")
    }
    #[cfg(target_os = "linux")]
    fn service_file(sb: &Sandbox) -> PathBuf {
        sb.home
            .join(".config/systemd/user/openmoat-approvals.service")
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn listen_as_service(sb: &Sandbox, extra: Option<(&str, &str)>) -> super::Output {
        let mut cmd = sb.command();
        as_person(cmd.args(["approvals", "listen", "--service"]));
        if let Some((name, value)) = extra {
            cmd.env(name, value);
        }
        cmd.output().unwrap()
    }

    #[test]
    fn install_writes_the_listener_service_owner_only_and_uninstall_removes_it() {
        let sb = Sandbox::installed(&[]);
        crate::remote_approvals::connect(&sb);
        let path = service_file(&sb);

        // Nothing installed: the service listener has no file to run from.
        let out = listen_as_service(&sb, None);
        assert_eq!(out.status.code(), Some(USAGE));
        assert!(
            text(&out).contains("no service is installed"),
            "{}",
            text(&out)
        );

        let out = run(&sb, &["approvals", "install"]);
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        let written = std::fs::read_to_string(&path).unwrap();
        // The binary the hooks run, as `init` resolved it (canonical).
        let binary = std::fs::canonicalize(env!("CARGO_BIN_EXE_openmoat")).unwrap();
        assert!(
            written.contains(binary.to_string_lossy().as_ref()),
            "{written}"
        );
        assert!(
            written.contains("approvals") && written.contains("--service"),
            "{written}"
        );
        assert!(written.contains(sb.home.join(".moat").to_string_lossy().as_ref()));
        assert_eq!(mode(&path), 0o600);
        let logs = sb.home.join(".moat/logs");
        for log in ["approvals.out.log", "approvals.err.log"] {
            assert_eq!(mode(&logs.join(log)), 0o600, "{log}");
        }
        let status = text(&sb.moat(&["approvals", "status"]));
        assert!(status.contains("approvals service"), "{status}");

        // The file as installed, but not started by the service manager.
        let out = listen_as_service(&sb, None);
        assert_eq!(out.status.code(), Some(USAGE));
        assert!(text(&out).contains("did not start this"), "{}", text(&out));

        // A steered environment is refused before anything else is read.
        for (name, value) in [
            ("SSL_CERT_FILE", "/tmp/attacker-ca.pem"),
            ("DYLD_INSERT_LIBRARIES", "/tmp/x.dylib"),
            ("LD_PRELOAD", "/tmp/x.so"),
        ] {
            let out = listen_as_service(&sb, Some((name, value)));
            assert_eq!(out.status.code(), Some(USAGE), "{name}");
            assert!(text(&out).contains(name), "{}", text(&out));
        }

        // A service file someone changed is not run, and `status` says why.
        let tampered = written.replacen("MOAT_HOME", "MOAT_HOME_X", 1);
        std::fs::write(&path, &tampered).unwrap();
        let out = listen_as_service(&sb, None);
        assert_eq!(out.status.code(), Some(USAGE));
        assert!(
            text(&out).contains("refusing to run from the service file"),
            "{}",
            text(&out)
        );
        let status = text(&sb.moat(&["approvals", "status"]));
        assert!(status.contains("approvals service file"), "{status}");

        let out = run(&sb, &["approvals", "uninstall"]);
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        assert!(!path.exists());
        let status = text(&sb.moat(&["approvals", "status"]));
        assert!(!status.contains("approvals service"), "{status}");
    }

    /// `openmoat uninstall` removes the listener's service with the hooks.
    #[test]
    fn uninstall_removes_the_listener_service() {
        let sb = Sandbox::installed(&[]);
        crate::remote_approvals::connect(&sb);
        assert_eq!(run(&sb, &["approvals", "install"]).status.code(), Some(OK));
        let out = run(&sb, &["uninstall"]);
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        assert!(!service_file(&sb).exists());
        assert!(text(&out).contains("approvals service"), "{}", text(&out));
    }
}

#[cfg(windows)]
#[test]
fn install_refuses_on_windows_with_a_clear_hint() {
    let sb = Sandbox::installed(&[]);
    let out = run(&sb, &["approvals", "listen", "--service"]);
    assert_eq!(out.status.code(), Some(USAGE));
    assert!(text(&out).contains("no user service"), "{}", text(&out));
}
