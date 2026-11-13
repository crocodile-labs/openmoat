//! Files open in whatever starts `openmoat run` stay out of the sandbox
//! (ADR-088). The launcher here is `bash`, which opens a file the policy
//! denies on descriptors 3 and 42 without close-on-exec, as a shell, an IDE or
//! a CI runner can; the command inside then reads both. Without the sweep it
//! would read the file through them: Landlock and Seatbelt check a path when
//! it is opened, not a descriptor opened before.

use std::path::Path;
use std::process::Output;

#[cfg(target_os = "linux")]
use super::confined::isolated;
use super::confined::ran;
use super::{LIGHTWEIGHT, installed_with_secret};
use crate::common::{OK, Sandbox, output, stdout, text};

/// Reads descriptors 3 and 42 by redirection and by `/dev/fd`, printing each
/// status.
const PROBE: &str = "for fd in 3 42; do
  cat <&$fd; echo \"fd$fd=$?\"
  cat /dev/fd/$fd; echo \"path$fd=$?\"
done";

/// The launcher: opens `$0` on descriptors 3 and 42, inheritable, then runs
/// the rest of its arguments.
const LAUNCHER: &str = "exec 3<\"$0\" 42<\"$0\"; exec \"$@\"";

/// A secret file in the home's `.ssh`, which the policy denies; made for the test.
fn secret(sb: &Sandbox) -> (std::path::PathBuf, String) {
    let value = format!("FAKE-INHERITED-FD-SECRET-{}", std::process::id());
    let path = sb.home.join(".ssh/inherited_key");
    std::fs::write(&path, &value).unwrap();
    (path, value)
}

/// [`LAUNCHER`] around `program`, in `project`, with the test's environment.
fn launch(sb: &Sandbox, project: &Path, secret: &Path, program: &[&str]) -> Output {
    let tmp = sb.home.with_file_name("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    output(
        sb.configure(std::process::Command::new("/bin/bash"))
            .current_dir(project)
            .env("TMPDIR", &tmp)
            .args(["-c", LAUNCHER])
            .arg(secret)
            .args(program),
        None,
    )
}

/// `openmoat run <flags> -- /bin/bash -c PROBE` under [`LAUNCHER`].
fn run_probe(sb: &Sandbox, project: &Path, secret: &Path, flags: &[&str]) -> Output {
    let moat = env!("CARGO_BIN_EXE_openmoat");
    let mut program = vec![moat, "run"];
    program.extend(flags);
    program.extend(["--", "/bin/bash", "-c", PROBE]);
    launch(sb, project, secret, &program)
}

/// The control: without `openmoat run` the probe reads the secret through
/// both descriptors, so the launcher really leaves them inheritable.
fn check_control(sb: &Sandbox, project: &Path, secret: &Path, value: &str) {
    let out = launch(sb, project, secret, &["/bin/bash", "-c", PROBE]);
    let shown = text(&out);
    assert!(stdout(&out).contains("fd3=0"), "{shown}");
    assert!(stdout(&out).contains("fd42=0"), "{shown}");
    assert!(
        shown.contains(value),
        "the launcher passes the file on: {shown}"
    );
}

/// Neither descriptor reaches the command: each redirection fails with
/// `EBADF`, and the secret's bytes are nowhere in the output.
fn check_refused(out: &Output, value: &str) {
    let shown = text(out);
    assert_eq!(out.status.code(), Some(OK), "{shown}");
    for fd in [3, 42] {
        assert!(!stdout(out).contains(&format!("fd{fd}=0")), "{fd}: {shown}");
        assert!(
            !stdout(out).contains(&format!("path{fd}=0")),
            "{fd}: {shown}"
        );
    }
    // One per redirection; bash 3.2 (macOS) names the wrong descriptor in it,
    // and `/dev/fd/<n>` is ENOENT on Linux, where it is a `/proc` link.
    assert!(
        shown.matches("Bad file descriptor").count() >= 2,
        "EBADF on both: {shown}"
    );
    assert!(!shown.contains(value), "{shown}");
}

/// The attack, in the Lightweight tier (Seatbelt on macOS, Landlock and
/// seccomp on Linux).
// protection: credentials every linux,macos
#[test]
fn descriptors_the_launcher_left_open_do_not_reach_a_command() {
    let (sb, project) = installed_with_secret();
    let (path, value) = secret(&sb);
    check_control(&sb, &project, &path, &value);
    let out = run_probe(&sb, &project, &path, &[LIGHTWEIGHT]);
    if !ran(&out) {
        return;
    }
    check_refused(&out, &value);
}

/// The same in the Isolated tier: bubblewrap passes every open descriptor on,
/// so `openmoat run` marks them before it starts bubblewrap and again inside.
#[cfg(target_os = "linux")]
#[test]
fn descriptors_the_launcher_left_open_do_not_reach_a_command_under_isolate() {
    let (sb, project) = installed_with_secret();
    let (path, value) = secret(&sb);
    check_control(&sb, &project, &path, &value);
    let out = run_probe(&sb, &project, &path, &["--isolate"]);
    if !ran(&out) || !isolated(&out) {
        return;
    }
    check_refused(&out, &value);
}
