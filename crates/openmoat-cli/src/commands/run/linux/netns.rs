//! `moat run` on Linux without `--isolate`: a network namespace of the
//! agent's own, where bubblewrap can make one.
//!
//! Landlock restricts TCP connections by port only (`NetPort`), and a seccomp
//! filter cannot read the address `connect()` is given, which it gets as a
//! pointer. With those two alone a command could reach any host on the
//! proxy's port and go around the proxy. So the agent starts in new user and
//! network namespaces whose only interface is loopback. Nothing else changes:
//! the whole root is bound in as it is, there is no PID namespace, and the same
//! Landlock rules and seccomp filter apply inside. `moat isolated` serves the
//! proxy's port on that loopback and relays each connection over a Unix socket
//! to the proxy outside, as under `--isolate`.
//!
//! Where bubblewrap is missing or cannot create the namespaces, `moat run`
//! starts with Landlock and seccomp alone and says so on every start, and
//! `moat doctor` warns; with `--netns=require` it refuses to start instead.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result};

use super::isolate::{Session, relay_to_proxy, system_bwrap};
use super::{Confined, Rules};
use crate::context::path_string;
use crate::sandbox::Report;
use crate::sandbox::bwrap::{self, Mount};
use crate::sandbox::landlock::TCP_PORT_ALLOWANCE;

/// The namespaces: a user namespace, needed to create the network one
/// unprivileged, and the network namespace, where bubblewrap brings up
/// loopback alone.
const UNSHARE: [&str; 3] = ["--unshare-user", "--unshare-net", "--die-with-parent"];

/// The whole root, devices included, at the same paths.
const ROOT: [&str; 3] = ["--dev-bind", "/", "/"];

/// bubblewrap's monitoring process stays in the terminal's foreground group
/// and dies of Ctrl-C's `SIGINT`, which would end the agent through
/// `--die-with-parent`. The shell ignores `SIGINT` for it (ignored signals stay
/// ignored across `exec`); `moat isolated` handles `SIGINT` itself, so the
/// agent it starts gets the default back and decides what Ctrl-C means.
const IGNORE_INTERRUPT: &str = "trap '' INT; exec \"$0\" \"$@\"";

/// How the agent's network is confined.
#[derive(Debug, PartialEq, Eq)]
pub enum Network {
    /// A network namespace with loopback alone, made by this bubblewrap.
    Namespace(PathBuf),
    /// The machine's network, with connections limited to the proxy's port
    /// on every host; why there is no namespace.
    PortOnly(String),
}

/// This machine's choice.
pub fn network() -> Network {
    decide(system_bwrap(), refused)
}

/// A namespace where `bwrap` exists and `refused` finds no reason it cannot
/// make one.
fn decide(bwrap: Option<PathBuf>, refused: impl FnOnce(&Path) -> Option<String>) -> Network {
    let Some(bwrap) = bwrap else {
        return Network::PortOnly(
            "bubblewrap is not installed (`bwrap` in /usr/bin, /bin or /usr/local/bin)".to_owned(),
        );
    };
    match refused(&bwrap) {
        None => Network::Namespace(bwrap),
        Some(why) => Network::PortOnly(format!(
            "bubblewrap cannot create a network namespace here ({why}; unprivileged user \
             namespaces must be allowed, and on Ubuntu 24.04 AppArmor restricts them: \
             kernel.apparmor_restrict_unprivileged_userns)"
        )),
    }
}

/// Why `bwrap` cannot create [`UNSHARE`]'s namespaces, if it cannot.
fn refused(bwrap: &Path) -> Option<String> {
    let out = Command::new(bwrap)
        .args(UNSHARE)
        .args(ROOT)
        .arg("--")
        .arg(bwrap)
        .arg("--version")
        .output();
    match out {
        Ok(out) if out.status.success() => None,
        Ok(out) => Some(String::from_utf8_lossy(&out.stderr).trim().to_owned()),
        Err(error) => Some(format!("starting {}: {error}", bwrap.display())),
    }
}

/// What `moat run` prints on every start without a namespace (`why`), naming
/// the `masks` only a namespace could have applied.
pub fn port_only_notice(port: u16, why: &str, masks: &[Mount]) -> String {
    let mut notice = format!(
        "moat run: the network is restricted by port only: {why}, so a command in the sandbox \
         can reach any host on port {port} and go around the proxy's checks and audit. With \
         bubblewrap (`apt install bubblewrap`) `openmoat run` gives the agent a network of its own \
         whose only exit is the proxy; `openmoat run --isolate` needs it too and also hides the \
         rest of the machine"
    );
    let open: Vec<&str> = masks
        .iter()
        .filter_map(|m| match m {
            Mount::ReadOnly(p) | Mount::Hide { path: p, .. } => Some(p.as_str()),
            Mount::ReadWrite(_) | Mount::Tmpfs(_) => None,
        })
        .collect();
    if !open.is_empty() {
        notice = format!(
            "{notice}.\nmoat run: without it, these paths the policy denies stay open to \
             commands, because a read root or `--write` path holds them: {}",
            open.join(", ")
        );
    }
    notice
}

/// What `moat doctor` warns where there is no namespace, if there is none.
pub fn doctor_warning() -> Option<String> {
    match network() {
        Network::Namespace(_) => None,
        Network::PortOnly(why) => Some(format!(
            "openmoat run     network restricted by port only: {why}; commands could reach any \
             host on the proxy's port. Install bubblewrap for a network namespace (also needed \
             by `openmoat run --isolate`)"
        )),
    }
}

/// `program` under `bwrap` in its own network namespace, `moat isolated`
/// applying `rules` inside, in `cwd`, with the proxy on `port` relayed in and
/// `masks` over the denied paths inside the grants.
pub fn namespaced(
    bwrap: &Path,
    rules: &Rules,
    masks: &[Mount],
    mut report: Report,
    program: &Path,
    cwd: &str,
    port: u16,
) -> Result<Confined> {
    report.allowances.retain(|a| a.rule != TCP_PORT_ALLOWANCE);
    let session = Session::create(&[])?;
    relay_to_proxy(&session.socket, port)?;
    let moat = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("locating the moat binary")?;
    let (blank_file, blank_dir) = session.blanks();
    let masks = bwrap::args(masks, &blank_file, &blank_dir);
    let mut command = Command::new("/bin/sh");
    command.args(arguments(
        bwrap,
        &moat,
        &session.socket,
        port,
        &serde_json::to_string(rules)?,
        cwd,
        &masks,
    ));
    command.arg(program);
    Ok(Confined {
        command,
        report,
        restrict: None,
        _session: Some(session),
        warning: None,
    })
}

/// `/bin/sh`'s arguments up to the agent; `masks` are bubblewrap's mount
/// arguments over the whole root.
fn arguments(
    bwrap: &Path,
    moat: &Path,
    socket: &Path,
    port: u16,
    rules: &str,
    cwd: &str,
    masks: &[String],
) -> Vec<String> {
    let mut args = vec![
        "-c".to_owned(),
        IGNORE_INTERRUPT.to_owned(),
        path_string(bwrap),
    ];
    args.extend(UNSHARE.map(str::to_owned));
    args.extend(ROOT.map(str::to_owned));
    args.extend(masks.iter().cloned());
    args.extend(["--chdir", cwd, "--"].map(str::to_owned));
    args.extend([
        path_string(moat),
        "isolated".to_owned(),
        "--socket".to_owned(),
    ]);
    args.push(path_string(socket));
    args.extend(["--port".to_owned(), port.to_string(), "--rules".to_owned()]);
    args.extend([rules.to_owned(), "--".to_owned()]);
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_working_bubblewrap_gives_a_namespace() {
        let bwrap = PathBuf::from("/usr/bin/bwrap");
        let chosen = decide(Some(bwrap.clone()), |_| None);
        assert_eq!(chosen, Network::Namespace(bwrap));
    }

    #[test]
    fn without_bubblewrap_the_network_is_port_only_and_says_why() {
        let Network::PortOnly(why) = decide(None, |_| unreachable!("nothing to probe")) else {
            panic!("no bubblewrap, no namespace");
        };
        assert!(why.contains("bubblewrap is not installed"), "{why}");
        let notice = port_only_notice(41_000, &why, &[]);
        for expected in [
            "restricted by port only",
            "any host on port 41000",
            "apt install bubblewrap",
            "openmoat run --isolate",
        ] {
            assert!(notice.contains(expected), "{expected}: {notice}");
        }
        assert!(!notice.contains("stay open"), "{notice}");
        let masks = [
            Mount::ReadWrite("/home/me/.claude".into()),
            Mount::ReadOnly("/home/me/.claude/settings.json".into()),
        ];
        let notice = port_only_notice(41_000, &why, &masks);
        assert!(
            notice.contains("stay open to commands")
                && notice.ends_with(": /home/me/.claude/settings.json"),
            "{notice}"
        );
    }

    #[test]
    fn a_bubblewrap_that_cannot_make_namespaces_is_port_only_with_its_reason() {
        let bwrap = PathBuf::from("/usr/bin/bwrap");
        let chosen = decide(Some(bwrap), |_| {
            Some("setting up uid map: Permission denied".to_owned())
        });
        let Network::PortOnly(why) = chosen else {
            panic!("a refused namespace is not used");
        };
        assert!(why.contains("uid map: Permission denied"), "{why}");
        assert!(
            why.contains("apparmor_restrict_unprivileged_userns"),
            "{why}"
        );
    }

    /// The namespace holds the whole root and the agent starts through
    /// `moat isolated`, which serves the proxy's port inside.
    #[test]
    fn bubblewrap_gets_a_network_namespace_over_the_whole_root() {
        let args = arguments(
            Path::new("/usr/bin/bwrap"),
            Path::new("/opt/moat"),
            Path::new("/tmp/moat-run-1/proxy.sock"),
            41_000,
            "{}",
            "/work/project",
            &[
                "--ro-bind-try".to_owned(),
                "/home/me/.claude/settings.json".to_owned(),
                "/home/me/.claude/settings.json".to_owned(),
            ],
        );
        let expected = [
            "-c",
            IGNORE_INTERRUPT,
            "/usr/bin/bwrap",
            "--unshare-user",
            "--unshare-net",
            "--die-with-parent",
            "--dev-bind",
            "/",
            "/",
            // the masks over the whole root, after it
            "--ro-bind-try",
            "/home/me/.claude/settings.json",
            "/home/me/.claude/settings.json",
            "--chdir",
            "/work/project",
            "--",
            "/opt/moat",
            "isolated",
            "--socket",
            "/tmp/moat-run-1/proxy.sock",
            "--port",
            "41000",
            "--rules",
            "{}",
            "--",
        ];
        assert_eq!(args, expected);
        assert!(
            !args
                .iter()
                .any(|a| a == "--unshare-all" || a == "--unshare-pid")
        );
    }

    /// The shell runs bubblewrap with its arguments as given and `SIGINT`
    /// ignored.
    #[test]
    fn the_shell_execs_bubblewrap_with_sigint_ignored() {
        let out = Command::new("/bin/sh")
            .args(["-c", IGNORE_INTERRUPT, "/bin/sh", "-c"])
            .arg("grep '^SigIgn' /proc/self/status; echo \"$0|$1\"")
            .args(["first arg", "second"])
            .output()
            .expect("sh runs");
        let shown = String::from_utf8_lossy(&out.stdout);
        assert!(shown.contains("first arg|second"), "{shown}");
        let ignored = shown
            .lines()
            .find_map(|l| l.strip_prefix("SigIgn:"))
            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .expect("the mask");
        assert_ne!(ignored & (1 << (libc::SIGINT - 1)), 0, "{shown}");
    }
}
