//! `moat run --isolate` on Linux: the Isolated tier (ADR-018) with
//! bubblewrap, rootless and without a daemon or an image.
//!
//! bubblewrap starts the agent in new user, mount, PID, IPC, UTS, cgroup and
//! network namespaces. Its root holds only the mounts `crate::sandbox::bwrap`
//! generates: the project with its denied paths covered, the read roots,
//! `--write` paths and an empty temp directory. The network namespace has only
//! loopback. `moat` itself runs first inside it (`moat isolated`): it serves
//! the proxy's port on that loopback and relays each connection over a Unix
//! socket bound in from outside, where this process relays it on to the proxy.
//! Then it applies the same Landlock rules and seccomp filter as the
//! Lightweight tier to a thread of its own, which starts the agent.

use std::fs::{DirBuilder, File, Permissions};
use std::io;
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context as _, Result, bail};
use openmoat_core::{EvalContext, Policy};

use super::{Confined, Rules, refuse_exposed, restricted};
use crate::cli::IsolatedArgs;
use crate::context::path_string;
use crate::exit::Code;
use crate::sandbox::{Grants, Report, bwrap, bwrap_mounts};

/// Where bubblewrap is taken from. Not `PATH`: `bwrap` starts unconfined and
/// builds the sandbox, so a `bwrap` a project ships (a relative `PATH` entry,
/// `node_modules/.bin`) must never be the one that runs.
const BWRAP_DIRS: [&str; 3] = ["/usr/bin", "/bin", "/usr/local/bin"];

/// The system's bubblewrap, symlinks resolved.
pub(super) fn system_bwrap() -> Option<PathBuf> {
    let dirs: Vec<PathBuf> = BWRAP_DIRS.iter().map(PathBuf::from).collect();
    crate::environment::find_in(&dirs, &[], "bwrap").and_then(|p| std::fs::canonicalize(p).ok())
}

/// Namespaces bubblewrap creates; a user namespace is required, not tried.
const UNSHARE: [&str; 3] = ["--unshare-all", "--unshare-user", "--die-with-parent"];

/// Keeps the agent from creating user namespaces of its own inside the
/// sandbox. bubblewrap 0.8 and later know it; an older one refuses to start
/// with it, so it is passed only when [`usable`] found it accepted.
const DISABLE_USERNS: &str = "--disable-userns";

/// [`UNSHARE`], with [`DISABLE_USERNS`] when this bubblewrap knows it.
fn unshare(disable_userns: bool) -> Vec<&'static str> {
    let mut args = UNSHARE.to_vec();
    if disable_userns {
        args.push(DISABLE_USERNS);
    }
    args
}

pub fn isolate(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
    program: &Path,
    state: &Path,
) -> Result<Confined> {
    let bwrap = system_bwrap().context(
        "`moat run --isolate` needs bubblewrap (`bwrap` in /usr/bin, /bin or /usr/local/bin; \
         `apt install bubblewrap`); refusing rather than starting the agent in a weaker tier",
    )?;
    let disable_userns = usable(&bwrap)?;
    let port = grants.proxy_port.context("no proxy port")?;
    let generated = bwrap_mounts(policy, ctx, grants)?;
    // The mounts hide the state directory only under the empty temp directory.
    refuse_exposed(state, &generated.rules, true)?;
    let session = Session::create(&generated.placeholders)?;
    relay_to_proxy(&session.socket, port)?;
    let moat = std::env::current_exe().and_then(std::fs::canonicalize)?;
    let (moat, dir) = (path_string(&moat), path_string(&session.dir));
    let mut command = Command::new(&bwrap);
    command
        .args(unshare(disable_userns))
        .args(["--dev", "/dev", "--proc", "/proc"])
        .args(bwrap::args(
            &generated.mounts,
            &path_string(&session.dir.join("file")),
            &path_string(&session.dir.join("dir")),
        ))
        // Read-only: connecting to the socket needs no write access to the
        // mount, and the placeholders stay as they are.
        .args(["--ro-bind", &moat, &moat, "--ro-bind", &dir, &dir])
        .args(["--chdir", &ctx.cwd, "--", &moat, "isolated", "--socket"])
        .arg(&session.socket)
        .args(["--port", &port.to_string(), "--rules"])
        .arg(serde_json::to_string(&generated.rules)?)
        .arg("--")
        .arg(program);
    Ok(Confined {
        command,
        report: generated.report,
        restrict: None,
        _session: Some(session),
        warning: None,
    })
}

/// Outside the sandbox: relay each connection to `socket` on to the proxy's
/// `port` on loopback.
pub(super) fn relay_to_proxy(socket: &Path, port: u16) -> Result<()> {
    let listener =
        UnixListener::bind(socket).with_context(|| format!("listening on {}", socket.display()))?;
    std::thread::spawn(move || {
        for unix in listener.incoming().flatten() {
            std::thread::spawn(move || {
                if let Ok(tcp) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)) {
                    splice(&tcp, &unix);
                }
            });
        }
    });
    Ok(())
}

/// Refuse, with bubblewrap's reason, where it cannot create the namespaces:
/// a kernel or distribution that restricts unprivileged user namespaces.
/// Otherwise whether it accepts [`DISABLE_USERNS`]: tried first, and only
/// when that fails is the sandbox tried without it.
fn usable(bwrap: &Path) -> Result<bool> {
    let probe = |disable_userns: bool| {
        Command::new(bwrap)
            .args(unshare(disable_userns))
            .args(["--ro-bind", "/", "/", "--"])
            .arg(bwrap)
            .arg("--version")
            .output()
            .with_context(|| format!("starting {}", bwrap.display()))
    };
    if probe(true)?.status.success() {
        return Ok(true);
    }
    let out = probe(false)?;
    if !out.status.success() {
        bail!(
            "bubblewrap cannot create its namespaces here, so `moat run --isolate` refuses: {}\
             (unprivileged user namespaces must be allowed; on Ubuntu 24.04 AppArmor restricts \
             them: kernel.apparmor_restrict_unprivileged_userns)",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(false)
}

/// Inside the sandbox: relay the proxy's port to the socket, then start the
/// agent with the Landlock rules and seccomp filter applied.
pub fn inside(args: &IsolatedArgs) -> Result<Code> {
    let rules: Rules = serde_json::from_str(&args.rules).context("reading the Landlock rules")?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, args.port))
        .context("listening on the proxy's port inside the sandbox")?;
    let socket = args.socket.clone();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let socket = socket.clone();
            std::thread::spawn(move || {
                if let Ok(unix) = UnixStream::connect(&socket) {
                    splice(&tcp, &unix);
                }
            });
        }
    });
    // Ctrl-C belongs to the agent, as outside.
    signal_hook::flag::register(
        signal_hook::consts::SIGINT,
        Arc::new(AtomicBool::new(false)),
    )
    .context("keeping OpenMoat running on Ctrl-C")?;
    let (program, rest) = args.command.split_first().context("no agent to run")?;
    let mut agent = restricted(&rules, Report::default(), Command::new(program))?;
    agent.command().args(rest);
    let status = agent.status()?;
    Ok(if status.success() {
        Code::Ok
    } else {
        Code::Failed
    })
}

/// Copy both ways between `tcp` and `unix`; each side's end of data closes
/// the other's sending half.
fn splice(tcp: &TcpStream, unix: &UnixStream) {
    let (Ok(tcp_out), Ok(unix_in)) = (tcp.try_clone(), unix.try_clone()) else {
        return;
    };
    let back = std::thread::spawn(move || {
        let _ = io::copy(&mut &unix_in, &mut &tcp_out);
        let _ = tcp_out.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut &*tcp, &mut &*unix);
    let _ = unix.shutdown(Shutdown::Write);
    let _ = back.join();
}

/// A private directory for the session (mode `0700`) with the proxy's socket
/// and the placeholders hidden paths are covered with (mode `000`), and the
/// placeholders created in the project. All are removed when it drops.
pub struct Session {
    dir: PathBuf,
    pub(super) socket: PathBuf,
    placeholders: Vec<PathBuf>,
}

impl Session {
    pub(super) fn create(placeholders: &[String]) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!("moat-run-{}", std::process::id()));
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let mut session = Self {
            socket: dir.join("proxy.sock"),
            dir,
            placeholders: Vec::new(),
        };
        File::create_new(session.dir.join("file"))?
            .set_permissions(Permissions::from_mode(0o000))?;
        std::fs::create_dir(session.dir.join("dir"))?;
        std::fs::set_permissions(session.dir.join("dir"), Permissions::from_mode(0o000))?;
        for path in placeholders {
            File::create_new(path).with_context(|| format!("creating a placeholder at {path}"))?;
            session.placeholders.push(PathBuf::from(path));
        }
        Ok(session)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        for path in &self.placeholders {
            // Only while it is still the empty file this session created.
            if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.len() == 0) {
                let _ = std::fs::remove_file(path);
            }
        }
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(self.dir.join("file"));
        let _ = std::fs::remove_dir(self.dir.join("dir"));
        let _ = std::fs::remove_dir(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::{DISABLE_USERNS, UNSHARE, unshare};

    #[test]
    fn user_namespaces_are_disabled_only_where_bubblewrap_knows_how() {
        let with = unshare(true);
        assert_eq!(with[..UNSHARE.len()], UNSHARE);
        assert_eq!(with.last(), Some(&DISABLE_USERNS));
        // `--disable-userns` needs the user namespace bubblewrap creates.
        assert!(with.contains(&"--unshare-user"));
        assert_eq!(unshare(false), UNSHARE.to_vec());
    }
}
