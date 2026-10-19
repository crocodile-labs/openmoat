//! `moat run` on Linux: Landlock rules generated for the session
//! (`crate::sandbox::landlock`) and a seccomp filter (`crate::sandbox::seccomp`),
//! applied to a thread of its own that starts the agent. Both restrict the
//! calling thread and what it starts, so OpenMoat's proxy thread stays
//! unrestricted and keeps its audit log and its network. With `--isolate`
//! (`linux/isolate.rs`) the agent starts in bubblewrap, and `moat` inside it
//! applies the same rules and filter.

use std::path::Path;
use std::process::{Command, ExitStatus};

use anyhow::{Context as _, Result, bail};
use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetError, Scope, path_beneath_rules,
};
use openmoat_core::{EvalContext, Policy};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};

use crate::sandbox::landlock::Rules;
use crate::sandbox::seccomp::SOCKET_ARGS;
use crate::sandbox::{Grants, Report, exposure, landlock_rules, session_tmpdir};

/// `moat run --isolate`: bubblewrap around the same rules.
mod isolate;

/// The first ABI that restricts TCP connections (Linux 6.7). An older kernel
/// is refused rather than run with the network open.
const ABI_REQUIRED: ABI = ABI::V4;

/// Calls the agent may not make at all. An `io_uring` ring creates sockets
/// (`IORING_OP_SOCKET`) without the `socket()` call the filter checks. ptrace
/// and `process_vm_*` would let a command the agent starts read or change
/// another process in the sandbox, such as the agent and the tokens in its
/// memory; debuggers such as `strace` and `gdb` do not work in here.
const DENIED: [i64; 6] = [
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
];

/// x32 programs on x86-64 make calls under the same architecture, numbered
/// from [`X32`]: the filter refuses their `socket()` and the calls above.
/// A call made under another architecture (32-bit `int 0x80`, which has
/// `socketcall`) kills the process.
#[cfg(target_arch = "x86_64")]
const X32_DENIED: &[i64] = &[41, 425, 426, 427, 521, 539, 540];
#[cfg(not(target_arch = "x86_64"))]
const X32_DENIED: &[i64] = &[];
const X32: i64 = 0x4000_0000;

/// `ioctl()` requests the agent may not make on any file. `TIOCSTI` pushes
/// characters into the input of the terminal the agent shares with the user,
/// whose shell reads and runs them once the agent exits, outside every sandbox
/// (CVE-2017-5226); `TIOCLINUX` does the same on a Linux console through its
/// paste buffer. The kernel reads the request as 32 bits, so does the filter.
const TERMINAL_INPUT: [libc::Ioctl; 2] = [libc::TIOCSTI, libc::TIOCLINUX];

/// `ioctl()` under x32, numbered from [`X32`].
#[cfg(target_arch = "x86_64")]
const X32_IOCTL: &[i64] = &[514];
#[cfg(not(target_arch = "x86_64"))]
const X32_IOCTL: &[i64] = &[];

/// The agent, ready to start in its sandbox.
pub struct Confined {
    command: Command,
    report: Report,
    /// The Landlock rules and seccomp filter of the thread that starts the
    /// agent; `None` under `--isolate`, where `inside` applies them.
    restrict: Option<(RulesetCreated, BpfProgram)>,
    /// What `--isolate` created for the session, removed when it ends.
    _session: Option<isolate::Session>,
}

pub fn confine(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
    program: &Path,
    state: &Path,
) -> Result<Confined> {
    let generated = landlock_rules(policy, ctx, grants)?;
    refuse_exposed(state, &generated.rules, false)?;
    restricted(&generated.rules, generated.report, Command::new(program))
}

pub use isolate::{inside, isolate};

/// Refuse to start where `rules` would show OpenMoat's state directory `state`
/// to the agent: Landlock cannot deny inside a grant (`crate::sandbox::exposure`).
fn refuse_exposed(state: &Path, rules: &Rules, isolated: bool) -> Result<()> {
    let tmpdir = session_tmpdir();
    match exposure::refusal(state, rules, tmpdir.as_deref(), isolated) {
        Some(why) => bail!("{why}"),
        None => Ok(()),
    }
}

/// `command`, to start with `rules` and the seccomp filter applied.
fn restricted(rules: &Rules, report: Report, command: Command) -> Result<Confined> {
    let ports = rules
        .connect_port
        .map(|port| Ok(NetPort::new(port, AccessNet::ConnectTcp)));
    let build = || -> Result<RulesetCreated, RulesetError> {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI_REQUIRED))?
            .handle_access(AccessNet::from_all(ABI_REQUIRED))?
            // Abstract Unix sockets and signals outside the sandbox (Linux
            // 6.12), where the kernel has them.
            .set_compatibility(CompatLevel::BestEffort)
            .scope(Scope::from_all(ABI::V6))?
            .create()?
            .add_rules(path_beneath_rules(
                &rules.read,
                AccessFs::from_read(ABI_REQUIRED),
            ))?
            .add_rules(path_beneath_rules(
                &rules.write,
                AccessFs::from_all(ABI_REQUIRED),
            ))?
            .add_rules(ports)
    };
    let ruleset = build().context("`moat run` needs Landlock ABI 4 (Linux 6.7 or later)")?;
    let filter = seccomp_filter().context("generating the seccomp filter")?;
    Ok(Confined {
        command,
        report,
        restrict: Some((ruleset, filter)),
        _session: None,
    })
}

/// `socket()` only with the values in [`SOCKET_ARGS`], `ioctl()` with none of
/// [`TERMINAL_INPUT`], none of [`DENIED`]: those calls fail with `EPERM`, and
/// every other call is allowed.
fn seccomp_filter() -> Result<BpfProgram> {
    // `socket()` is refused when one argument has none of its values.
    let mut socket = Vec::new();
    for (arg, allowed) in (0..).zip(SOCKET_ARGS) {
        let other = allowed.iter().map(|&value| {
            SeccompCondition::new(arg, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, value.into())
        });
        socket.push(SeccompRule::new(other.collect::<Result<_, _>>()?)?);
    }
    // `ioctl()` is refused when its request is one of them.
    let mut terminal = Vec::new();
    for request in TERMINAL_INPUT {
        let request = argument(request).context("an ioctl request out of range")?;
        let equal = SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, request);
        terminal.push(SeccompRule::new(vec![equal?])?);
    }
    let x32_ioctl = X32_IOCTL.iter().map(|nr| X32 + nr);
    let ioctl = [libc::SYS_ioctl].into_iter().chain(x32_ioctl);
    let ioctl = ioctl.map(|nr| (nr, terminal.clone()));
    let x32 = X32_DENIED.iter().map(|nr| X32 + nr);
    let refused = DENIED.into_iter().chain(x32).map(|nr| (nr, Vec::new()));
    let rules = refused
        .chain(ioctl)
        .chain([(libc::SYS_socket, socket)])
        .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM.unsigned_abs()),
        std::env::consts::ARCH.try_into()?,
    )?;
    Ok(filter.try_into()?)
}

/// `value` as the filter compares arguments. Generic because libc's `Ioctl` is
/// `c_ulong` with glibc and `c_int` with musl, which `moat` is also built for.
fn argument(value: impl TryInto<u64>) -> Option<u64> {
    value.try_into().ok()
}

impl Confined {
    pub fn command(&mut self) -> &mut Command {
        &mut self.command
    }

    pub fn report(&self) -> &Report {
        &self.report
    }

    pub fn status(self) -> Result<ExitStatus> {
        let Self {
            mut command,
            restrict,
            _session,
            ..
        } = self;
        let Some((ruleset, filter)) = restrict else {
            return command.status().context("starting bubblewrap");
        };
        std::thread::spawn(move || {
            ruleset
                .restrict_self()
                .context("applying the Landlock rules")?;
            seccompiler::apply_filter(&filter).context("applying the seccomp filter")?;
            command.status().context("starting the agent")
        })
        .join()
        .ok()
        .context("the thread that starts the agent panicked")?
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, UdpSocket};
    use std::os::unix::net::{UnixDatagram, UnixStream};

    use super::*;

    /// The real filter, on a thread of its own: the test's other threads keep
    /// their sockets.
    #[test]
    fn the_filter_refuses_unix_and_udp_sockets_and_allows_tcp_and_socketpair() {
        let filter = seccomp_filter().expect("the filter compiles");
        let errno = |result: std::io::Result<()>| result.err().and_then(|e| e.raw_os_error());
        let (unix, udp, tcp, pair) = std::thread::spawn(move || {
            seccompiler::apply_filter(&filter).expect("the filter applies");
            (
                errno(UnixDatagram::unbound().map(drop)),
                errno(UdpSocket::bind("127.0.0.1:0").map(drop)),
                errno(TcpListener::bind("127.0.0.1:0").map(drop)),
                errno(UnixStream::pair().map(drop)),
            )
        })
        .join()
        .expect("the filtered thread finishes");
        assert_eq!((unix, udp), (Some(libc::EPERM), Some(libc::EPERM)));
        assert_eq!((tcp, pair), (None, None));
        assert!(
            UdpSocket::bind("127.0.0.1:0").is_ok(),
            "this thread is not filtered"
        );
    }

    /// A child on a terminal of its own (`pty.fork` makes it the controlling
    /// terminal, which TIOCSTI needs) reads the window size, then pushes one
    /// byte into the terminal's input. Exits with TIOCSTI's errno, 0 when it
    /// went through, 255 when TIOCGWINSZ failed.
    const TERMINAL_PROBE: &str = r##"
import fcntl, os, pty, termios
pid, _ = pty.fork()
if pid == 0:
    try:
        fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8))
    except OSError:
        os._exit(255)
    try:
        fcntl.ioctl(0, termios.TIOCSTI, b"#")
        os._exit(0)
    except OSError as e:
        os._exit(e.errno)
_, status = os.waitpid(pid, 0)
os._exit(os.waitstatus_to_exitcode(status))
"##;

    fn terminal_probe() -> Option<i32> {
        Command::new("python3")
            .args(["-c", TERMINAL_PROBE])
            .status()
            .expect("python3 runs")
            .code()
    }

    /// The real filter, on a thread of its own, on a terminal the test opens.
    #[test]
    fn the_filter_refuses_terminal_input_and_allows_other_terminal_calls() {
        let filter = seccomp_filter().expect("the filter compiles");
        let filtered = std::thread::spawn(move || {
            seccompiler::apply_filter(&filter).expect("the filter applies");
            terminal_probe()
        })
        .join()
        .expect("the filtered thread finishes");
        assert_eq!(filtered, Some(libc::EPERM));
        // Unfiltered, TIOCSTI goes through, or fails with EIO where the kernel
        // refuses it itself (`dev.tty.legacy_tiocsti=0`): never the filter's EPERM.
        assert!(matches!(terminal_probe(), Some(0 | libc::EIO)));
    }
}
