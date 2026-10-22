//! `moat run` on Linux: Landlock rules generated for the session
//! (`crate::sandbox::landlock`) and a seccomp filter (`crate::sandbox::seccomp`),
//! applied to a thread of its own that starts the agent. Both restrict the
//! calling thread and what it starts, so OpenMoat's proxy thread stays
//! unrestricted and keeps its audit log and its network. Landlock limits TCP by
//! port only, so where bubblewrap can make one the agent also gets a network
//! namespace of its own (`linux/netns.rs`), and `moat` inside it applies the
//! rules and filter; elsewhere `moat run` says the network is restricted by port
//! only. With `--isolate` (`linux/isolate.rs`) the agent starts in bubblewrap's
//! own view of the machine, and `moat` inside it applies the same rules and filter.

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
use crate::sandbox::{
    Grants, Report, exposure, kernel_self_in_writes, landlock_rules, netns_masks,
    netns_project_masks, session_tmpdir,
};

/// `moat run --isolate`: bubblewrap around the same rules.
mod isolate;
/// `moat run`: the agent's own network namespace, where bubblewrap runs.
mod netns;

/// The first ABI that restricts TCP connections (Linux 6.7). An older kernel
/// is refused rather than run with the network open.
const ABI_REQUIRED: ABI = ABI::V4;

/// Calls the agent may not make at all. An `io_uring` ring creates sockets
/// (`IORING_OP_SOCKET`) without the `socket()` call the filter checks. ptrace
/// and `process_vm_*` would let a command the agent starts read or change
/// another process in the sandbox, such as the agent and the tokens in its
/// memory; debuggers such as `strace` and `gdb` do not work in here. The
/// kernel keyrings (`keyctl`, `add_key`, `request_key`) hold the person's
/// session keys (Kerberos tickets, filesystem keys), which Landlock does not
/// cover. `setns()` joins a namespace that exists already (another of the
/// person's containers, through `/proc/<pid>/ns`), which [`CLONE_NAMESPACES`]
/// keeps the agent from creating.
const DENIED: [i64; 10] = [
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_setns,
];

/// The flags that make `clone()` and `unshare()` create a namespace (mount,
/// cgroup, UTS, IPC, user, PID, network). A new user namespace gives a command
/// every capability inside it and a fresh view in which to mount over what
/// the sandbox hides; the others need it unprivileged. Containers, Chromium's
/// own sandbox and bubblewrap cannot start in here.
const CLONE_NAMESPACES: [u64; 7] = [
    0x0002_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
];

/// `CLONE_NEWTIME`, which `unshare()` takes too; in `clone()`'s flags that bit
/// is part of the exit signal.
const CLONE_NEWTIME: u64 = 0x80;

/// x32 programs on x86-64 make calls under the same architecture, numbered
/// from [`X32`]: the filter refuses their `socket()` and the calls above.
/// A call made under another architecture (32-bit `int 0x80`, which has
/// `socketcall`) kills the process.
#[cfg(target_arch = "x86_64")]
const X32_DENIED: &[i64] = &[41, 425, 426, 427, 521, 539, 540, 248, 249, 250, 308];
#[cfg(not(target_arch = "x86_64"))]
const X32_DENIED: &[i64] = &[];
const X32: i64 = 0x4000_0000;

/// `clone()`, `unshare()` and `clone3()` under x32, numbered from [`X32`].
#[cfg(target_arch = "x86_64")]
const X32_NAMESPACE_CALLS: [&[i64]; 3] = [&[56], &[272], &[435]];
#[cfg(not(target_arch = "x86_64"))]
const X32_NAMESPACE_CALLS: [&[i64]; 3] = [&[], &[], &[]];

/// `ioctl()` requests the agent may not make on any file. `TIOCSTI` pushes
/// characters into the input of the terminal the agent shares with the user,
/// whose shell reads and runs them once the agent exits, outside every sandbox
/// (CVE-2017-5226); `TIOCLINUX` does the same on a Linux console through its
/// paste buffer. The kernel reads the request as 32 bits, so does the filter.
const TERMINAL_INPUT: [libc::Ioctl; 2] = [libc::TIOCSTI, libc::TIOCLINUX];

/// Calls that send on a socket, with the index of their `flags` argument.
/// With `MSG_FASTOPEN` such a call connects an unconnected TCP socket itself
/// (TCP Fast Open, `tcp_sendmsg_fastopen`), without the `connect()` whose LSM
/// hook Landlock's port rule checks; refused, so where the network is
/// restricted by port only a command cannot reach another port that way.
const SENDS: [(i64, u8); 3] = [
    (libc::SYS_sendto, 3),
    (libc::SYS_sendmsg, 2),
    (libc::SYS_sendmmsg, 3),
];

/// The same calls under x32, numbered from [`X32`].
#[cfg(target_arch = "x86_64")]
const X32_SENDS: &[(i64, u8)] = &[(44, 3), (518, 2), (538, 3)];
#[cfg(not(target_arch = "x86_64"))]
const X32_SENDS: &[(i64, u8)] = &[];

/// `ioctl()` under x32, numbered from [`X32`].
#[cfg(target_arch = "x86_64")]
const X32_IOCTL: &[i64] = &[514];
#[cfg(not(target_arch = "x86_64"))]
const X32_IOCTL: &[i64] = &[];

/// The agent, ready to start in its sandbox.
pub struct Confined {
    command: Command,
    report: Report,
    /// The Landlock rules and seccomp filters of the thread that starts the
    /// agent; `None` under bubblewrap, where `inside` applies them.
    restrict: Option<(RulesetCreated, Vec<BpfProgram>)>,
    /// What bubblewrap's session created, removed when it ends.
    _session: Option<isolate::Session>,
    /// Where the sandbox is weaker than `moat run` promises: printed before
    /// the agent starts.
    warning: Option<String>,
}

pub fn confine(
    policy: &Policy,
    ctx: &EvalContext,
    grants: Grants,
    program: &Path,
    state: &Path,
) -> Result<Confined> {
    let port = grants.proxy_port;
    let writes = grants.writes.clone();
    let generated = landlock_rules(policy, ctx, grants)?;
    refuse_exposed(state, &generated.rules, false)?;
    // Built here also where `inside` applies them: a kernel without Landlock
    // ABI 4 is refused before anything starts.
    let mut agent = restricted(&generated.rules, generated.report, Command::new(program))?;
    let Some(port) = port else {
        // No port: Landlock allows no TCP connection at all.
        return Ok(agent);
    };
    // What the deny rules name inside the read roots and `--write` paths,
    // which Landlock grants whole.
    let masks = netns_masks(policy, ctx, &generated.rules)?;
    match netns::network() {
        netns::Network::Namespace(bwrap) => {
            // The agent configuration and hook settings in the project,
            // read-only where they exist, and the folders holding them pinned.
            let mut masks = masks;
            masks.extend(netns_project_masks(policy, ctx)?);
            netns::namespaced(
                &bwrap,
                &generated.rules,
                &masks,
                agent.report,
                program,
                &ctx.cwd,
                port,
            )
        }
        netns::Network::PortOnly(why) => {
            // Only the namespace's mounts keep these from commands inside a
            // `--write` path: without it, refuse rather than leave them open.
            let held = kernel_self_in_writes(policy, ctx, &writes)?;
            if let Some(refusal) = exposure::kernel_self_refusal(&held, &why) {
                bail!("{refusal}");
            }
            agent.warning = Some(netns::port_only_notice(port, &why, &masks));
            Ok(agent)
        }
    }
}

/// Why `moat run` here would restrict the network by port only, for `moat doctor`.
pub fn port_only_network() -> Option<String> {
    netns::doctor_warning()
}

pub use isolate::{inside, isolate};

/// The terminals this process's standard input, output and error are on, as
/// `/proc` names them (`/dev/pts/3`, `/dev/tty1`); not `/dev/tty` itself.
pub fn terminals() -> Vec<String> {
    use std::os::unix::fs::FileTypeExt as _;

    let mut found = Vec::new();
    for fd in 0..3 {
        let Ok(path) = std::fs::read_link(format!("/proc/self/fd/{fd}")) else {
            continue;
        };
        let path = crate::context::path_string(&path);
        let name = path.strip_prefix("/dev/").unwrap_or_default();
        let named = name
            .strip_prefix("pts/")
            .is_some_and(|n| n != "ptmx" && !n.contains('/'))
            || (name.starts_with("tty") && name != "tty" && !name.contains('/'));
        let device = std::fs::metadata(&path).is_ok_and(|m| m.file_type().is_char_device());
        if named && device && !found.contains(&path) {
            found.push(path);
        }
    }
    found
}

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
    let ruleset = build().context("`openmoat run` needs Landlock ABI 4 (Linux 6.7 or later)")?;
    let filters = seccomp_filters().context("generating the seccomp filter")?;
    Ok(Confined {
        command,
        report,
        restrict: Some((ruleset, filters)),
        _session: None,
        warning: None,
    })
}

/// The filters, applied in order: [`seccomp_filter`], then [`clone3_filter`].
fn seccomp_filters() -> Result<Vec<BpfProgram>> {
    Ok(vec![seccomp_filter()?, clone3_filter()?])
}

/// `clone3()` passes its flags in memory, which a filter cannot read, so it
/// fails with `ENOSYS`, as on a kernel without it: the C libraries then fall
/// back to `clone()`, whose flags [`seccomp_filter`] reads.
fn clone3_filter() -> Result<BpfProgram> {
    let x32 = X32_NAMESPACE_CALLS[2].iter().map(|nr| X32 + nr);
    let calls = [libc::SYS_clone3].into_iter().chain(x32);
    let filter = SeccompFilter::new(
        calls.map(|nr| (nr, Vec::new())).collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS.unsigned_abs()),
        std::env::consts::ARCH.try_into()?,
    )?;
    Ok(filter.try_into()?)
}

/// One rule per flag in `flags`: the call is refused when its first argument
/// has any of them.
fn any_flag(flags: &[u64]) -> Result<Vec<SeccompRule>> {
    flags
        .iter()
        .map(|&flag| {
            let set = SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(flag),
                flag,
            )?;
            Ok(SeccompRule::new(vec![set])?)
        })
        .collect()
}

/// `socket()` only with the values in [`SOCKET_ARGS`], `ioctl()` with none of
/// [`TERMINAL_INPUT`], [`SENDS`] without `MSG_FASTOPEN`, `clone()` and
/// `unshare()` with none of [`CLONE_NAMESPACES`], none of [`DENIED`]: those
/// calls fail with `EPERM`, and every other call is allowed.
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
    // A send is refused when its flags hold `MSG_FASTOPEN`.
    let fast_open = argument(libc::MSG_FASTOPEN).context("MSG_FASTOPEN out of range")?;
    let mut sends = Vec::new();
    let x32_sends = X32_SENDS.iter().map(|&(nr, arg)| (X32 + nr, arg));
    for (nr, arg) in SENDS.into_iter().chain(x32_sends) {
        let masked = SeccompCondition::new(
            arg,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(fast_open),
            fast_open,
        )?;
        sends.push((nr, vec![SeccompRule::new(vec![masked])?]));
    }
    let clone_rules = any_flag(&CLONE_NAMESPACES)?;
    let mut unshare_flags = CLONE_NAMESPACES.to_vec();
    unshare_flags.push(CLONE_NEWTIME);
    let unshare_rules = any_flag(&unshare_flags)?;
    let [x32_clone, x32_unshare, _] = X32_NAMESPACE_CALLS;
    let clone = [libc::SYS_clone]
        .into_iter()
        .chain(x32_clone.iter().map(|nr| X32 + nr));
    let clone = clone.map(|nr| (nr, clone_rules.clone()));
    let unshare = [libc::SYS_unshare]
        .into_iter()
        .chain(x32_unshare.iter().map(|nr| X32 + nr));
    let unshare = unshare.map(|nr| (nr, unshare_rules.clone()));
    let rules = refused
        .chain(ioctl)
        .chain(sends)
        .chain(clone)
        .chain(unshare)
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

    pub fn warning(&self) -> Option<&str> {
        self.warning.as_deref()
    }

    pub fn status(self) -> Result<ExitStatus> {
        let Self {
            mut command,
            restrict,
            _session,
            ..
        } = self;
        let Some((ruleset, filters)) = restrict else {
            return command.status().context("starting bubblewrap");
        };
        std::thread::spawn(move || {
            ruleset
                .restrict_self()
                .context("applying the Landlock rules")?;
            for filter in &filters {
                seccompiler::apply_filter(filter).context("applying the seccomp filter")?;
            }
            command.status().context("starting the agent")
        })
        .join()
        .ok()
        .context("the thread that starts the agent panicked")?
    }
}

#[cfg(test)]
mod tests;
