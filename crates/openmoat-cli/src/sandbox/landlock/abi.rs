//! The Landlock ABI ladder (ADR-082): what each Landlock ABI from `openmoat
//! run`'s floor up adds, whether `openmoat run` uses it, and what holds where
//! the kernel lacks it. The table is platform-neutral, so every line is a unit
//! test on every OS; the kernel's ABI is read on Linux only
//! (`commands/run/linux/abi.rs`).
//!
//! The ABI numbers, the rights each adds and the first Linux release with each
//! come from the kernel's Landlock documentation
//! (<https://docs.kernel.org/userspace-api/landlock.html> and its per-release
//! copies) and from the `landlock` crate's `ABI` variants; ADR-082
//! records how they were checked.
//!
//! A step is only ever added beside what holds without it: no seccomp rule is
//! removed because a newer ABI covers the same calls, so a kernel without a
//! step falls back to exactly the previous behaviour, never to less.

use serde::Serialize;

/// The oldest ABI `openmoat run` starts on: TCP connections by port (Linux
/// 6.7). An older kernel is refused, not run with the network open.
pub const FLOOR: u32 = 4;

/// What `openmoat run` does with one ABI's addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Use {
    /// The floor: `openmoat run` refuses a kernel without it.
    Required,
    /// Added where the kernel has it.
    Used,
    /// Not asked for, on purpose ([`Step::why`] says why).
    NotUsed,
    /// The `landlock` crate OpenMoat builds with cannot ask for it yet.
    NotInCrate,
}

/// One rung of the ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Step {
    pub abi: u32,
    /// The first Linux release with it.
    pub linux: &'static str,
    /// What the ABI adds, by the kernel's names.
    pub adds: &'static str,
    pub used: Use,
    /// What `openmoat run` does with it where the kernel has it.
    pub why: &'static str,
    /// What holds where the kernel lacks it.
    pub without: &'static str,
}

/// ABI 4 (the floor) to 12, the newest the kernel documents.
pub const STEPS: [Step; 9] = [
    Step {
        abi: 4,
        linux: "6.7",
        adds: "TCP bind and connect by port (`LANDLOCK_ACCESS_NET_*_TCP`)",
        used: Use::Required,
        why: "files and the proxy's TCP port, with ABI 1 to 3's file rights",
        without: "`openmoat run` refuses to start",
    },
    Step {
        abi: 5,
        linux: "6.10",
        adds: "`ioctl` on devices (`LANDLOCK_ACCESS_FS_IOCTL_DEV`)",
        used: Use::NotUsed,
        why: "the terminal's own `ioctl` calls (window size, modes) must keep working; \
              the seccomp filter refuses `TIOCSTI` and `TIOCLINUX`",
        without: "the seccomp filter refuses `TIOCSTI` and `TIOCLINUX`",
    },
    Step {
        abi: 6,
        linux: "6.12",
        adds: "abstract Unix sockets and signals scoped to the sandbox (`LANDLOCK_SCOPE_*`)",
        used: Use::Used,
        why: "abstract Unix sockets and signals outside the sandbox are refused",
        without: "the seccomp filter refuses Unix sockets; signals to the person's other \
                  processes are not scoped",
    },
    Step {
        abi: 7,
        linux: "6.15",
        adds: "denials in the kernel's audit log (`LANDLOCK_RESTRICT_SELF_LOG_*`)",
        used: Use::NotUsed,
        why: "the kernel's defaults stay; OpenMoat's audit log records its own decisions",
        without: "nothing changes: OpenMoat does not read the kernel's audit log",
    },
    Step {
        abi: 8,
        linux: "7.0",
        adds: "one ruleset for every thread of the process (`LANDLOCK_RESTRICT_SELF_TSYNC`)",
        used: Use::NotUsed,
        why: "the rules restrict the thread that starts the agent and everything it starts; \
              OpenMoat's proxy and relay threads must stay outside them",
        without: "nothing changes",
    },
    Step {
        abi: 9,
        linux: "7.1",
        adds: "connecting and sending to pathname Unix sockets \
               (`LANDLOCK_ACCESS_FS_RESOLVE_UNIX`)",
        used: Use::Used,
        why: "a pathname Unix socket made outside the sandbox (a D-Bus bus, the Docker \
              socket, `/dev/log`) cannot be connected or sent to, beside the seccomp filter",
        without: "the seccomp filter alone: no Unix `socket()` and no datagram socket pair",
    },
    Step {
        abi: 10,
        linux: "7.2",
        adds: "UDP bind, connect and send (`LANDLOCK_ACCESS_NET_BIND_UDP`, \
               `LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP`)",
        used: Use::NotInCrate,
        why: "the `landlock` crate OpenMoat is built with cannot ask for it yet",
        without: "the seccomp filter refuses UDP sockets",
    },
    Step {
        abi: 11,
        linux: "7.3",
        adds: "`no_new_privs` set by `landlock_restrict_self` \
               (`LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS`)",
        used: Use::NotUsed,
        why: "nothing to add: `no_new_privs` is already set before the rules apply",
        without: "nothing changes",
    },
    Step {
        abi: 12,
        linux: "7.4",
        adds: "capability and namespace use (`LANDLOCK_PERMISSION_CAPABILITY_USE`, \
               `LANDLOCK_PERMISSION_NAMESPACE_USE`)",
        used: Use::NotInCrate,
        why: "the `landlock` crate OpenMoat is built with cannot ask for it yet",
        without: "the seccomp filter refuses new namespaces and joining one",
    },
];

/// The kernel's Landlock, as `openmoat run` finds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    not(any(target_os = "linux", test)),
    expect(
        dead_code,
        reason = "only Linux reads a kernel's Landlock; the table is the same code everywhere"
    )
)]
pub enum Kernel {
    /// No Landlock at all: why.
    Missing(String),
    /// The kernel's ABI, also where it is newer than the crate knows.
    Abi(u32),
}

impl Kernel {
    fn abi(&self) -> u32 {
        match self {
            Self::Missing(_) => 0,
            Self::Abi(abi) => *abi,
        }
    }

    /// Whether `openmoat run` can start on this kernel.
    pub fn meets_floor(&self) -> bool {
        self.abi() >= FLOOR
    }

    /// The ABIs `openmoat run` applies here, oldest first.
    pub fn applied(&self) -> Vec<u32> {
        STEPS
            .iter()
            .filter(|s| matches!(s.used, Use::Required | Use::Used) && s.abi <= self.abi())
            .map(|s| s.abi)
            .collect()
    }
}

/// One line for `openmoat doctor` and the audit record: the kernel's ABI and
/// what `openmoat run` applies from it.
pub fn summary(kernel: &Kernel) -> String {
    match kernel {
        Kernel::Missing(why) => {
            format!("Landlock is not available here ({why}): `openmoat run` refuses to start")
        }
        Kernel::Abi(abi) if !kernel.meets_floor() => format!(
            "Landlock ABI {abi} here, below ABI {FLOOR} (Linux 6.7): `openmoat run` refuses \
             to start"
        ),
        Kernel::Abi(abi) => {
            let applied: Vec<String> = kernel.applied().iter().map(u32::to_string).collect();
            let missing = STEPS
                .iter()
                .filter(|s| s.used == Use::Used && s.abi > *abi)
                .map(|s| format!("ABI {} (Linux {})", s.abi, s.linux))
                .collect::<Vec<_>>();
            let rest = if missing.is_empty() {
                String::new()
            } else {
                format!(
                    "; the seccomp filter alone holds what {} would add",
                    missing.join(" and ")
                )
            };
            format!(
                "Landlock ABI {abi} here: `openmoat run` applies ABI {}{rest}",
                applied.join(", ")
            )
        }
    }
}

/// One line per step, for `--verbose` and `openmoat sandbox show`.
pub fn lines(kernel: &Kernel) -> Vec<String> {
    let mut lines: Vec<String> = STEPS
        .iter()
        .map(|step| {
            let state = match (step.abi <= kernel.abi(), step.used) {
                (true, Use::Required | Use::Used) => format!("used: {}", step.why),
                (true, Use::NotUsed | Use::NotInCrate) => {
                    format!("available, not used: {}; {}", step.why, step.without)
                }
                (false, _) => format!("not available here: {}", step.without),
            };
            format!(
                "ABI {} (Linux {}) {}: {state}",
                step.abi, step.linux, step.adds
            )
        })
        .collect();
    let newest = STEPS.last().map_or(FLOOR, |s| s.abi);
    if kernel.abi() > newest {
        lines.push(format!(
            "ABI {} here is newer than this table: what it adds is not used",
            kernel.abi()
        ));
    }
    lines
}

/// The ladder as JSON, for `--format json`.
pub fn json(kernel: &Kernel) -> serde_json::Value {
    serde_json::json!({
        "kernel": kernel,
        "floor": FLOOR,
        "applied": kernel.applied(),
        "summary": summary(kernel),
        "steps": STEPS,
    })
}

#[cfg(test)]
mod tests;
