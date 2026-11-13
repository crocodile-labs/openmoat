//! The sandbox boundary one `openmoat run` has (ADR-089): which tier was asked
//! for and which started, every downgrade and why, how the network is held,
//! the Landlock ABI, whether tool commands get the relay token, and for each
//! restriction whether the system has it, the run asks for it, it applied and
//! a check after the agent started confirmed it.
//!
//! Pure data: the CLI fills it from the platform and the launch, writes it to
//! the audit log as one row on every run and prints it for
//! `openmoat run --print-boundary`. Its JSON form is what scripts read, so
//! fields are only added, and [`VERSION`] moves when one changes meaning.

use serde::{Deserialize, Serialize};

/// The version of the record's JSON form.
pub const VERSION: u32 = 1;

/// The boundary of one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveBoundary {
    /// [`VERSION`].
    pub version: u32,
    /// The operating system (`linux`, `macos`, …).
    pub os: String,
    /// What the command line asked for.
    pub requested: Requested,
    /// The tier that starts.
    pub tier: Tier,
    /// Every way this run is weaker than the full boundary, each with why.
    pub downgrades: Vec<Downgrade>,
    /// How the agent's network is held.
    pub network: Network,
    /// Linux: the kernel's Landlock ABI and what `restrict_self` reported.
    pub landlock: Option<Landlock>,
    /// Whether tool commands receive the hook relay token (ADR-075).
    pub tool_token: ToolToken,
    /// Each restriction the platform has, in a fixed order.
    pub restrictions: Vec<Restriction>,
    /// What the check after the agent started found; `None` before the
    /// agent starts (`--print-boundary`) or where no report came back.
    pub launch: Option<LaunchCheck>,
}

/// The tier asked for on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requested {
    /// Neither `--isolate` nor `--no-isolate`: the platform's default.
    Default,
    /// `--isolate`.
    Isolated,
    /// `--no-isolate`.
    Lightweight,
}

/// The tiers of ADR-018.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// The agent's own sandbox and OpenMoat's hooks, without `openmoat run`;
    /// named so a record compares with a hook-only session, never one a run starts.
    Standard,
    /// Landlock and seccomp, or Seatbelt, over the whole machine.
    Lightweight,
    /// bubblewrap's own view of the machine around the same rules.
    Isolated,
}

/// One way the run is weaker than the full boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Downgrade {
    /// What is weaker.
    pub what: Weaker,
    /// Whether the person chose it (`--no-isolate`) rather than the system
    /// lacking what it needs.
    pub chosen: bool,
    /// Why, in the words the run notice uses.
    pub why: String,
}

/// What a [`Downgrade`] weakens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Weaker {
    /// The Lightweight tier instead of the Isolated one.
    Tier,
    /// The network restricted by port only instead of a namespace.
    Network,
    /// The project's top granted whole instead of entry by entry, by the
    /// person's own `sandbox.project_top: writable` (ADR-090): `.env`,
    /// `.git/hooks` and `.moat` there are open to commands.
    ProjectTop,
}

/// How the agent's network is held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    /// The mode.
    pub mode: NetworkMode,
    /// The proxy's loopback port, once the run has one.
    pub proxy_port: Option<u16>,
}

/// The ways `openmoat run` holds the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// A network namespace whose only interface is loopback; the proxy is
    /// the only way out (Linux, bubblewrap).
    Namespace,
    /// Landlock's TCP port rule alone: any host on the proxy's port is
    /// reachable (Linux without a usable bubblewrap).
    PortOnly,
    /// The Seatbelt profile allows the proxy's address alone (macOS).
    Profile,
}

/// The Landlock part of the record (Linux).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Landlock {
    /// The kernel's ABI, also where it is newer than the `landlock` crate knows.
    pub abi: Option<u32>,
    /// Why there is no usable Landlock, when there is none.
    pub unavailable: Option<String>,
    /// What `restrict_self` reported for the agent's ruleset; `None` before
    /// the agent starts, when [`Self::abi`] comes from a probe.
    pub enforcement: Option<Enforcement>,
}

/// Landlock's `RulesetStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    /// Every right asked for applies.
    Full,
    /// The required rights apply; a best-effort one the kernel lacks does not.
    Partial,
    /// Nothing applies.
    None,
}

/// Whether tool commands receive the hook relay token (ADR-075).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "why")]
pub enum ToolToken {
    /// A wrapper in front of the agent's tool shell drops it.
    Withheld,
    /// The host's own integration takes it out of the environment.
    WithheldByIntegration,
    /// Tool commands keep it: why.
    NotWithheld(String),
    /// The program is no agent OpenMoat knows, so no token handling applies.
    UnknownAgent,
}

/// The restrictions a record names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    /// macOS: the Seatbelt profile `sandbox-exec` applies.
    Seatbelt,
    /// Landlock's file rights (ABI 1 to 3).
    LandlockFilesystem,
    /// Landlock's TCP connect rule for the proxy's port (ABI 4).
    LandlockTcpPort,
    /// Abstract Unix sockets and signals scoped to the sandbox (ABI 6,
    /// best effort).
    LandlockScopes,
    /// Pathname Unix sockets made outside the sandbox refused (ABI 9, best
    /// effort).
    LandlockResolveUnix,
    /// The seccomp filters.
    Seccomp,
    /// `PR_SET_NO_NEW_PRIVS`: no set-user-ID gain across `exec`.
    NoNewPrivs,
    /// The agent's own network namespace (bubblewrap).
    NetworkNamespace,
    /// bubblewrap's view of the machine: the project without its denied
    /// paths, the read roots and `--write` paths (the Isolated tier).
    IsolatedView,
}

impl Mechanism {
    /// The name the JSON form and the run's output use.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Seatbelt => "seatbelt",
            Self::LandlockFilesystem => "landlock_filesystem",
            Self::LandlockTcpPort => "landlock_tcp_port",
            Self::LandlockScopes => "landlock_scopes",
            Self::LandlockResolveUnix => "landlock_resolve_unix",
            Self::Seccomp => "seccomp",
            Self::NoNewPrivs => "no_new_privs",
            Self::NetworkNamespace => "network_namespace",
            Self::IsolatedView => "isolated_view",
        }
    }
}

/// One restriction of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restriction {
    /// Which.
    pub name: Mechanism,
    /// This system has it.
    pub available: bool,
    /// This run asks for it.
    pub configured: bool,
    /// The kernel or tool reported it in force; `None` before the agent
    /// starts, or where nothing reports it.
    pub applied: Option<bool>,
    /// A check after the agent started confirmed it (`/proc/<pid>/status`);
    /// `None` where no such check exists (Landlock's rules cannot be read
    /// back, Seatbelt has no `/proc`).
    pub tested: Option<bool>,
}

impl Restriction {
    /// A restriction as planned: not yet applied or tested.
    #[must_use]
    pub fn planned(name: Mechanism, available: bool, configured: bool) -> Self {
        Self {
            name,
            available,
            configured,
            applied: None,
            tested: None,
        }
    }

    /// Whether the run asked for it, the system has it, and the launch found
    /// it not applied or not in force. Once the agent started (`launched`),
    /// what the tier promises must be confirmed: unknown counts as missing
    /// for the seccomp filters and `no_new_privs` (`tested`), and for
    /// Landlock's required rights and bubblewrap's namespace and view
    /// (`applied`). Best-effort steps and Seatbelt, which nothing reports,
    /// are missing only when reported off.
    #[must_use]
    pub fn missing(&self, launched: bool) -> bool {
        if !self.configured || !self.available {
            return false;
        }
        let reported_off = self.applied == Some(false) || self.tested == Some(false);
        let confirmed = match self.name {
            Mechanism::Seccomp | Mechanism::NoNewPrivs => self.tested == Some(true),
            Mechanism::LandlockFilesystem
            | Mechanism::LandlockTcpPort
            | Mechanism::NetworkNamespace
            | Mechanism::IsolatedView => self.applied == Some(true),
            Mechanism::LandlockScopes | Mechanism::LandlockResolveUnix | Mechanism::Seatbelt => {
                true
            }
        };
        reported_off || (launched && !confirmed)
    }
}

/// What the launch reported, from the process that started the agent: the
/// result of `restrict_self` and the seccomp filters, and the agent's
/// `/proc/<pid>/status` read after it started.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchCheck {
    /// The kernel's Landlock ABI, as `restrict_self` reported it.
    pub landlock_abi: Option<u32>,
    /// The ruleset's enforcement, as `restrict_self` reported it.
    pub landlock: Option<Enforcement>,
    /// `restrict_self` set `no_new_privs`.
    pub no_new_privs_set: Option<bool>,
    /// How many seccomp filters were applied.
    pub seccomp_filters: Option<u32>,
    /// The `Seccomp_filters:` count of the thread that started the agent,
    /// before it applied them: filters a parent (a container runtime, a
    /// service manager) had already set.
    pub inherited_seccomp_filters: Option<u32>,
    /// The agent's `Seccomp_filters:` count.
    pub proc_seccomp_filters: Option<u32>,
    /// The agent's `NoNewPrivs:` line read `1`. It may have been set by a
    /// parent already; what counts is that it is in force.
    pub proc_no_new_privs: Option<bool>,
    /// The agent's `Seccomp:` line read `2` (filter mode) and its filter count
    /// is the inherited count plus the filters applied, so the filters in
    /// force include this run's, not only a parent's.
    pub proc_seccomp_filter: Option<bool>,
    /// The report came from `openmoat isolated` inside bubblewrap.
    pub in_bubblewrap: bool,
    /// Why the launch was stopped, when it was.
    pub failure: Option<String>,
}

impl LaunchCheck {
    /// What the tier promises and the check found missing on Linux: a ruleset
    /// not enforced, `no_new_privs` or the seccomp filter not in force in the
    /// agent. Empty when everything is in force.
    #[must_use]
    pub fn linux_gaps(&self) -> Vec<&'static str> {
        let mut gaps = Vec::new();
        if self.landlock != Some(Enforcement::Full) && self.landlock != Some(Enforcement::Partial) {
            gaps.push("the Landlock rules are not enforced");
        }
        if self.proc_no_new_privs != Some(true) {
            gaps.push("the agent's /proc status does not show `NoNewPrivs: 1`");
        }
        if self.proc_seccomp_filter != Some(true) {
            gaps.push(
                "the agent's /proc status does not show `Seccomp: 2` with this run's filters \
                 added to the inherited ones (`Seccomp_filters`)",
            );
        }
        gaps
    }

    /// The check's failure: the one the reporting process gave, else the
    /// [`Self::linux_gaps`] found here, so a report is never taken on trust.
    #[must_use]
    pub fn linux_failure(&self) -> Option<String> {
        let gaps = self.linux_gaps();
        self.failure
            .clone()
            .or_else(|| (!gaps.is_empty()).then(|| gaps.join("; ")))
    }
}

impl EffectiveBoundary {
    /// Whether anything is weaker than the full boundary.
    #[must_use]
    pub fn downgraded(&self) -> bool {
        !self.downgrades.is_empty()
    }

    /// The restriction named `name`, if the platform has it.
    #[must_use]
    pub fn restriction(&self, name: Mechanism) -> Option<&Restriction> {
        self.restrictions.iter().find(|r| r.name == name)
    }

    /// Fold what the launch reported into the record: what applied, what the
    /// check after the start confirmed, and the ABI `restrict_self` saw in
    /// place of the probe's.
    pub fn launched(&mut self, check: LaunchCheck) {
        if let Some(landlock) = &mut self.landlock {
            if check.landlock_abi.is_some() {
                landlock.abi = check.landlock_abi;
            }
            landlock.enforcement = check.landlock;
        }
        let abi = self.landlock.as_ref().and_then(|l| l.abi);
        let enforced = check.landlock.map(|e| e != Enforcement::None);
        // A step the kernel's ABI lacks is not applied, whatever the ruleset
        // reports. One the kernel has applies only when the ruleset is fully
        // enforced; a partial one may lack exactly that step, so it is unknown.
        let step = |from: u32| match (check.landlock, abi) {
            (Some(Enforcement::None), _) => Some(false),
            (_, Some(abi)) if abi < from => Some(false),
            (Some(Enforcement::Full), Some(_)) => Some(true),
            _ => None,
        };
        for restriction in &mut self.restrictions {
            let (applied, tested) = match restriction.name {
                Mechanism::LandlockFilesystem | Mechanism::LandlockTcpPort => (enforced, None),
                Mechanism::LandlockScopes => (step(6), None),
                Mechanism::LandlockResolveUnix => (step(9), None),
                Mechanism::Seccomp => (
                    check.seccomp_filters.map(|n| n > 0),
                    check.proc_seccomp_filter,
                ),
                Mechanism::NoNewPrivs => (check.no_new_privs_set, check.proc_no_new_privs),
                Mechanism::NetworkNamespace | Mechanism::IsolatedView => {
                    (Some(check.in_bubblewrap), None)
                }
                Mechanism::Seatbelt => (None, None),
            };
            if restriction.configured {
                restriction.applied = applied;
                restriction.tested = tested;
            }
        }
        self.launch = Some(check);
    }

    /// The restrictions the run asked for, the system has, and the launch
    /// found missing; with the launch's own failure, if it stopped the agent.
    #[must_use]
    pub fn missing(&self) -> Vec<String> {
        let mut missing: Vec<String> = self
            .restrictions
            .iter()
            .filter(|r| r.missing(self.launch.is_some()))
            .map(|r| r.name.id().to_owned())
            .collect();
        if let Some(failure) = self.launch.as_ref().and_then(|l| l.failure.clone()) {
            missing.push(failure);
        }
        missing
    }
}

#[cfg(test)]
mod tests;
