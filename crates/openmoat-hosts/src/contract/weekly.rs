//! How CI's weekly check of each agent's latest release runs a host
//! (`scripts/ci/latest-agents.sh`). `tests/docs/` writes these facts into
//! `scripts/ci/latest-agents/agents.json`, which the job and its checks
//! read, so the host list and what the job installs cannot drift apart. The
//! steps no fact can say are in the record's own script,
//! `scripts/ci/latest-agents/hosts/<agent>.sh`.

/// Whether the weekly job runs the host, and how ([`HostSpec::weekly`](super::HostSpec::weekly)).
#[derive(Debug)]
#[non_exhaustive]
pub struct Weekly {
    /// The job's records for the host, or why it has none.
    pub runs: WeeklyRuns,
    /// Variables the job sets for every agent, besides the one that moves the
    /// host's directory (from the spec, for a host whose location is one
    /// directory), so no agent finds state outside the throwaway home:
    /// `(name, value)`, the value with `{HOME}` and `{ROOT}` (the throwaway
    /// root) in it.
    pub env: &'static [(&'static str, &'static str)],
}

impl Weekly {
    /// Not run, for no stated reason: what a spec takes when it names
    /// nothing, which the registry's tests refuse.
    pub const BASE: Weekly = Weekly {
        runs: WeeklyRuns::NotRun(""),
        env: &[],
    };
}

/// The weekly job's records for a host.
#[derive(Debug)]
pub enum WeeklyRuns {
    /// One record per run: a host whose releases differ in how they load
    /// OpenMoat has one per line of releases (OpenCode 1 and 2).
    Runs(&'static [WeeklyRun]),
    /// The job does not run the host, for this reason.
    NotRun(&'static str),
}

/// One record of the weekly job: one `agents.json` entry and one job per
/// runner.
#[derive(Debug)]
#[non_exhaustive]
pub struct WeeklyRun {
    /// The record's name (`opencode-1`), which names its script
    /// `scripts/ci/latest-agents/hosts/<agent>.sh` and its jobs.
    pub agent: &'static str,
    /// How the latest release is installed.
    pub install: WeeklyInstall,
    /// The release the adapter was last checked against.
    pub checked: Checked,
    /// The directory the agent's first start makes, `{VARIABLE}` expanded
    /// from the job's environment, for a host whose location is not one
    /// directory; for one that is, the generator takes it from the spec and
    /// this is `None`.
    pub dir: Option<&'static str>,
    /// The files that must parse after `openmoat init`, and as what.
    pub config: &'static [(&'static str, ConfigFormat)],
    /// The golden shell payload the job sends `openmoat guard`.
    pub payload: Option<WeeklyPayload>,
    /// What a passing run asserts against the real agent.
    pub proves: &'static [Proves],
    /// Why the run proves no hook call, when it proves none.
    pub why: Option<&'static str>,
    /// The runners the record runs on.
    pub runners: &'static [Runner],
    /// Values the record's script reads (`check.py get <agent>
    /// values.<name>`), so a script never writes another host's word: the
    /// model provider an agent is set to, for one.
    pub values: &'static [(&'static str, &'static str)],
}

impl WeeklyRun {
    /// A record with no directory, config files, payload or claims; each
    /// host's record names what it has and ends with `..WeeklyRun::BASE`.
    pub const BASE: WeeklyRun = WeeklyRun {
        agent: "",
        install: WeeklyInstall::Script {
            kind: "",
            binary: "",
        },
        checked: Checked {
            version: None,
            source: "",
            note: None,
        },
        dir: None,
        config: &[],
        payload: None,
        proves: &[],
        why: None,
        runners: &[Runner::Linux, Runner::Mac],
        values: &[],
    };
}

/// How the weekly job installs a release.
#[derive(Debug)]
pub enum WeeklyInstall {
    /// `npm install` of the package's latest release, lifecycle scripts off;
    /// `binary` is relative to the install directory, `{platform}` node's
    /// `process.platform-process.arch`.
    Npm {
        /// The npm package.
        package: &'static str,
        /// The binary the job runs.
        binary: &'static str,
    },
    /// `npm pack` of the latest release, read and never run: a canary for a
    /// host OpenMoat sets nothing up for yet (its script's `canary`).
    NpmPack {
        /// The npm package.
        package: &'static str,
    },
    /// The record's script installs it (`install_agent`).
    Script {
        /// The name the record gives the way it installs (`goose-release`).
        kind: &'static str,
        /// Where the binary ends up, `{VARIABLE}` from the job's environment.
        binary: &'static str,
    },
}

impl WeeklyInstall {
    /// The kind `agents.json` names.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Npm { .. } => "npm",
            Self::NpmPack { .. } => "npm-pack",
            Self::Script { kind, .. } => kind,
        }
    }
}

/// The release an adapter was last checked against.
#[derive(Debug)]
pub struct Checked {
    /// The version, or `None` when no release says it ([`Checked::note`]).
    pub version: Option<&'static str>,
    /// The file (from the repository root) that names the version.
    pub source: &'static str,
    /// Why no version is recorded.
    pub note: Option<&'static str>,
}

/// What a config file the job checks after `openmoat init` must parse as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    /// JSON.
    Json,
    /// JavaScript (`node --check`).
    JavaScript,
    /// A POSIX shell script (`sh -n`).
    Shell,
    /// What the agent itself accepts, asked by the record's script
    /// (`check_config_format`): the name `agents.json` gives the format.
    Agent(&'static str),
}

impl ConfigFormat {
    /// The name `agents.json` gives the format.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::JavaScript => "javascript",
            Self::Shell => "shell",
            Self::Agent(name) => name,
        }
    }
}

/// The host's golden shell payload and the JSON pointers the job reads in it.
#[derive(Debug)]
pub struct WeeklyPayload {
    /// The fixture, under `crates/openmoat-hosts/src/host/`.
    pub fixture: &'static str,
    /// The pointer of the shell command in the payload.
    pub command: &'static str,
    /// The pointer of the verdict in the hook's reply, or the name of the
    /// host's own reply shape (`check.py`'s `verdict_of`).
    pub verdict: &'static str,
    /// Whether the host's hook answers an allowed call with nothing.
    pub allow_is_silent: bool,
}

/// What a passing weekly run asserts against the real agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proves {
    /// A call the agent made was decided by OpenMoat's hook and held.
    Hook,
    /// The hook-failure step's comparison with the host's fact (ADR-079).
    HookFailure,
    /// An MCP call the agent made was decided by the hook.
    Mcp,
}

impl Proves {
    /// The name `agents.json` gives the claim.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hook => "hook",
            Self::HookFailure => "hook-failure",
            Self::Mcp => "mcp",
        }
    }
}

/// A runner the weekly job runs a record on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runner {
    /// GitHub's `ubuntu-latest`.
    Linux,
    /// GitHub's `macos-15`.
    Mac,
}

impl Runner {
    /// The runner's label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Linux => "ubuntu-latest",
            Self::Mac => "macos-15",
        }
    }
}
