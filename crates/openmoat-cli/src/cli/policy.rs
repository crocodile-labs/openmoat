//! `moat policy` grammar.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

use super::Format;

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Validate a policy file and print a summary.
    Lint(LintArgs),
    /// Decide one action against a policy and explain the result.
    Check(CheckArgs),
    /// Print what OS layers enforce for a policy: the compiled IR and its losses.
    Compile(CompileArgs),
    /// Add what this release's default policy changed to ~/.moat/policy.yaml, keeping every
    /// line you changed; shows the diff and asks first. Refused unless run from an
    /// interactive terminal, except with --dry-run.
    Upgrade(UpgradeArgs),
    /// Install a team's signed policy pack: verify its OpenSSH signature against the
    /// keys `moat policy trust-key` trusted, then merge its rules into the policy and
    /// pin the pack. Refused unless run from an interactive terminal, and over a
    /// drifted lock.
    Install(InstallArgs),
    /// Trust an OpenSSH public key to sign policy packs (and, where the policy sets
    /// `require_signed_repo_policy`, repository policies). Refused unless run from an
    /// interactive terminal, and over a drifted lock.
    TrustKey(TrustKeyArgs),
    /// Remove an installed policy pack by name. Refused unless run from an
    /// interactive terminal, and over a drifted lock.
    Remove(RemoveArgs),
}

#[derive(Debug, Args)]
pub struct InstallArgs {
    /// The pack: a policy file with only `version`, `deny`, `ask` and `allow`.
    pub pack: PathBuf,

    /// Its detached signature (`ssh-keygen -Y sign -n openmoat-policy`). Defaults
    /// to the pack's path with `.sig` appended.
    #[arg(long, value_name = "PATH")]
    pub sig: Option<PathBuf>,

    /// The name the pack is installed and its rules prefixed under (`pack:<name>:`).
    /// Defaults to the file name without its extension.
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct TrustKeyArgs {
    /// The public key file (`id_ed25519.pub`).
    pub key: PathBuf,

    /// Who the key belongs to, as signatures will name them (`alice@example.com`).
    #[arg(long)]
    pub name: String,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// The installed pack's name.
    pub name: String,
}

#[derive(Debug, Args)]
pub struct LintArgs {
    /// Policy file to validate. Defaults to the installed user policy.
    pub file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// The action: a shell command, a path, a URL or an MCP tool name, depending on --kind.
    pub action: String,

    /// Policy file to evaluate against. Defaults to the installed user policy.
    #[arg(long, short)]
    pub policy: Option<PathBuf>,

    /// Kind of action.
    #[arg(long, value_enum, default_value_t = ActionKind::Shell)]
    pub kind: ActionKind,

    /// Trusted project root that `${project}` expands to. Defaults to the git root of --cwd.
    #[arg(long)]
    pub project: Option<PathBuf>,

    /// Working directory the action runs in. Defaults to the current directory.
    #[arg(long)]
    pub cwd: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct CompileArgs {
    /// Policy file to compile. Defaults to the installed user policy.
    #[arg(long, short)]
    pub policy: Option<PathBuf>,

    /// Trusted project root that `${project}` expands to. Defaults to the git root of --cwd.
    #[arg(long)]
    pub project: Option<PathBuf>,

    /// Working directory to compile for. Defaults to the current directory.
    #[arg(long)]
    pub cwd: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ActionKind {
    Shell,
    FsRead,
    FsWrite,
    Net,
    /// A URL read by a host fetch tool (`WebFetch`).
    Fetch,
    Mcp,
}

#[derive(Debug, Args)]
pub struct UpgradeArgs {
    /// Show the changes without writing anything; needs no terminal.
    #[arg(long, conflicts_with = "undo")]
    pub dry_run: bool,

    /// Apply without asking (still only from a terminal).
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Restore the policy the last upgrade replaced, byte for byte.
    #[arg(long)]
    pub undo: bool,
}
