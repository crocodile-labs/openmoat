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
    /// Check a change before it is merged: every file it adds, edits, deletes or renames that
    /// the policy protects (CI, git hooks, build and package files, agent settings, OpenMoat's
    /// own files, secrets), and added lines holding a known token. Exits 0 when nothing is
    /// found, 2 when the policy denies something, 3 when something needs a person's review.
    CheckDiff(CheckDiffArgs),
    /// Print what OS layers enforce for a policy: the compiled IR and its losses.
    Compile(CompileArgs),
    /// Add what this release's default policy changed to ~/.moat/policy.yaml, keeping every
    /// line you changed; shows the diff and asks first. Refused unless run from an
    /// interactive terminal, except with --dry-run.
    Upgrade(UpgradeArgs),
    /// Install a team's signed policy pack: verify its OpenSSH signature against the
    /// keys `openmoat policy trust-key` trusted, then merge its rules into the policy and
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
    /// The pack: a policy file with only `version`, `deny`, `review` and `allow`.
    pub pack: PathBuf,

    /// Its detached signature (`ssh-keygen -Y sign -n openmoat-pack`). Defaults
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
pub struct CheckDiffArgs {
    /// The revision the change is made against, such as a pull request's base commit. The
    /// change is everything from where `--head` left it to `--head`, and the policy files
    /// are read as this revision has them. Without it, the unified diff on stdin is checked.
    #[arg(long, value_name = "REV")]
    pub base: Option<String>,

    /// The revision with the change. Defaults to `HEAD`.
    #[arg(long, value_name = "REV", requires = "base")]
    pub head: Option<String>,

    /// Policy to check against. Defaults to the shipped default policy, so every machine
    /// gives the same answer. With --base, a relative path is a file of the repository,
    /// read as --base has it. The repository's own `.moat/policy.yaml` at --base adds its
    /// deny and review rules.
    #[arg(long, short)]
    pub policy: Option<PathBuf>,

    /// Output format. Defaults to `github` when GitHub Actions runs it, `text` otherwise.
    #[arg(long, value_enum)]
    pub format: Option<DiffFormat>,
}

/// `policy check-diff --format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DiffFormat {
    Text,
    Json,
    /// GitHub Actions workflow commands (`::error file=…::…`), then the text.
    Github,
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "four command-line flags, each of its own: clap reads them as bools"
)]
pub struct UpgradeArgs {
    /// Show the changes without writing anything; needs no terminal.
    #[arg(long, conflicts_with = "undo")]
    pub dry_run: bool,

    /// Show the full diff of the policy after the summary of its changes
    /// (`d` at the question shows it too).
    #[arg(long, conflicts_with = "undo")]
    pub diff: bool,

    /// Apply without asking (still only from a terminal).
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Restore the policy the last upgrade replaced, byte for byte.
    #[arg(long)]
    pub undo: bool,
}
