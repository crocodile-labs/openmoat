//! A host's own files the default policy and the taint list protect, and the
//! processes that tell the host is running (`tests/protect.rs` writes the
//! generated lists from them and checks them).

/// A host's paths in the generated blocks of the default policy's
/// `kernel-self`, `agent-credentials`, `runs-later`, `agent-temp` rules and of
/// the core's taint list (`PROTECTED_WRITES`). The hosts whose paths
/// `kernel-self` names among other hosts' lines (Claude Code, Codex, Cursor)
/// leave [`Protect::self_paths`] empty: those lines stay hand-written.
#[derive(Debug)]
#[non_exhaustive]
pub struct Protect {
    /// `kernel-self`'s `fs.write` globs: what an agent may never change.
    pub self_paths: &'static [Paths],
    /// The writes that need review once the session read untrusted content.
    pub taint: &'static [Paths],
    /// The host's own temporary folders, whose files it writes and reads
    /// back itself (the output of its background commands): the default
    /// policy's `agent-temp` rule lets its tools read them, and reads there
    /// do not count as collecting files outside the project (ADR-061).
    pub temp_dirs: &'static [Paths],
    /// `agent-credentials`' globs: the files where the host keeps its login,
    /// provider keys and OAuth tokens, which the agent's own tools may neither
    /// read nor write. The rule is `hook_only`, so the host itself still reads
    /// them inside an OS sandbox. Named under the default directory; the
    /// engine adds the moved one (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, …) as for
    /// `kernel-self`.
    pub credentials: &'static [Paths],
    /// The host's files it loads or runs later, outside any sandbox: the
    /// default policy's `runs-later` rule holds a write of one for review,
    /// and `project-fs` leaves the project's (`**/…`) out of its grant. Those
    /// marked [`RunsLater::agent_config`] are the configuration the host
    /// loads when it next opens the project (hooks, MCP servers, plugins,
    /// commands, subagents, policy files); `openmoat run`'s sandboxes deny
    /// commands writing them, and the folders above them, in every tier.
    pub runs_later: &'static [RunsLater],
}

impl Protect {
    /// No paths of the host's own: what a spec takes when it names none.
    pub const BASE: Protect = Protect {
        self_paths: &[],
        taint: &[],
        temp_dirs: &[],
        credentials: &[],
        runs_later: &[],
    };
}

/// Files of a host that run later ([`Protect::runs_later`]), the comment
/// above them in the default policy, and whether they are the host's own
/// configuration in a project.
#[derive(Debug)]
#[non_exhaustive]
pub struct RunsLater {
    /// The globs, the comment above them, in the `runs-later` rule's order.
    pub paths: Paths,
    /// The host loads them as its configuration when it next opens the
    /// project, so `openmoat run`'s sandboxes deny commands writing them.
    /// Only project globs (`**/…`) carry it: a home file is the host's own
    /// state, which `openmoat run --write` may grant.
    pub agent_config: bool,
}

impl RunsLater {
    /// The host's configuration in a project (`**/…` globs only): held for
    /// review in the hook, denied to commands under `openmoat run`.
    #[must_use]
    pub const fn agent_config(why: &'static str, globs: &'static [&'static str]) -> Self {
        Self {
            paths: Paths::new(why, globs),
            agent_config: true,
        }
    }

    /// Files held for review in the hook only: the host's files in the home,
    /// and the folders above its configuration in a project, which the
    /// sandboxes cover as the folders above [`RunsLater::agent_config`]
    /// entries.
    #[must_use]
    pub const fn review(why: &'static str, globs: &'static [&'static str]) -> Self {
        Self {
            paths: Paths::new(why, globs),
            agent_config: false,
        }
    }
}

/// Path globs and the comment above them in a generated list.
#[derive(Debug)]
#[non_exhaustive]
pub struct Paths {
    /// The comment, one line of the list per `\n`-separated line.
    pub why: &'static str,
    /// The globs, in the list's order.
    pub globs: &'static [&'static str],
}

impl Paths {
    /// `globs`, explained by `why`.
    #[must_use]
    pub const fn new(why: &'static str, globs: &'static [&'static str]) -> Self {
        Self { why, globs }
    }
}

/// How to tell a host's process among the ancestors of a command
/// (`openmoat`'s person-only commands refuse to run under an agent).
#[derive(Debug)]
#[non_exhaustive]
pub struct ProcessSpec {
    /// The host's program names, without `.exe` or a `.js`, `.mjs` or `.cjs`
    /// extension.
    pub names: &'static [&'static str],
    /// Directories the host installs its code under, for a host that runs as
    /// `node <dir>/…/cli.js` or from a versioned file; each one directory per
    /// path segment, matched in a row. A match is reported by its first segment.
    pub package_dirs: &'static [&'static [&'static str]],
    /// A helper process the host's commands run under, matched in its
    /// lowercased program path; `None` when there is none.
    pub helper: Option<Helper>,
}

impl ProcessSpec {
    /// No processes: what a spec takes when it names none.
    pub const BASE: ProcessSpec = ProcessSpec {
        names: &[],
        package_dirs: &[],
        helper: None,
    };
}

/// A helper process of the host (Cursor's editor helpers).
#[derive(Debug)]
#[non_exhaustive]
pub struct Helper {
    /// What its lowercased program path contains.
    pub path: &'static str,
    /// The name the ancestor is reported by.
    pub name: &'static str,
}
