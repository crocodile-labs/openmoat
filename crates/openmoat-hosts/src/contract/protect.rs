//! A host's own files the default policy and the taint list protect, and the
//! processes that tell the host is running (`tests/protect.rs` writes the
//! generated lists from them and checks them).

/// A host's paths in the generated blocks of the default policy's
/// `kernel-self` and `agent-credentials` rules and of the core's taint list
/// (`PROTECTED_WRITES`). The hosts whose paths `kernel-self` and the taint
/// list name among other hosts' lines (Claude Code, Codex, Cursor) leave
/// those two empty: their lines stay hand-written.
#[derive(Debug)]
#[non_exhaustive]
pub struct Protect {
    /// `kernel-self`'s `fs.write` globs: what an agent may never change.
    pub self_paths: &'static [Paths],
    /// The writes that ask once the session read untrusted content.
    pub taint: &'static [Paths],
    /// `agent-credentials`' globs: the files where the host keeps its login,
    /// provider keys and OAuth tokens, which the agent's own tools may neither
    /// read nor write. The rule is `hook_only`, so the host itself still reads
    /// them inside an OS sandbox. Named under the default directory; the
    /// engine adds the moved one (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, …) as for
    /// `kernel-self`.
    pub credentials: &'static [Paths],
}

impl Protect {
    /// No paths of the host's own: what a spec takes when it names none.
    pub const BASE: Protect = Protect {
        self_paths: &[],
        taint: &[],
        credentials: &[],
    };
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
