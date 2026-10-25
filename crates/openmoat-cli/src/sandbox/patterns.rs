//! Classifying IR patterns for hosts that have no project of their own.

use super::PROJECT;

/// Where an IR pattern points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spot<'a> {
    /// The project itself (`""`) or a path below it (`.git/**`).
    Project(&'a str),
    /// An absolute path or glob.
    Absolute(&'a str),
    /// A relative glob such as `**/.env`, which matches at any depth; the
    /// leading `**/` is removed.
    Anywhere(&'a str),
}

pub fn spot(pattern: &str) -> Spot<'_> {
    if pattern == PROJECT {
        return Spot::Project("");
    }
    if let Some(rest) = pattern
        .strip_prefix(PROJECT)
        .and_then(|r| r.strip_prefix('/'))
    {
        return Spot::Project(rest);
    }
    let bytes = pattern.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if pattern.starts_with('/') || drive {
        Spot::Absolute(pattern)
    } else {
        Spot::Anywhere(pattern.trim_start_matches("**/"))
    }
}

/// The project-relative write exclusion for a `.git` at any depth below the
/// project (a `gitdir:` file or a planted directory in a subdirectory), which
/// git follows like the root's own `.git`.
pub const ANY_GIT: &str = "**/.git/**";

/// Files in a project that CI, a commit-hook manager, the editor or the agent
/// host runs later, outside any sandbox (`runs-later` in the default policy,
/// which also lists the hosts' home files). `project-fs` and `moat allow --dir`
/// leave them out so the hook asks; an OS sandbox gets no deny for them, which
/// would also make them unreadable (Codex globs) or refuse a whole granted
/// directory (Cursor).
pub const RUNS_LATER: &[&str] = &[
    "**/.github/workflows/**",
    "**/.gitlab-ci.yml",
    "**/.circleci/**",
    "**/azure-pipelines.yml",
    "**/Jenkinsfile",
    "**/.buildkite/**",
    "**/.husky/**",
    "**/.pre-commit-config.yaml",
    "**/lefthook.yml",
    "**/.lefthook.yml",
    "**/.vscode/tasks.json",
    "**/.claude/hooks/**",
    "**/.mcp.json",
    "**/.cursor/mcp.json",
    "**/.codex/config.toml",
    "**/.openclaw/extensions/**",
    "**/.github/hooks/**",
    "**/.github/mcp.json",
    "**/.pi/extensions/**",
    "**/.pi/mcp.json",
    "**/.pi/settings.json",
    // the folders above them, which a rename moves with everything inside
    "**/.github/hooks",
    "**/.pi",
    "**/.pi/extensions",
    "**/.gemini/policies/**",
    "**/.gemini/commands/**",
    "**/.gemini/agents/**",
    "**/.github/agents/**",
    "**/.claude/agents/**",
    "**/.claude/skills/**",
    "**/.claude/commands/**",
    "**/.opencode/plugins/**",
    "**/.opencode/plugin/**",
    "**/.opencode/tools/**",
    "**/.opencode/tool/**",
    "**/.opencode/commands/**",
    "**/.opencode/command/**",
    "**/.opencode/opencode.json",
    "**/.opencode/opencode.jsonc",
    "**/.opencode/package.json",
    "**/opencode.json",
    "**/opencode.jsonc",
    // the folders above a project's OpenCode plugins
    "**/.opencode",
    "**/.opencode/plugins",
    "**/.opencode/plugin",
];

/// The [`RUNS_LATER`] files an agent host loads as its own configuration when
/// it next opens the project: hooks, MCP servers and extensions, which run
/// with the person's rights. Nothing a build or an install writes, so
/// `openmoat run` denies commands writing them; CI files and commit-hook
/// managers' files stay writable there (an install runs `husky`).
pub const AGENT_CONFIG: &[&str] = &[
    "**/.claude/hooks/**",
    "**/.mcp.json",
    "**/.cursor/mcp.json",
    "**/.codex/config.toml",
    "**/.openclaw/extensions/**",
    "**/.github/hooks/**",
    "**/.github/mcp.json",
    "**/.pi/extensions/**",
    "**/.pi/mcp.json",
    "**/.pi/settings.json",
    "**/.opencode/plugins/**",
    "**/.opencode/plugin/**",
    "**/.opencode/tools/**",
    "**/.opencode/tool/**",
    "**/.opencode/opencode.json",
    "**/.opencode/opencode.jsonc",
    "**/opencode.json",
    "**/opencode.jsonc",
];

/// A write exclusion of one of [`RUNS_LATER`], below the project or below a
/// directory `moat allow --dir` granted.
pub fn runs_later_exclusion(pattern: &str) -> bool {
    exclusion_of(pattern, RUNS_LATER)
}

/// A write exclusion of one of [`AGENT_CONFIG`], as [`runs_later_exclusion`].
pub fn agent_config_exclusion(pattern: &str) -> bool {
    exclusion_of(pattern, AGENT_CONFIG)
}

/// The folders above the file or folder an [`AGENT_CONFIG`] entry names, as
/// paths relative to where it is found, outermost first: `.github` for
/// `**/.github/hooks/**`, `.cursor` for `**/.cursor/mcp.json`, none for
/// `**/.mcp.json`. Renaming one moves the file out from under its pattern.
pub fn folders_above(entry: &str) -> Vec<String> {
    let name = entry.strip_prefix("**/").unwrap_or(entry);
    let name = name.strip_suffix("/**").unwrap_or(name);
    let mut folders = Vec::new();
    let mut at = 0;
    while let Some(slash) = name[at..].find('/') {
        at += slash;
        folders.push(name[..at].to_owned());
        at += 1;
    }
    folders
}

/// For an [`agent_config_exclusion`] (`/p/**/.github/hooks/**`), each folder
/// above the file it names directly in the directory it is below
/// (`/p/.github`). Not at any depth: packages bring their own `.github` into
/// `node_modules`, and installing or removing one would fail.
pub fn agent_config_folders(pattern: &str) -> Vec<String> {
    for file in AGENT_CONFIG {
        let Some(head) = pattern.strip_suffix(file) else {
            continue;
        };
        if head.ends_with('/') {
            return folders_above(file)
                .into_iter()
                .map(|folder| format!("{head}{folder}"))
                .collect();
        }
    }
    Vec::new()
}

/// Whether `pattern` names one of `files` below the project or below a
/// directory `moat allow --dir` granted.
fn exclusion_of(pattern: &str, files: &[&str]) -> bool {
    let rest = match spot(pattern) {
        Spot::Project(rest) => rest,
        Spot::Absolute(path) => path,
        Spot::Anywhere(_) => return false,
    };
    files
        .iter()
        .any(|file| rest == *file || rest.ends_with(&format!("/{file}")))
}

/// A write exclusion that keeps a repository's `.git` out of an allow rule:
/// the project's own (`.git/**`, [`ANY_GIT`]) or one below a directory
/// `moat allow --dir` granted (`/w/lib/.git/**`, `/w/lib/**/.git/**`).
pub fn git_exclusion(pattern: &str) -> bool {
    match spot(pattern) {
        Spot::Project(rest) => rest == ".git/**" || rest == ANY_GIT,
        Spot::Absolute(path) => path.ends_with("/.git/**"),
        Spot::Anywhere(_) => false,
    }
}

pub fn has_glob(pattern: &str) -> bool {
    pattern.contains(['*', '?', '[', ']', '{', '}'])
}

/// `dir` for `dir/**` or `dir` when it names one literal location.
pub fn literal_tree(pattern: &str) -> Option<&str> {
    let base = pattern.strip_suffix("/**").unwrap_or(pattern);
    (!base.is_empty() && !has_glob(base)).then_some(base)
}

/// Whether `entry` lies below the directory `node`. A root (`/`, `C:/`) already
/// ends in its separator, so `/` has every absolute path below it, not `//…`.
pub fn is_below(entry: &str, node: &str) -> bool {
    let prefix = if node.ends_with('/') {
        node.to_owned()
    } else {
        format!("{node}/")
    };
    entry.len() > prefix.len() && entry.starts_with(&prefix)
}

/// A rule's positive patterns and its exclusions (without the `!`).
pub fn split(patterns: &[String]) -> (Vec<&str>, Vec<&str>) {
    let (excluded, positive): (Vec<&str>, Vec<&str>) = patterns
        .iter()
        .map(String::as_str)
        .partition(|p| p.starts_with('!'));
    let excluded = excluded.into_iter().map(|p| &p[1..]).collect();
    (positive, excluded)
}

/// A host pattern a domain list takes as written: `name` or `*.name`, whose
/// last label has a letter, so it never matches an IP address.
pub fn domain(pattern: &str) -> bool {
    let name = pattern.strip_prefix("*.").unwrap_or(pattern);
    let label = |l: &str| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    name.split('.').all(label)
        && name
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.chars().any(|c| c.is_ascii_alphabetic()))
}

/// Append `value` unless it is already there, keeping first-seen order.
pub fn push_unique(list: &mut Vec<String>, value: String) {
    if !list.contains(&value) {
        list.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spots_and_shapes() {
        assert_eq!(spot("/__moat_project__"), Spot::Project(""));
        assert_eq!(spot("/__moat_project__/.git/**"), Spot::Project(".git/**"));
        assert_eq!(
            spot("/__moat_project__x"),
            Spot::Absolute("/__moat_project__x")
        );
        assert_eq!(spot("C:/x"), Spot::Absolute("C:/x"));
        assert_eq!(spot("**/.env"), Spot::Anywhere(".env"));
        assert_eq!(literal_tree("/h/.ssh/**"), Some("/h/.ssh"));
        assert_eq!(literal_tree("/h/**/.env"), None);
        assert_eq!(split(&["a".into(), "!b".into()]), (vec!["a"], vec!["b"]));
        assert!(is_below("/h/.ssh", "/h") && is_below("/h", "/") && is_below("C:/x", "C:/"));
        assert!(!is_below("/hx", "/h") && !is_below("/h", "/h") && !is_below("/", "/"));
        for ok in ["github.com", "*.crates.io", "localhost"] {
            assert!(domain(ok), "{ok}");
        }
        for bad in [
            "169.254.*",
            "fe80:*",
            "100.100.100.200",
            "*",
            "a*.b.com",
            "::1",
        ] {
            assert!(!domain(bad), "{bad}");
        }
    }

    /// [`RUNS_LATER`] and the default policy name the same files: `runs-later`
    /// asks for each, and `project-fs` leaves each out, so the ask is reached.
    #[test]
    fn runs_later_matches_the_default_policy() {
        let policy = openmoat_core::Policy::parse(openmoat_core::DEFAULT_POLICY).unwrap();
        let group = |groups: &[openmoat_core::RuleGroup], id: &str| {
            groups.iter().find(|g| g.id == id).unwrap().fs_write.clone()
        };
        let asked = group(&policy.ask, "runs-later");
        let allowed = group(&policy.allow, "project-fs");
        for file in RUNS_LATER {
            assert!(asked.iter().any(|p| p == file), "runs-later lacks {file}");
            let left_out = format!("!${{project}}/{file}");
            assert!(allowed.contains(&left_out), "project-fs lacks {left_out}");
        }
        let in_projects = asked.iter().filter(|p| p.starts_with("**/")).count();
        assert_eq!(in_projects, RUNS_LATER.len(), "{asked:?}");
    }

    /// Every agent configuration file is one `runs-later` asks for; CI files
    /// and commit-hook managers' files are not among them.
    #[test]
    fn agent_configuration_is_part_of_runs_later() {
        for file in AGENT_CONFIG {
            assert!(RUNS_LATER.contains(file), "{file}");
        }
        for file in [
            "**/.github/workflows/**",
            "**/.husky/**",
            "**/.vscode/tasks.json",
        ] {
            assert!(!AGENT_CONFIG.contains(&file), "{file}");
        }
        assert!(agent_config_exclusion("/__moat_project__/**/.mcp.json"));
        assert!(agent_config_exclusion("/w/lib/**/.claude/hooks/**"));
        assert!(!agent_config_exclusion("/__moat_project__/**/.husky/**"));
        assert!(runs_later_exclusion("/__moat_project__/**/.husky/**"));
        assert!(!agent_config_exclusion("**/.mcp.json"));
    }

    /// The folders above an agent's configuration are named too, so that
    /// renaming one cannot move a protected file out from under its pattern.
    #[test]
    fn the_folders_above_agent_configuration_are_named() {
        assert_eq!(folders_above("**/.github/hooks/**"), [".github"]);
        assert_eq!(folders_above("**/.cursor/mcp.json"), [".cursor"]);
        assert_eq!(
            folders_above("**/.github/copilot/settings.json"),
            [".github", ".github/copilot"]
        );
        assert!(folders_above("**/.mcp.json").is_empty());
        assert_eq!(
            agent_config_folders("/__moat_project__/**/.pi/extensions/**"),
            ["/__moat_project__/.pi"]
        );
        assert_eq!(
            agent_config_folders("/w/lib/**/.openclaw/extensions/**"),
            ["/w/lib/.openclaw"]
        );
        assert!(agent_config_folders("/__moat_project__/**/.mcp.json").is_empty());
        assert!(agent_config_folders("/__moat_project__/**/.husky/**").is_empty());
    }
}
