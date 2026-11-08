//! The policy's `taint:` section (ADR-020, docs/POLICY.md §4.1): what session
//! taint protects beyond the built-in list, which MCP tools return metadata
//! rather than content, and whether file provenance (ADR-029) is on. The
//! engine applies the lists in `engine/taint.rs`; the CLI keeps provenance in
//! the audit log.

use serde::{Deserialize, Serialize};

use crate::pattern::GlobPattern;
use crate::policy::PolicyError;

/// The MCP server whose tab and window tools are the built-in metadata tools:
/// Claude in Chrome, which Claude Code provides itself (`claude --chrome`, the
/// browser extension), not a server any MCP configuration file defines. A server a configuration or a
/// pin defines under this name is another program that took the name, and the
/// built-in list does not apply to it ([`TaintSettings::defined_servers`],
/// ADR-069).
pub const BUILTIN_METADATA_SERVER: &str = "claude-in-chrome";

/// MCP tools whose result is the browser's own bookkeeping, not the content of
/// a page: Claude in Chrome's tab, window, browser and shortcut lists (tab ids,
/// titles, URLs). Their results do not taint the session (ADR-057 amendment of
/// 2026-11-07), and are still read for injected input: a host, path or command
/// in a tab's title or URL is kept with the tool as its source. Every tool that
/// returns what a page says (`get_page_text`, `read_page`, `find`, `navigate`,
/// `javascript_tool`, the console and network logs, screenshots) is not listed.
/// They apply only while no configured server takes [`BUILTIN_METADATA_SERVER`].
const METADATA_TOOLS: [&str; 8] = [
    "mcp__claude-in-chrome__list_connected_browsers",
    "mcp__claude-in-chrome__resize_window",
    "mcp__claude-in-chrome__select_browser",
    "mcp__claude-in-chrome__shortcuts_list",
    "mcp__claude-in-chrome__switch_browser",
    "mcp__claude-in-chrome__tabs_close_mcp",
    "mcp__claude-in-chrome__tabs_context_mcp",
    "mcp__claude-in-chrome__tabs_create_mcp",
];

/// How every MCP tool's name starts (`mcp__<server>__<tool>`).
const MCP_PREFIX: &str = "mcp__";

/// Files whose change runs code or steers the agent later, beyond the edit
/// itself: CI, git hooks, editor tasks, the build and test definitions of every
/// ecosystem whose commands the default policy runs, and agent instructions and
/// settings. Writing them is ordinary work, until the session has read content an
/// attacker may control. Source and test files, including test-runner configs
/// written in JavaScript (`jest.config.js`), are not listed: they are code the run
/// executes like any other file, and the command that runs them is named in a
/// listed file (`package.json`).
const PROTECTED_WRITES: [&str; 162] = [
    "**/.github/workflows/**",
    "**/.gitlab-ci.yml",
    "**/.circleci/**",
    "**/azure-pipelines.yml",
    "**/Jenkinsfile",
    "**/.buildkite/**",
    "**/.husky/**",
    // the folders a repository's `core.hooksPath` usually names (`runs-later`)
    "**/.githooks/**",
    "**/.git-hooks/**",
    "**/githooks/**",
    "**/git-hooks/**",
    "**/.githooks",
    "**/.git-hooks",
    "**/githooks",
    "**/git-hooks",
    "**/.pre-commit-config.yaml",
    "**/lefthook.yml",
    "**/.lefthook.yml",
    "**/.vscode/**",
    // the editors' project configuration, which the editor runs (ADR-060)
    "**/.vscode",
    "**/*.code-workspace",
    "**/.idea/**",
    "**/.idea",
    "**/*.run.xml",
    // JavaScript: scripts, and package-manager settings that pick the script shell
    "**/package.json",
    "**/.npmrc",
    "**/bunfig.toml",
    "**/.yarnrc",
    "**/.yarnrc.yml",
    "**/pnpm-workspace.yaml",
    // make, just, task
    "**/Makefile",
    "**/makefile",
    "**/GNUmakefile",
    "**/*.mk",
    "**/justfile",
    "**/Justfile",
    "**/.justfile",
    "**/Taskfile.yml",
    "**/Taskfile.yaml",
    // Rust: build scripts, `[build]`/`runner` settings
    "**/build.rs",
    "**/Cargo.toml",
    "**/.cargo/config",
    "**/.cargo/config.toml",
    // Go: a `toolchain` line downloads and runs another Go
    "**/go.mod",
    "**/go.work",
    // CMake
    "**/CMakeLists.txt",
    "**/*.cmake",
    "**/CMakePresets.json",
    "**/CMakeUserPresets.json",
    // Maven
    "**/pom.xml",
    "**/.mvn/**",
    "**/mvnw",
    "**/mvnw.cmd",
    // Gradle
    "**/*.gradle",
    "**/*.gradle.kts",
    "**/gradle.properties",
    "**/gradlew",
    "**/gradlew.bat",
    "**/gradle/wrapper/**",
    // .NET: projects and the MSBuild files they import
    "**/*.csproj",
    "**/*.fsproj",
    "**/*.vbproj",
    "**/*.props",
    "**/*.targets",
    "**/global.json",
    "**/NuGet.config",
    "**/nuget.config",
    // Ruby
    "**/Rakefile",
    "**/*.rake",
    "**/Gemfile",
    "**/*.gemspec",
    "**/.rspec",
    // PHP
    "**/composer.json",
    "**/artisan",
    "**/phpunit.xml",
    "**/phpunit.xml.dist",
    // Python: pytest loads `conftest.py` and its config before any test
    "**/conftest.py",
    "**/pytest.ini",
    "**/pyproject.toml",
    "**/setup.py",
    "**/setup.cfg",
    "**/tox.ini",
    "**/noxfile.py",
    // what every Python start runs (`runs-later`)
    "**/site-packages/*.pth",
    "**/dist-packages/*.pth",
    "**/sitecustomize.py",
    "**/usercustomize.py",
    "**/.venv/bin/**",
    "**/venv/bin/**",
    "**/.venv/bin",
    "**/venv/bin",
    "**/.devcontainer/**",
    "**/.devcontainer",
    "**/.devcontainer.json",
    // containers
    "**/Dockerfile",
    "**/docker-compose*.yml",
    "**/docker-compose*.yaml",
    "**/compose*.yml",
    "**/compose*.yaml",
    // agents
    "**/CLAUDE.md",
    "**/AGENTS.md",
    "**/.claude/**",
    "**/.claude.json",
    "**/.codex/**",
    "**/.cursor/**",
    "**/.cursorrules",
    "**/.mcp.json",
    // instruction files and skills the next session of an agent obeys
    // (ADR-057): the shared `.agents/skills` folder several agents load,
    // Windsurf's rules, and GitHub Copilot's path-scoped instructions
    "**/.agents/skills",
    "**/.agents/skills/**",
    "**/.windsurfrules",
    "**/.windsurf/rules/**",
    "**/.github/instructions/**",
    // generated:taint from each host spec's `protect.taint` (openmoat-hosts `tests/protect.rs`)
    // Continue CLI: its configuration, whose MCP servers it starts
    "**/.continue/config.yaml",
    // OpenClaw: its configuration, OpenMoat's plugin and the plugin directories the
    // Gateway loads; not the whole state directory, whose workspace is ordinary work
    "**/.openclaw",
    "**/.openclaw/openclaw.json",
    "**/.openclaw/openmoat",
    "**/.openclaw/openmoat/**",
    "**/.openclaw/extensions/**",
    // the database where the Gateway keeps cron jobs and exec approvals
    "**/.openclaw/state/**",
    // GitHub Copilot CLI: its hooks, settings, MCP servers, plugins and custom
    // agents, not its session folders; a repository's hooks, settings and
    // instructions
    "**/.copilot",
    "**/.copilot/hooks",
    "**/.copilot/hooks/**",
    "**/.copilot/settings.json",
    "**/.copilot/config.json",
    "**/.copilot/mcp-config.json",
    "**/.copilot/installed-plugins/**",
    "**/.copilot/agents/**",
    "**/.github/hooks/**",
    "**/.github/mcp.json",
    "**/.github/agents/**",
    "**/.github/copilot/**",
    "**/.github/copilot-instructions.md",
    // pi: its agent directory (extensions, settings, trust decisions) and a
    // project's `.pi` (extensions, settings, MCP servers, system prompt)
    "**/.pi",
    "**/.pi/**",
    // Gemini CLI: its settings, extensions and the memory file it loads into
    // every session
    "**/GEMINI.md",
    "**/.gemini",
    "**/.gemini/**",
    // OpenCode: its configuration directory, a project's `.opencode` and
    // `opencode.json[c]` (plugins, custom tools, commands, MCP servers, permission
    // rules) and the npm plugins it caches
    "**/.config/opencode",
    "**/.config/opencode/**",
    "**/.opencode",
    "**/.opencode/**",
    "**/opencode.json",
    "**/opencode.jsonc",
    "**/.cache/opencode/node_modules/**",
    // Hermes Agent: the skills, cron jobs, memories and persona it loads into
    // later sessions, and a project's `.hermes.md` and plugins
    "~/.hermes/skills/**",
    "~/.hermes/cron/**",
    "~/.hermes/memories/**",
    "~/.hermes/SOUL.md",
    "**/.hermes.md",
    "**/.hermes/**",
    // Cline: its directory (settings, MCP servers, hooks, plugins), the
    // rules, workflows and hooks in `Documents/Cline`, and a project's `.cline`
    // and `.clinerules` (hooks, plugins, rules)
    "**/.cline",
    "**/.cline/**",
    "**/Documents/Cline/**",
    "**/.clinerules",
    "**/.clinerules/**",
    // goose: the hints it loads into every session, its configuration, saved
    // recipes and plugin settings, and the plugins whose hooks it runs
    "**/.goosehints",
    "~/.config/goose",
    "~/.config/goose/**",
    "**/.config/goose/**",
    "**/.agents/plugins",
    "**/.agents/plugins/**",
    // /generated
    // OpenMoat's own state (`kernel-self` denies it outright)
    "**/.moat/**",
];

/// The `taint:` section. Absent in policies written before it existed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaintSettings {
    /// Path globs whose writes need review once the session read untrusted content, in
    /// addition to the built-in list, which a policy cannot shorten. No `!`
    /// exclusions, for the same reason.
    #[serde(default)]
    pub protected_writes: Vec<String>,
    /// MCP tools, by full name (`mcp__<server>__<tool>`), whose result is the
    /// server's own metadata rather than content an attacker writes, in
    /// addition to the built-in list: their results do not taint the session,
    /// and their output still feeds injected input (ADR-057).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metadata_tools: Vec<String>,
    /// MCP servers, by name, that an agent's MCP configuration or OpenMoat's
    /// pins define. The built-in metadata tools are those of a server the
    /// host provides itself ([`BUILTIN_METADATA_SERVER`]); one defined here
    /// under that name is not it, and every tool of it taints the session.
    /// The CLI adds the names it finds pinned; a policy may list more, which
    /// can only make more results taint. `metadata_tools` still counts: a
    /// person who lists a tool there trusts it by its full name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub defined_servers: Vec<String>,
    /// File provenance (ADR-029): a file a session wrote after reading
    /// untrusted content taints the sessions that later read or run it.
    /// Absent means on; `false` turns it off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<bool>,
}

impl TaintSettings {
    /// Whether file provenance is on under `settings` (the policy's `taint:`
    /// section, if any). On unless the section says `provenance: false`.
    #[must_use]
    pub fn provenance_on(settings: Option<&Self>) -> bool {
        settings.and_then(|s| s.provenance).unwrap_or(true)
    }
}

/// The built-in protected paths followed by the ones `settings` adds.
pub(crate) fn protected_writes(settings: Option<&TaintSettings>) -> impl Iterator<Item = &str> {
    PROTECTED_WRITES.into_iter().chain(
        settings
            .into_iter()
            .flat_map(|s| s.protected_writes.iter().map(String::as_str)),
    )
}

/// Whether the MCP tool `name` returns metadata (the built-in list, unless a
/// configured server took its server's name, and the ones `settings` adds),
/// whose result does not taint the session.
pub(crate) fn is_metadata_tool(settings: Option<&TaintSettings>, name: &str) -> bool {
    let impostor = settings.is_some_and(|s| {
        s.defined_servers
            .iter()
            .any(|server| server == BUILTIN_METADATA_SERVER)
    });
    (METADATA_TOOLS.contains(&name) && !impostor)
        || settings.is_some_and(|s| s.metadata_tools.iter().any(|tool| tool == name))
}

/// Each added path is a glob that compiles and is not an exclusion, which
/// would take a built-in path out of protection; each added metadata tool is
/// one MCP tool's full name.
pub(crate) fn check(settings: Option<&TaintSettings>) -> Result<(), PolicyError> {
    check_protected_writes(settings)?;
    check_metadata_tools(settings)
}

fn check_protected_writes(settings: Option<&TaintSettings>) -> Result<(), PolicyError> {
    let problem = |problem: String| PolicyError::Rule {
        rule: "taint.protected_writes".to_owned(),
        problem,
    };
    for p in settings.iter().flat_map(|s| &s.protected_writes) {
        if p.trim_start().starts_with('!') {
            return Err(problem(format!(
                "`{p}` is an exclusion; the list can only add paths"
            )));
        }
        GlobPattern::compile(p, false).map_err(|e| problem(e.to_string()))?;
    }
    Ok(())
}

/// Names are compared exactly, so a glob would match no tool: each entry is
/// one full `mcp__<server>__<tool>` name.
fn check_metadata_tools(settings: Option<&TaintSettings>) -> Result<(), PolicyError> {
    let Some(bad) = settings
        .iter()
        .flat_map(|s| &s.metadata_tools)
        .find(|name| !is_tool_name(name))
    else {
        return Ok(());
    };
    Err(PolicyError::Rule {
        rule: "taint.metadata_tools".to_owned(),
        problem: format!(
            "`{bad}` is not one MCP tool's full name (`mcp__<server>__<tool>`, no wildcards)"
        ),
    })
}

/// Whether `name` is `mcp__<server>__<tool>` with both parts present and no
/// space or glob character.
fn is_tool_name(name: &str) -> bool {
    let plain = !name
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '*' | '?' | '[' | ']' | '{' | '}' | '!'));
    plain
        && name
            .strip_prefix(MCP_PREFIX)
            .and_then(|rest| rest.split_once("__"))
            .is_some_and(|(server, tool)| !server.is_empty() && !tool.is_empty())
}

#[cfg(test)]
mod tests {
    use crate::policy::{Policy, PolicyError};

    #[test]
    fn protected_writes_must_be_plain_globs() {
        let ok = "version: 1\ntaint:\n  protected_writes: ['**/deploy/**', '${project}/run.sh']\n";
        assert_eq!(
            Policy::parse(ok)
                .unwrap()
                .taint
                .unwrap()
                .protected_writes
                .len(),
            2
        );
        assert!(Policy::parse("version: 1\ntaint: {}\n").is_ok());
        for bad in ["'**/[x'", "'!**/package.json'", "''"] {
            let yaml = format!("version: 1\ntaint:\n  protected_writes: [{bad}]\n");
            assert!(
                matches!(Policy::parse(&yaml), Err(PolicyError::Rule { rule, .. }) if rule == "taint.protected_writes"),
                "{bad} must be rejected"
            );
        }
        assert!(Policy::parse("version: 1\ntaint: { bogus: [] }\n").is_err());
    }

    #[test]
    fn metadata_tools_are_full_mcp_tool_names() {
        let yaml = |list: &str| format!("version: 1\ntaint:\n  metadata_tools: [{list}]\n");
        let ok = Policy::parse(&yaml("mcp__tabs__list_tabs")).unwrap();
        let settings = ok.taint.as_ref();
        assert!(super::is_metadata_tool(settings, "mcp__tabs__list_tabs"));
        assert!(super::is_metadata_tool(
            settings,
            "mcp__claude-in-chrome__tabs_context_mcp"
        ));
        assert!(!super::is_metadata_tool(settings, "mcp__tabs__read_tab"));
        assert!(!super::is_metadata_tool(
            None,
            "mcp__claude-in-chrome__get_page_text"
        ));
        for bad in [
            "'mcp__tabs__*'",
            "list_tabs",
            "'mcp__tabs__'",
            "'mcp____x'",
            "''",
        ] {
            assert!(
                matches!(Policy::parse(&yaml(bad)), Err(PolicyError::Rule { rule, .. }) if rule == "taint.metadata_tools"),
                "{bad} must be rejected"
            );
        }
    }

    /// The built-in list names only tools that list tabs, windows, browsers or
    /// shortcuts: none of Claude in Chrome's page-content tools.
    #[test]
    fn built_in_metadata_tools_leave_page_content_tools_out() {
        for tool in [
            "get_page_text",
            "read_page",
            "find",
            "navigate",
            "javascript_tool",
            "read_console_messages",
            "read_network_requests",
            "computer",
            "gif_creator",
            "upload_image",
            "form_input",
            "file_upload",
            "shortcuts_execute",
            "browser_batch",
        ] {
            let name = format!("mcp__claude-in-chrome__{tool}");
            assert!(!super::is_metadata_tool(None, &name), "{name}");
        }
        assert!(super::METADATA_TOOLS.iter().all(|t| super::is_tool_name(t)));
    }

    #[test]
    fn provenance_is_on_unless_the_policy_turns_it_off() {
        use super::TaintSettings;
        let on =
            |yaml: &str| TaintSettings::provenance_on(Policy::parse(yaml).unwrap().taint.as_ref());
        assert!(on("version: 1\n"));
        assert!(on("version: 1\ntaint: {}\n"));
        assert!(on("version: 1\ntaint: { provenance: true }\n"));
        assert!(!on("version: 1\ntaint: { provenance: false }\n"));
        assert!(Policy::parse("version: 1\ntaint: { provenance: maybe }\n").is_err());
    }

    /// A path a `fs.write` pattern of the default policy names: `~` as a home,
    /// `**/` as a project, a trailing `/**` as a file below, `*` as a word.
    fn sample(pattern: &str) -> String {
        let path = pattern
            .replacen('~', "/home/u", 1)
            .replacen("**/", "/home/u/work/repo/", 1);
        let path = match path.strip_suffix("/**") {
            Some(dir) => format!("{dir}/x"),
            None => path,
        };
        path.replace('*', "v1")
    }

    /// One list of "files that run later": every file `runs-later` holds for review and
    /// every OpenMoat or host config file `kernel-self` denies is also a write
    /// session taint protects. (`sandbox/patterns.rs` `RUNS_LATER` is checked
    /// against `runs-later` in the CLI.)
    #[test]
    fn protected_writes_cover_runs_later_and_the_kernel_config_files() {
        let policy = Policy::parse(crate::DEFAULT_POLICY).unwrap();
        let protected: Vec<_> = super::PROTECTED_WRITES
            .iter()
            .map(|p| crate::pattern::GlobPattern::compile(p, false).unwrap())
            .collect();
        let rule = |groups: &[crate::RuleGroup], id: &str| {
            groups.iter().find(|g| g.id == id).unwrap().fs_write.clone()
        };
        let mut files = rule(&policy.review, "runs-later");
        // the binary is not a file that runs later as configuration does
        files.extend(rule(&policy.deny, "kernel-self").into_iter().filter(|p| {
            !["/bin/moat", "apps/moat", "/bin/openmoat", "apps/openmoat"]
                .iter()
                .any(|binary| p.contains(binary))
        }));
        assert!(files.len() > 30, "{files:?}");
        for pattern in &files {
            let path = sample(pattern);
            assert!(
                protected.iter().any(|g| g.is_match(&path)),
                "`{pattern}` ({path}) is not in PROTECTED_WRITES"
            );
        }
    }
}
