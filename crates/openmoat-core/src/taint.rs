//! The policy's `taint:` section (ADR-020, docs/POLICY.md §4.1): what session
//! taint protects beyond the built-in list. The engine applies it in
//! `engine/taint.rs`.

use serde::{Deserialize, Serialize};

use crate::pattern::GlobPattern;
use crate::policy::PolicyError;

/// Files whose change runs code or steers the agent later, beyond the edit
/// itself: CI, git hooks, editor tasks, the build and test definitions of every
/// ecosystem whose commands the default policy runs, and agent instructions and
/// settings. Writing them is ordinary work, until the session has read content an
/// attacker may control. Source and test files, including test-runner configs
/// written in JavaScript (`jest.config.js`), are not listed: they are code the run
/// executes like any other file, and the command that runs them is named in a
/// listed file (`package.json`).
const PROTECTED_WRITES: [&str; 84] = [
    "**/.github/workflows/**",
    "**/.gitlab-ci.yml",
    "**/.circleci/**",
    "**/azure-pipelines.yml",
    "**/Jenkinsfile",
    "**/.buildkite/**",
    "**/.husky/**",
    "**/.githooks/**",
    "**/.pre-commit-config.yaml",
    "**/lefthook.yml",
    "**/.lefthook.yml",
    "**/.vscode/**",
    // JavaScript: scripts, and package-manager settings that pick the script shell
    "**/package.json",
    "**/.npmrc",
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
    // OpenMoat's own state (`kernel-self` denies it outright)
    "**/.moat/**",
];

/// The `taint:` section. Absent in policies written before it existed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaintSettings {
    /// Path globs a write to asks once the session read untrusted content, in
    /// addition to the built-in list, which a policy cannot shorten. No `!`
    /// exclusions, for the same reason.
    #[serde(default)]
    pub protected_writes: Vec<String>,
}

/// The built-in protected paths followed by the ones `settings` adds.
pub(crate) fn protected_writes(settings: Option<&TaintSettings>) -> impl Iterator<Item = &str> {
    PROTECTED_WRITES.into_iter().chain(
        settings
            .into_iter()
            .flat_map(|s| s.protected_writes.iter().map(String::as_str)),
    )
}

/// Each added path is a glob that compiles and is not an exclusion, which
/// would take a built-in path out of protection.
pub(crate) fn check(settings: Option<&TaintSettings>) -> Result<(), PolicyError> {
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

    /// One list of "files that run later": every file `runs-later` asks for and
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
        let mut files = rule(&policy.ask, "runs-later");
        // the binary is not a file that runs later as configuration does
        files.extend(
            rule(&policy.deny, "kernel-self")
                .into_iter()
                .filter(|p| !p.contains("/bin/moat") && !p.contains("apps/moat")),
        );
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
