//! What a change touches that the policy protects (ADR-050).
//!
//! Every path a change writes (added, edited, deleted, renamed from or to) is
//! decided by the core engine as an `fs.write` inside a project, with session
//! taint set as after reading untrusted content: a pull request is content
//! nobody on this machine wrote. So the default policy's `deny` rules
//! (`kernel-self`, `secrets-paths`) give `deny`, and its `review` rules and the
//! files session taint protects (CI, hooks, build and package files, agent
//! settings) give `review`. No path list lives here.
//!
//! On top of the engine, what only a diff shows: a path that leaves the
//! repository, a symbolic link and where it points, a submodule, a change to
//! the policy files the check itself read, and added lines holding a known
//! token shape (`openmoat_audit::token_shape`, the push check's scanner).
//!
//! And what the added lines do (ADR-055, `content.rs`): the core's content
//! checks, at the levels the policy's `check_diff.levels` sets.

use anyhow::Result;
use openmoat_core::diffscan::Settings;
use openmoat_core::{
    Action, CompiledPolicy, Decision, EvalContext, NoResolver, Policy, TAINT_RULE, Taint, Verdict,
};
use serde::Serialize;

use super::parse::FileChange;

mod content;

/// Where the repository is placed for the engine. Not a real directory: no
/// file is read, and it is outside any home so no `~/` rule meets it.
const ROOT: &str = "/openmoat-diff/repo";
const HOME: &str = "/openmoat-diff/home";

/// What the untrusted content of every change is, in the engine's taint.
const UNTRUSTED: &str = "the change under review";

pub const PATH_RULE: &str = "diff-path";
pub const SECRET_RULE: &str = "diff-secret";
pub const POLICY_RULE: &str = "diff-policy";
pub const LINK_RULE: &str = "diff-link";
pub const SUBMODULE_RULE: &str = "diff-submodule";
pub const UNCHECKED_RULE: &str = "diff-unchecked";

/// git's modes for a symbolic link and a submodule.
const LINK_MODE: &str = "120000";
const SUBMODULE_MODE: &str = "160000";

/// How much a finding holds up a merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// A person should look before it is merged: the policy holds it for review.
    Review,
    /// The policy denies it.
    Deny,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Deny => "deny",
        }
    }

    fn of(verdict: Verdict) -> Option<Self> {
        match verdict {
            Verdict::Deny => Some(Self::Deny),
            Verdict::Review => Some(Self::Review),
            _ => None,
        }
    }
}

/// One thing a change does that the policy protects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub level: Level,
    /// The path in the repository, `/`-separated, as the diff names it.
    pub path: String,
    /// The line in the new file, for an added line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub rules: Vec<String>,
    pub reasons: Vec<String>,
}

impl Finding {
    fn new(level: Level, path: &str, rule: &str, reason: String) -> Self {
        Self {
            level,
            path: path.to_owned(),
            line: None,
            rules: vec![rule.to_owned()],
            reasons: vec![reason],
        }
    }

    /// Add `other`, about the same path: the stricter level, every rule and reason.
    fn absorb(&mut self, other: Self) {
        self.level = self.level.max(other.level);
        for rule in other.rules {
            if !self.rules.contains(&rule) {
                self.rules.push(rule);
            }
        }
        for reason in other.reasons {
            if !self.reasons.contains(&reason) {
                self.reasons.push(reason);
            }
        }
    }
}

/// Where a path of the diff lands.
#[derive(Debug, PartialEq, Eq)]
enum Placed {
    /// Inside the repository, `/`-separated with `.` and `..` collapsed.
    Inside(String),
    /// Absolute, or above the repository root.
    Outside,
}

/// `raw` taken from the directory `dir` of the repository (`""` for the
/// root). `\` counts as a separator too, as on Windows.
fn place(raw: &str, dir: &str) -> Placed {
    let unified = raw.replace('\\', "/");
    let drive = unified.as_bytes().get(1) == Some(&b':');
    if unified.starts_with('/') || drive {
        return Placed::Outside;
    }
    let mut segments: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
    for segment in unified.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return Placed::Outside;
                }
            }
            name => segments.push(name),
        }
    }
    Placed::Inside(segments.join("/"))
}

/// `path` as Windows opens it: each name without trailing dots and spaces,
/// which NTFS drops (`.github./workflows` is `.github/workflows`).
fn windows_spelling(path: &str) -> String {
    path.split('/')
        .map(|s| s.trim_end_matches(['.', ' ']))
        .map(|s| if s.is_empty() { "_" } else { s })
        .collect::<Vec<_>>()
        .join("/")
}

/// The policy compiled for checking changes, and the repository paths of the
/// policy files the check read, whose change it reports.
pub struct Gate<'p> {
    policy: CompiledPolicy<'p>,
    policy_files: Vec<String>,
    /// The policy's `check_diff:` section.
    settings: Option<&'p Settings>,
}

impl<'p> Gate<'p> {
    /// File paths compare without letter case: a change merged here may be
    /// checked out on macOS or Windows, where `.Claude/Settings.json` is
    /// `.claude/settings.json`.
    pub fn new(policy: &'p Policy, policy_files: &[String]) -> Result<Self> {
        let ctx = EvalContext {
            home: HOME.to_owned(),
            project: Some(ROOT.to_owned()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: ROOT.to_owned(),
            case_insensitive_paths: true,
        };
        let policy_files = policy_files
            .iter()
            .filter_map(|p| match place(p, "") {
                Placed::Inside(p) => Some(p.to_lowercase()),
                Placed::Outside => None,
            })
            .collect();
        Ok(Self {
            policy: CompiledPolicy::compile(policy, &ctx)?,
            policy_files,
            settings: policy.check_diff.as_ref(),
        })
    }

    /// Every finding of `files`, one per path and one per added line a check
    /// finds something on, in the order of the diff; new hosts last.
    pub fn check(&self, files: &[FileChange]) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();
        let mut add = |finding: Finding| match findings
            .iter_mut()
            .find(|f| f.path == finding.path && f.line == finding.line)
        {
            Some(found) => found.absorb(finding),
            None => findings.push(finding),
        };
        for file in files {
            for path in file.paths() {
                self.path_findings(path).into_iter().for_each(&mut add);
            }
            self.mode_findings(file).into_iter().for_each(&mut add);
            secret_findings(file).into_iter().for_each(&mut add);
            content::findings(self.settings, file)
                .into_iter()
                .for_each(&mut add);
        }
        content::host_findings(&self.policy, self.settings, files)
            .into_iter()
            .for_each(&mut add);
        findings
    }

    fn path_findings(&self, raw: &str) -> Vec<Finding> {
        let path = match place(raw, "") {
            Placed::Inside(path) if !path.is_empty() && !path.contains('\0') => path,
            _ => {
                return vec![Finding::new(
                    Level::Deny,
                    raw,
                    PATH_RULE,
                    "the path leaves the repository or is not a file name git checks out"
                        .to_owned(),
                )];
            }
        };
        let mut findings = Vec::new();
        if let Some(finding) = self.decided(raw, &path, None) {
            findings.push(finding);
        }
        if self.policy_files.contains(&path.to_lowercase()) {
            findings.push(Finding::new(
                Level::Review,
                raw,
                POLICY_RULE,
                "changes a policy file this check reads; checked from git, the check reads \
                 the base revision's copy, so the change applies only once it is merged"
                    .to_owned(),
            ));
        }
        findings
    }

    /// The engine's decision for writing `path` (and its Windows spelling), as
    /// a finding on `shown`; `via` names the link it is reached through.
    fn decided(&self, shown: &str, path: &str, via: Option<&str>) -> Option<Finding> {
        let mut decision = self.write(path);
        let windows = windows_spelling(path);
        if windows != path {
            let other = self.write(&windows);
            if other.verdict > decision.verdict {
                decision = other;
            }
        }
        let level = Level::of(decision.verdict)?;
        // Session taint's reason speaks of a session; for a change, say what it means.
        let tainted = decision.rules.iter().any(|r| r == TAINT_RULE);
        let reasons = decision
            .reasons
            .iter()
            .map(|reason| {
                let reason = if tainted && reason.contains(UNTRUSTED) {
                    "CI, a build or test tool, a commit hook or an AI agent runs or reads this \
                     file later"
                        .to_owned()
                } else {
                    reason.replace(&format!("{ROOT}/"), "")
                };
                match via {
                    Some(target) => format!("through the link to {target}: {reason}"),
                    None => reason,
                }
            })
            .collect();
        Some(Finding {
            level,
            path: shown.to_owned(),
            line: None,
            rules: decision.rules,
            reasons,
        })
    }

    fn write(&self, path: &str) -> Decision {
        let action = Action::FsWrite {
            path: format!("{ROOT}/{path}"),
        };
        let taint = Taint {
            secrets: Vec::new(),
            untrusted: Some(UNTRUSTED.to_owned()),
        };
        let decision = self.policy.decide(&action);
        self.policy
            .with_taint(decision, &action, &NoResolver, &taint)
    }

    /// A symbolic link (and what it points to) or a submodule the change adds or changes.
    fn mode_findings(&self, file: &FileChange) -> Vec<Finding> {
        let mut findings = Vec::new();
        let Some(shown) = file.new.as_deref().or(file.old.as_deref()) else {
            return findings;
        };
        let modes = [file.old_mode.as_deref(), file.new_mode.as_deref()];
        if modes.contains(&Some(SUBMODULE_MODE)) {
            findings.push(Finding::new(
                Level::Review,
                shown,
                SUBMODULE_RULE,
                "changes a submodule: the commit it points to is not in this diff, and its \
                 code was not checked"
                    .to_owned(),
            ));
        }
        let Some(new) = file.new.as_deref() else {
            return findings;
        };
        if file.new_mode.as_deref() != Some(LINK_MODE) {
            return findings;
        }
        let Some((_, target)) = file.added.first() else {
            findings.push(Finding::new(
                Level::Review,
                new,
                LINK_RULE,
                "makes a symbolic link whose target the diff does not show".to_owned(),
            ));
            return findings;
        };
        let dir = new.rsplit_once('/').map_or("", |(dir, _)| dir);
        let reason = match place(target, dir) {
            Placed::Inside(inside) => {
                findings.extend(self.decided(new, &inside, Some(target)));
                format!(
                    "makes a symbolic link to {target}: what later reads or writes {new} \
                     reaches that file instead"
                )
            }
            Placed::Outside => format!(
                "makes a symbolic link to {target}, outside the repository: what later reads \
                 or writes {new} reaches a file of the machine it is checked out on"
            ),
        };
        findings.push(Finding::new(Level::Review, new, LINK_RULE, reason));
        findings
    }
}

/// Each added line of `file` that holds a known token shape. The value is never named.
fn secret_findings(file: &FileChange) -> Vec<Finding> {
    let Some(path) = file.new.as_deref() else {
        return Vec::new();
    };
    file.added
        .iter()
        .filter_map(|(line, text)| {
            let shape = openmoat_audit::token_shape(text)?;
            Some(Finding {
                line: Some(*line),
                ..Finding::new(
                    Level::Deny,
                    path,
                    SECRET_RULE,
                    format!(
                        "adds {shape}; the change already published it to whoever can read it, \
                         so revoke it and remove it from the commits"
                    ),
                )
            })
        })
        .collect()
}

/// The finding for a diff that was not read in full.
pub fn unchecked(why: String) -> Finding {
    Finding::new(Level::Review, "", UNCHECKED_RULE, why)
}

#[cfg(test)]
pub(super) fn placed_inside(raw: &str, dir: &str) -> Option<String> {
    match place(raw, dir) {
        Placed::Inside(p) => Some(p),
        Placed::Outside => None,
    }
}
