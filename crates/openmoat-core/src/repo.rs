//! Repository policy: `<project>/.moat/policy.yaml`, committed by a team
//! (docs/POLICY.md §9, ADR-022).
//!
//! A repository is input the person did not write, so by itself its policy
//! only makes the user policy stricter: its deny rules join the user's, and its
//! ask rules are tried before the user's allow rules. Its allow rules widen the
//! user policy only once a person has trusted that exact file (`moat trust`);
//! the caller decides that and passes it to [`RepoPolicy::merge`].

use serde::Deserialize;

use crate::policy::{Policy, PolicyError, RuleGroup};

/// Prefix of every rule id a repository policy contributes, so decisions and
/// the audit log say where a rule came from, and a repository rule can never
/// pass for one of the user's (`kernel-self`) or collide with it.
pub const REPO_RULE_PREFIX: &str = "repo:";

/// A repository policy. Only rules: `defaults`, `executables` and `sandbox`
/// stay the user's, so any other key is a parse error.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoPolicy {
    /// Schema version; only 1 is supported.
    pub version: u32,
    /// Added to the user's deny rules.
    #[serde(default)]
    pub deny: Vec<RuleGroup>,
    /// Added to the user's allow rules, only when the file is trusted.
    #[serde(default)]
    pub allow: Vec<RuleGroup>,
    /// Tried before the user's allow rules.
    #[serde(default)]
    pub ask: Vec<RuleGroup>,
}

impl RepoPolicy {
    /// Parse and lint a repository policy. Pure: takes the YAML text.
    pub fn parse(yaml: &str) -> Result<Self, PolicyError> {
        let repo: Self = crate::yaml::from_str(yaml).map_err(PolicyError::Parse)?;
        // Every key it has is a policy key, so the policy lint checks the
        // version, the ids and every pattern the same way.
        Policy::parse(yaml)?;
        Ok(repo)
    }

    /// `user` with this policy merged in; its allow rules only when `trusted`.
    /// The user's deny rules still come first, so even a trusted repository
    /// cannot allow what the user denies.
    pub fn merge(&self, user: &Policy, trusted: bool) -> Result<Policy, PolicyError> {
        let mut merged = user.clone();
        merged.deny.extend(prefixed(&self.deny));
        merged.repo_ask.extend(prefixed(&self.ask));
        if trusted {
            merged.allow.extend(prefixed(&self.allow));
        }
        merged.lint()?;
        Ok(merged)
    }
}

fn prefixed(groups: &[RuleGroup]) -> impl Iterator<Item = RuleGroup> + '_ {
    groups.iter().map(|g| RuleGroup {
        id: format!("{REPO_RULE_PREFIX}{}", g.id),
        ..g.clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, CompiledPolicy, EvalContext, Verdict};

    const USER: &str = "version: 1\ndefaults: { '*': ask, net: deny }\n\
        deny:\n  - id: secrets\n    fs.read: ['~/.ssh/**']\n\
        allow:\n  - id: dev\n    shell: ['cargo *', 'git status']\n";

    fn decide(merged: &Policy, command: &str) -> (Verdict, Vec<String>) {
        let ctx = EvalContext {
            home: "/h".into(),
            project: Some("/p".into()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: "/p".into(),
            case_insensitive_paths: false,
        };
        let d = CompiledPolicy::compile(merged, &ctx)
            .unwrap()
            .decide(&Action::Shell {
                command: command.into(),
            });
        (d.verdict, d.rules)
    }

    fn merged(repo: &str, trusted: bool) -> Policy {
        let user = Policy::parse(USER).unwrap();
        RepoPolicy::parse(repo)
            .unwrap()
            .merge(&user, trusted)
            .unwrap()
    }

    #[test]
    fn deny_and_ask_tighten_what_the_user_allows() {
        let repo = "version: 1\ndeny:\n  - id: no-status\n    shell: ['git status']\n\
            ask:\n  - id: publish\n    shell: ['cargo publish']\n";
        let p = merged(repo, false);
        assert_eq!(
            decide(&p, "git status"),
            (Verdict::Deny, vec!["repo:no-status".into()])
        );
        assert_eq!(
            decide(&p, "cargo publish"),
            (Verdict::Ask, vec!["repo:publish".into()])
        );
        assert_eq!(decide(&p, "cargo test").0, Verdict::Allow);
    }

    #[test]
    fn allow_rules_widen_only_when_trusted_and_never_past_a_deny() {
        let repo = "version: 1\nallow:\n  - id: wide\n    shell: ['make *', 'cat *']\n    \
            fs.read: ['~/.ssh/**']\n";
        assert_eq!(decide(&merged(repo, false), "make deploy").0, Verdict::Ask);
        let trusted = merged(repo, true);
        assert_eq!(
            decide(&trusted, "make deploy"),
            (Verdict::Allow, vec!["repo:wide".into()])
        );
        assert_eq!(
            decide(&trusted, "cat ~/.ssh/id_rsa"),
            (Verdict::Deny, vec!["secrets".into()])
        );
    }

    #[test]
    fn a_repo_ask_still_loses_to_a_user_deny() {
        let repo = "version: 1\nask:\n  - id: keys\n    fs.read: ['~/.ssh/**']\n";
        assert_eq!(
            decide(&merged(repo, false), "cat ~/.ssh/id_rsa"),
            (Verdict::Deny, vec!["secrets".into()])
        );
    }

    #[test]
    fn rule_ids_are_prefixed_so_they_cannot_pose_as_the_users() {
        let repo = "version: 1\ndeny:\n  - id: secrets\n    shell: ['ls']\n";
        let p = merged(repo, false);
        let ids: Vec<&str> = p.deny.iter().map(|g| g.id.as_str()).collect();
        assert_eq!(ids, ["secrets", "repo:secrets"]);
    }

    #[test]
    fn rejects_everything_but_rules_and_bad_rules() {
        for bad in [
            "version: 1\ndefaults: allow\n",
            "version: 1\ndefaults: { net: allow }\n",
            "version: 1\nexecutables:\n  git: ['/tmp/git']\n",
            "version: 1\nsandbox:\n  read_roots: ['/etc']\n",
            "version: 1\nrepo_ask: []\n",
            "version: 2\n",
            "version: 1\ndeny:\n  - id: a\n",
            "version: 1\ndeny:\n  - id: a\n    shell: ['x']\nask:\n  - id: a\n    shell: ['y']\n",
            "deny: []\n",
        ] {
            assert!(RepoPolicy::parse(bad).is_err(), "{bad} must be rejected");
        }
    }
}
