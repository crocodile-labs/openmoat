//! Argument conditions on a rule group (`when:`, ADR-113, docs/POLICY.md §2.4):
//! typed tests of what a tool call's arguments hold, in the manner of Progent's
//! tool-call privilege policies. A group with conditions matches a call only
//! when one of its patterns matches the call and every condition holds, so a
//! condition can only narrow the group it is on. Conditions are allowed on
//! `deny` and `review` groups alone: they never make a call allowed, and an OS
//! layer, which cannot read arguments, applies such a group to every access its
//! patterns name (`ir::lower`), which is narrower still.
//!
//! The engine evaluates them in `engine/arguments.rs`; this module is the
//! policy file's model and its checks.

use serde::{Deserialize, Serialize};

use crate::pattern::GlobPattern;
use crate::policy::{PolicyError, RuleGroup};

/// The argument names a condition reads: one, several, or `*` for every value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ArgNames {
    /// One name (`to`), or `*`.
    One(String),
    /// Several names (`[to, cc, bcc]`).
    Many(Vec<String>),
}

impl ArgNames {
    /// The names, in the order written.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        match self {
            Self::One(name) => vec![name.as_str()],
            Self::Many(names) => names.iter().map(String::as_str).collect(),
        }
    }
}

/// What a value an untrusted output gave counts as (`provenance:`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provenance {
    /// A host or path in the value came from output the session read that
    /// someone else may have written (ADR-057).
    Untrusted,
}

/// One condition: `arg` (optional) and exactly one test.
///
/// A positive test (`under`, `host_in`, `in`, `matches`, `provenance`) holds
/// when **some** value passes it. A negated one (`not_under`, `host_not_in`,
/// `not_in`, `not_matches`) holds unless the call has values and **every**
/// one passes the positive test: a call that names no such value, or more
/// values than are read, is not shown to stay inside, so the condition holds
/// (fail closed).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Predicate {
    /// Which arguments the test reads, by name (snake case, or a dotted path
    /// `message.to`); absent, the test's own default (§2.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg: Option<ArgNames>,
    /// Holds when a path is one of these or below one (globs, `~`, `${project}`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub under: Vec<String>,
    /// Holds when a path is outside all of these, or the call names none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_under: Vec<String>,
    /// Holds when a URL's host matches one of these host globs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_in: Vec<String>,
    /// Holds when a URL's host matches none of these, or the call names none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_not_in: Vec<String>,
    /// Holds when a value (each address of a recipient list) matches one of
    /// these globs, ignoring case.
    #[serde(default, rename = "in", skip_serializing_if = "Vec::is_empty")]
    pub is_in: Vec<String>,
    /// Holds when a value (each address of a recipient list) matches none of
    /// these, or the call has none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_in: Vec<String>,
    /// Holds when a whole value matches one of these globs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<String>,
    /// Holds when a value matches none of these globs, or the call has none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_matches: Vec<String>,
    /// `untrusted`: holds when a host or path in a value came from untrusted
    /// output the session read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
}

/// The kind of test a [`Predicate`] makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Test {
    /// `under`, `not_under`.
    Under,
    /// `host_in`, `host_not_in`.
    HostIn,
    /// `in`, `not_in`.
    In,
    /// `matches`, `not_matches`.
    Matches,
    /// `provenance: untrusted`.
    Untrusted,
}

impl Predicate {
    /// Its one test, whether it is negated, and the patterns it lists; `None`
    /// when it sets no test or more than one.
    pub(crate) fn test(&self) -> Option<(Test, bool, &[String])> {
        let lists: [(Test, bool, &[String]); 8] = [
            (Test::Under, false, &self.under),
            (Test::Under, true, &self.not_under),
            (Test::HostIn, false, &self.host_in),
            (Test::HostIn, true, &self.host_not_in),
            (Test::In, false, &self.is_in),
            (Test::In, true, &self.not_in),
            (Test::Matches, false, &self.matches),
            (Test::Matches, true, &self.not_matches),
        ];
        let mut set = lists.into_iter().filter(|(_, _, list)| !list.is_empty());
        let first = set.next();
        let provenance = self.provenance.map(|_| (Test::Untrusted, false, &[][..]));
        match (first, set.next(), provenance) {
            (Some(one), None, None) | (None, None, Some(one)) => Some(one),
            _ => None,
        }
    }

    /// The condition as the reason names it (`not_in [*@example.com]`).
    pub(crate) fn describe(&self) -> String {
        let Some((test, negated, list)) = self.test() else {
            return String::new();
        };
        let name = match (test, negated) {
            (Test::Under, false) => "under",
            (Test::Under, true) => "not_under",
            (Test::HostIn, false) => "host_in",
            (Test::HostIn, true) => "host_not_in",
            (Test::In, false) => "in",
            (Test::In, true) => "not_in",
            (Test::Matches, false) => "matches",
            (Test::Matches, true) => "not_matches",
            (Test::Untrusted, _) => return "provenance untrusted".to_owned(),
        };
        format!("{name} [{}]", list.join(", "))
    }
}

/// Each group's conditions: only on `deny` and `review` groups (`allowed`),
/// each with exactly one test, plain argument names and patterns that compile.
pub(crate) fn check(group: &RuleGroup, allowed: bool) -> Result<(), PolicyError> {
    if group.when.is_empty() {
        return Ok(());
    }
    let problem = |problem: String| PolicyError::Rule {
        rule: group.id.clone(),
        problem,
    };
    if !allowed {
        return Err(problem(
            "`when` conditions narrow a `deny` or `review` rule only; an `allow` or `defer` \
             rule with conditions could let a call through on what its arguments claim"
                .to_owned(),
        ));
    }
    for predicate in &group.when {
        let Some((_, _, list)) = predicate.test() else {
            return Err(problem(
                "each `when` condition names exactly one test (`under`, `not_under`, `host_in`, \
                 `host_not_in`, `in`, `not_in`, `matches`, `not_matches` or `provenance`) with \
                 a non-empty list"
                    .to_owned(),
            ));
        };
        for name in predicate.arg.iter().flat_map(ArgNames::names) {
            if !is_arg_name(name) {
                return Err(problem(format!(
                    "`{name}` is not an argument name (letters, digits, `_`, `-` and `.` \
                     between names, or `*` alone)"
                )));
            }
        }
        for pattern in list {
            if pattern.trim_start().starts_with('!') {
                return Err(problem(format!(
                    "`{pattern}` is an exclusion; a condition's list names what it tests for"
                )));
            }
            GlobPattern::compile(pattern, false).map_err(|e| problem(e.to_string()))?;
        }
    }
    Ok(())
}

fn is_arg_name(name: &str) -> bool {
    name == "*"
        || (!name.is_empty()
            && name.split('.').all(|part| {
                !part.is_empty()
                    && part
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            }))
}

#[cfg(test)]
mod tests {
    use crate::policy::{Policy, PolicyError};

    fn parse(group: &str, list: &str) -> Result<Policy, PolicyError> {
        Policy::parse(&format!(
            "version: 1\n{list}:\n  - id: g\n    mcp: ['mcp__mail__send_email']\n    when:\n{group}"
        ))
    }

    #[test]
    fn conditions_need_one_test_and_a_deny_or_review_group() {
        let ok = "      - { arg: [to, cc], not_in: ['*@example.com'] }\n      - { provenance: untrusted }\n";
        assert_eq!(parse(ok, "deny").unwrap().deny[0].when.len(), 2);
        assert!(parse(ok, "review").is_ok());
        for list in ["allow", "defer"] {
            assert!(
                matches!(parse(ok, list), Err(PolicyError::Rule { rule, .. }) if rule == "g"),
                "{list} must refuse conditions"
            );
        }
        for bad in [
            "      - { arg: to }\n",
            "      - { in: ['a'], not_in: ['b'] }\n",
            "      - { in: ['a'], provenance: untrusted }\n",
            "      - { arg: 'to cc', in: ['a'] }\n",
            "      - { in: ['!a'] }\n",
            "      - { in: ['[a'] }\n",
            "      - { in: [] }\n",
        ] {
            assert!(parse(bad, "deny").is_err(), "{bad} must be refused");
        }
        assert!(parse("      - { bogus: ['a'] }\n", "deny").is_err());
    }
}
