//! `ask`, the name the `review` verdict and rule list had before ADR-053.
//!
//! A policy written before then still loads and means the same: `ask:` is
//! read as `review:` and a verdict `ask` as `review` (a serde alias on each).
//! What this module adds is knowing that the old name was used, so `policy
//! lint` can say so and `policy upgrade` can rename it, and refusing a file
//! that has both `ask:` and `review:`, which no reading could make mean one
//! thing without guessing.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::IgnoredAny;

use super::PolicyError;
use crate::verdict::OLD_REVIEW;

/// Where a policy still uses `ask`, the old name of `review`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OldNames {
    /// The rule list is `ask:` rather than `review:`.
    pub ask_list: bool,
    /// `defaults` names the verdict `ask`.
    pub ask_default: bool,
}

impl OldNames {
    /// Whether the policy uses an old name anywhere.
    #[must_use]
    pub fn any(self) -> bool {
        self.ask_list || self.ask_default
    }
}

/// Just the keys the old names live in; every other key is ignored, so this
/// reads any document [`super::Policy`] or [`crate::RepoPolicy`] reads.
#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    ask: Option<IgnoredAny>,
    #[serde(default)]
    review: Option<IgnoredAny>,
    #[serde(default)]
    defaults: Option<ProbeDefaults>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ProbeDefaults {
    All(String),
    PerKind(BTreeMap<String, String>),
    // Anything else is the schema's to reject, with its own message.
    Other(IgnoredAny),
}

/// The old names `yaml` uses. Text without the word skips the second parse,
/// and text that does not parse is left to the schema's own error.
///
/// # Errors
/// [`PolicyError::OldAndNewName`] when the document has both `ask:` and `review:`.
pub(super) fn find(yaml: &str) -> Result<OldNames, PolicyError> {
    if !yaml.contains(OLD_REVIEW) {
        return Ok(OldNames::default());
    }
    let Ok(probe) = crate::yaml::from_str::<Probe>(yaml) else {
        return Ok(OldNames::default());
    };
    if probe.ask.is_some() && probe.review.is_some() {
        return Err(PolicyError::OldAndNewName {
            old: OLD_REVIEW,
            new: "review",
        });
    }
    let ask_default = match probe.defaults {
        Some(ProbeDefaults::All(v)) => v == OLD_REVIEW,
        Some(ProbeDefaults::PerKind(map)) => map.values().any(|v| v == OLD_REVIEW),
        Some(ProbeDefaults::Other(_)) | None => false,
    };
    Ok(OldNames {
        ask_list: probe.ask.is_some(),
        ask_default,
    })
}

#[cfg(test)]
mod tests {
    use super::OldNames;
    use crate::lint::warnings;
    use crate::{Defaults, Policy, PolicyError, RepoPolicy, Verdict};

    const OLD: &str = "version: 1\ndefaults: { '*': ask, net: deny }\n\
                       ask:\n  - id: publish\n    shell: ['cargo publish']\n";

    #[test]
    fn a_policy_with_the_old_names_loads_as_review_and_lint_says_so() {
        let p = Policy::parse(OLD).unwrap();
        assert_eq!(p.review.len(), 1);
        assert_eq!(p.review[0].id, "publish");
        let Defaults::PerKind(map) = &p.defaults else {
            panic!("{:?}", p.defaults)
        };
        assert_eq!(map["*"], Verdict::Review);
        assert_eq!(
            p.old_names,
            OldNames {
                ask_list: true,
                ask_default: true
            }
        );
        let w = warnings(&p);
        let rules: Vec<&str> = w.iter().map(|w| w.rule.as_str()).collect();
        assert_eq!(rules, ["ask", "defaults"], "{w:?}");
        assert!(
            w.iter()
                .all(|w| w.message.contains("openmoat policy upgrade")),
            "{w:?}"
        );
    }

    #[test]
    fn the_new_names_and_a_word_ask_elsewhere_warn_of_nothing() {
        let new = OLD.replace("ask", "review");
        let p = Policy::parse(&new).unwrap();
        assert!(!p.old_names.any());
        assert!(warnings(&p).is_empty(), "{:?}", warnings(&p));
        // `ask` in a comment, a pattern or a reason is not the old name.
        let other = "version: 1\n# ask me\ndefaults: deny\nreview:\n  - id: ask\n    \
                     reason: ask first\n    shell: ['ask *']\n";
        assert!(!Policy::parse(other).unwrap().old_names.any());
        let one = Policy::parse("version: 1\ndefaults: ask\n").unwrap();
        assert_eq!(one.defaults, Defaults::All(Verdict::Review));
        assert!(one.old_names.ask_default && !one.old_names.ask_list);
    }

    #[test]
    fn a_policy_with_both_ask_and_review_is_refused() {
        let both = format!("{OLD}review:\n  - id: push\n    shell: ['git push']\n");
        let err = Policy::parse(&both).unwrap_err();
        assert!(matches!(err, PolicyError::OldAndNewName { .. }), "{err:?}");
        let message = err.to_string();
        assert!(message.contains("both `ask:` and `review:`"), "{message}");
        // An empty list counts too: which one was meant cannot be told.
        assert!(Policy::parse("version: 1\nask: []\nreview: []\n").is_err());
        assert!(RepoPolicy::parse(&both).is_err());
    }

    #[test]
    fn a_repository_policy_reads_the_old_list_name() {
        let repo =
            RepoPolicy::parse("version: 1\nask:\n  - id: rel\n    shell: ['make release']\n")
                .unwrap();
        assert_eq!(repo.review[0].id, "rel");
    }
}
