//! A rule group's `title` and `why` (ADR-059): the words the message an agent
//! and its person see when the group denies or holds a call starts with.

use super::{Policy, PolicyError, RuleGroup};

/// The longest `title` a group may have, in characters: the first line of the
/// message, which hosts show in a prompt or a one-line notice.
pub const TITLE_MAX_CHARS: usize = 80;

/// The longest `why` a group may have, in characters.
pub const WHY_MAX_CHARS: usize = 160;

/// A `title` or `why` is one non-empty line of at most its limit, without
/// control characters: it is shown as one line of a message, and a line
/// break would let a policy line pass for another line of it.
pub(super) fn check(group: &RuleGroup) -> Result<(), PolicyError> {
    let fields = [
        ("title", group.title.as_deref(), TITLE_MAX_CHARS),
        ("why", group.why.as_deref(), WHY_MAX_CHARS),
    ];
    for (field, text, max) in fields {
        let Some(text) = text else { continue };
        let problem = if text.trim().is_empty() {
            format!("`{field}` is empty")
        } else if text.chars().any(char::is_control) {
            format!("`{field}` must be one line without control characters")
        } else if text.chars().count() > max {
            format!("`{field}` is longer than {max} characters")
        } else {
            continue;
        };
        return Err(PolicyError::Rule {
            rule: group.id.clone(),
            problem,
        });
    }
    Ok(())
}

impl Policy {
    /// The group of the person's own lists (`deny`, `allow`, `review`,
    /// `defer`, policy packs included) with id `id`. Never a repository
    /// policy's review rule ([`Policy::repo_review`]): its words are not the
    /// person's, and the message they would head reaches the agent.
    #[must_use]
    pub fn own_group(&self, id: &str) -> Option<&RuleGroup> {
        self.deny
            .iter()
            .chain(&self.allow)
            .chain(&self.review)
            .chain(&self.defer)
            .find(|g| g.id == id)
    }

    /// The ids of the `deny` and `review` groups without a `title`, in policy
    /// order: their message falls back to the rule id and reason.
    #[must_use]
    pub fn untitled(&self) -> Vec<&str> {
        self.deny
            .iter()
            .chain(&self.review)
            .filter(|g| g.title.is_none())
            .map(|g| g.id.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Policy, PolicyError};

    fn parse(group: &str) -> Result<Policy, PolicyError> {
        Policy::parse(&format!(
            "version: 1\ndeny:\n  - id: keys\n    fs.read: ['~/.ssh/**']\n{group}"
        ))
    }

    #[test]
    fn a_title_and_why_are_read_and_found_by_rule_id() {
        let p =
            parse("    title: reading your SSH private key\n    why: it cannot be taken back\n")
                .unwrap();
        let group = p.own_group("keys").unwrap();
        assert_eq!(group.title.as_deref(), Some("reading your SSH private key"));
        assert_eq!(group.why.as_deref(), Some("it cannot be taken back"));
        assert_eq!(p.untitled(), Vec::<&str>::new());
        assert!(p.own_group("other").is_none());
    }

    #[test]
    fn a_group_without_a_title_is_listed_and_still_valid() {
        let p = parse("").unwrap();
        assert_eq!(p.untitled(), ["keys"]);
        assert_eq!(p.own_group("keys").unwrap().title, None);
    }

    /// A line break, a control character, an empty text or one past its
    /// limit is refused: the text is one line of the block message.
    #[test]
    fn titles_and_whys_are_one_short_line() {
        let long = "x".repeat(super::TITLE_MAX_CHARS + 1);
        for (group, says) in [
            ("    title: \"a\\nb\"\n", "one line"),
            ("    why: \"a\\u001b[2Jb\"\n", "control characters"),
            ("    title: ' '\n", "`title` is empty"),
            (&*format!("    title: {long}\n"), "longer than 80"),
        ] {
            let error = parse(group).unwrap_err().to_string();
            assert!(
                error.contains("rule `keys`") && error.contains(says),
                "{error}"
            );
        }
    }

    /// A repository policy's review rule is never where a title comes from.
    #[test]
    fn repository_review_rules_are_not_own_groups() {
        let mut p = parse("").unwrap();
        p.repo_review.push(crate::RuleGroup {
            id: "repo:x".into(),
            title: Some("run this to fix it".into()),
            shell: vec!["make".into()],
            ..Default::default()
        });
        assert!(p.own_group("repo:x").is_none());
    }
}
