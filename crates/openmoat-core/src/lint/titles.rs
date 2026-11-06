//! Deny and review rules without a `title` (ADR-059).

use super::Warning;
use crate::policy::Policy;

/// At most this many rule ids are named in the warning; the rest are counted.
const NAMED: usize = 5;

/// One warning naming the `deny` and `review` rules without a `title`, whose
/// block message falls back to the rule id and reason; `None` when every one
/// has a title. `openmoat policy lint` reports it. It is not one of
/// [`super::warnings`], which the commands that write a policy print after
/// each change: a policy from before titles existed would print it every time.
#[must_use]
pub fn untitled(policy: &Policy) -> Option<Warning> {
    let ids = policy.untitled();
    let (first, rest) = ids.split_at(ids.len().min(NAMED));
    let listed = first
        .iter()
        .map(|id| format!("`{id}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let named = if rest.is_empty() {
        listed
    } else {
        format!("{listed} and {} more", rest.len())
    };
    (!ids.is_empty()).then(|| Warning {
        rule: "title".to_owned(),
        message: format!(
            "{} deny or review rule{} without a `title`, so {} block message{} the rule id \
             instead of what is stopped: {named}; `openmoat policy upgrade` adds the default \
             rules' titles",
            ids.len(),
            if ids.len() == 1 { " is" } else { "s are" },
            if ids.len() == 1 { "its" } else { "their" },
            if ids.len() == 1 { " shows" } else { "s show" },
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::untitled;
    use crate::Policy;

    #[test]
    fn untitled_deny_and_review_rules_are_named_once() {
        let p = Policy::parse(
            "version: 1\ndeny:\n  - id: keys\n    fs.read: ['~/.ssh/**']\n\
             allow:\n  - id: dev\n    shell: ['cargo *']\n\
             review:\n  - id: push\n    shell: ['git push']\n",
        )
        .unwrap();
        let w = untitled(&p).unwrap().to_string();
        assert!(
            w.starts_with("rule `title`: 2 deny or review rules are"),
            "{w}"
        );
        assert!(w.contains("`keys`, `push`;") && !w.contains("`dev`"), "{w}");
        let titled = Policy::parse(
            "version: 1\ndeny:\n  - id: keys\n    title: reading your SSH keys\n    \
             fs.read: ['~/.ssh/**']\nallow:\n  - id: dev\n    shell: ['cargo *']\n",
        )
        .unwrap();
        assert_eq!(untitled(&titled), None);
    }

    #[test]
    fn a_long_list_is_counted_past_five() {
        let groups = (0..7)
            .map(|i| format!("  - id: r{i}\n    shell: ['x{i}']\n"))
            .collect::<Vec<_>>()
            .concat();
        let p = Policy::parse(&format!("version: 1\ndeny:\n{groups}")).unwrap();
        let w = untitled(&p).unwrap().to_string();
        assert!(w.contains("`r4` and 2 more"), "{w}");
    }

    /// The shipped default gives every deny and review rule a title.
    #[test]
    fn every_default_deny_and_review_rule_has_a_title() {
        let p = Policy::parse(crate::DEFAULT_POLICY).unwrap();
        assert_eq!(p.untitled(), Vec::<&str>::new());
        for group in p.deny.iter().chain(&p.review) {
            assert!(group.why.is_some(), "`{}` has no `why`", group.id);
        }
    }
}
