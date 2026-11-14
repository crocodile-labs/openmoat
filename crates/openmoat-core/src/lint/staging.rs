//! Warnings about the `agent-temp` rule, which both lets an agent's tools read
//! its own temporary folders and keeps those reads out of `staging`'s count
//! (ADR-061): a pattern wider than one agent's folder turns that count off
//! for everything it covers, without a word.

use super::Warning;
use crate::policy::Policy;
use crate::staging::AGENT_TEMP;

/// One warning for each `agent-temp` read that is an exclusion or covers more
/// than one agent's temporary folder ([`names_one_folder`]).
pub(super) fn agent_temp(policy: &Policy, out: &mut Vec<Warning>) {
    let wide: Vec<&str> = policy
        .allow
        .iter()
        .filter(|group| group.id == AGENT_TEMP)
        .flat_map(|group| &group.fs_read)
        .map(String::as_str)
        .filter(|pattern| !names_one_folder(pattern))
        .collect();
    for pattern in wide {
        out.push(Warning {
            rule: AGENT_TEMP.to_owned(),
            message: format!(
                "`{pattern}` is not one agent's temporary folder: reads there are allowed and \
                 never count as collecting files outside the project (`staging`), so a session \
                 can gather files there unnoticed; name the folder itself \
                 (`/tmp/<agent>-*/**`)"
            ),
        });
    }
}

/// The names of the system's shared temporary folders, by OS convention
/// (`/tmp`, Windows' `Temp`, macOS' per-user `T`): a pattern for everything
/// below one is every program's, not one agent's.
const SHARED_TEMP: &[&str] = &["tmp", "temp", "Temp", "TEMP", "T"];

/// Whether `pattern` names one folder of the kind an agent keeps for itself:
/// no exclusion, rooted at `/`, a drive or `~`, at least one literal folder
/// below the root, and a wildcard, if any, only after a literal start of a
/// folder's name (`/tmp/agent-*/**`) or below a literal folder that is not a
/// shared temporary folder (`~/.cache/agent/**`); not `/tmp/**`,
/// `/private/tmp/**` or `/**`.
fn names_one_folder(pattern: &str) -> bool {
    let rooted = pattern
        .strip_prefix("~/")
        .or_else(|| pattern.strip_prefix('/'))
        .or_else(|| {
            let (drive, rest) = pattern.split_once(":/")?;
            (drive.len() == 1 && drive.chars().all(|c| c.is_ascii_alphabetic())).then_some(rest)
        });
    let Some(rest) = rooted else {
        return false;
    };
    let wild = |c: char| matches!(c, '*' | '?' | '[' | '{' | '!');
    let segments: Vec<&str> = rest.split('/').collect();
    match segments.iter().position(|s| s.contains(wild)) {
        // a plain folder, at least two deep (`/tmp/agent`)
        None => segments.len() >= 2 && segments.iter().all(|s| !s.is_empty()),
        Some(at) => {
            let named = segments[at].split(wild).next().unwrap_or("");
            let below_own = at >= 2 && !SHARED_TEMP.contains(&segments[at - 1]);
            at >= 1
                && (!named.is_empty() || below_own)
                && segments[..at].iter().all(|s| !s.is_empty())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lint::warnings;
    use crate::policy::Policy;

    fn warned(reads: &str) -> Vec<String> {
        let yaml = format!("version: 1\nallow:\n  - id: agent-temp\n    fs.read: [{reads}]\n");
        warnings(&Policy::parse(&yaml).unwrap())
            .into_iter()
            .filter(|w| w.rule == "agent-temp")
            .map(|w| w.message)
            .collect()
    }

    #[test]
    fn agent_temp_names_only_agents_own_folders() {
        let quiet = [
            "'/tmp/agent-*/**'",
            "'/private/tmp/agent-*/**'",
            "'C:/Temp/agent-*/**'",
            "'~/.cache/agent-x/**'",
            "'/tmp/agent'",
        ];
        for reads in quiet {
            assert_eq!(warned(reads), Vec::<String>::new(), "{reads}");
        }
        for reads in [
            "'/**'",
            "'/tmp/**'",
            "'/tmp/*/**'",
            "'/private/tmp/**'",
            "'C:/Users/u/AppData/Local/Temp/**'",
            "'~/.cache/**'",
            "'/tmp'",
            "'**/x/**'",
            "'!/tmp/agent-*/**'",
            "'tmp/agent-*/**'",
            "'//agent-*/**'",
        ] {
            let found = warned(reads);
            assert_eq!(found.len(), 1, "{reads}: {found:?}");
            assert!(found[0].contains("`staging`"), "{reads}");
        }
        // another rule's reads are not this lint's business
        let other = "version: 1\nallow:\n  - id: wide\n    fs.read: ['/**']\n";
        assert!(
            !warnings(&Policy::parse(other).unwrap())
                .iter()
                .any(|w| w.rule == "agent-temp")
        );
    }

    #[test]
    fn the_default_agent_temp_rule_is_quiet() {
        let policy = Policy::parse(crate::DEFAULT_POLICY).unwrap();
        assert!(!warnings(&policy).iter().any(|w| w.rule == "agent-temp"));
    }
}
