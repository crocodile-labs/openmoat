//! What the Lightweight tier leaves open on Linux, as the committed evidence
//! shows (`docs/EVIDENCE.md`, #174): Landlock only grants, so a deny rule for a
//! path inside the project it grants cannot be enforced, and a command the
//! agent starts can read and write `.env`, create `.envrc`, and write the
//! project's `.moat` and `.git/hooks`. The hook still decides the agent's own
//! tool calls. The Isolated tier (bubblewrap) closes these; it is the default
//! where bubblewrap works (ADR-080), so this applies to `--no-isolate` and to a
//! system without it (`isolation.rs` says which).
//!
//! The platform says whether this applies through `bubblewrap`: `None` where
//! `moat run` is not Landlock (macOS's Seatbelt denies inside the project),
//! otherwise whether the system's bubblewrap is installed.

/// What commands can still do inside the project in the Lightweight tier on Linux.
const OPEN: &str = "commands the agent starts can still read and write the project's `.env`, \
                    create `.envrc` and write `.moat` and `.git/hooks`, since Landlock cannot \
                    deny a path inside the project it grants";

/// How to close [`OPEN`], with or without bubblewrap installed.
fn fix(bubblewrap: bool) -> &'static str {
    if bubblewrap {
        "`openmoat run --isolate` closes this"
    } else {
        "`openmoat run --isolate` closes this; it needs bubblewrap (`apt install bubblewrap`)"
    }
}

/// The two lines `moat run` prints on standard error when it starts the
/// Lightweight tier on Linux; `None` in the Isolated tier (`isolated`) and off
/// Linux. `openmoat doctor` says which tier applies (`isolation.rs`).
#[must_use]
pub fn notice(bubblewrap: Option<bool>, isolated: bool) -> Option<String> {
    let found = bubblewrap.filter(|_| !isolated)?;
    Some(format!(
        "moat run: {OPEN}; the hook still checks the agent's own tool calls.\nmoat run: {}",
        fix(found)
    ))
}

/// How `moat status`, `moat doctor` and `moat init` name the command that
/// puts an agent without a sandbox of its own in one: `--isolate` on Linux.
#[must_use]
pub fn command(bubblewrap: Option<bool>) -> &'static str {
    match bubblewrap {
        None => "`openmoat run`",
        Some(_) => "`openmoat run --isolate`",
    }
}

/// [`command`] as a person types it, without the backticks.
#[must_use]
pub fn words(bubblewrap: Option<bool>) -> &'static str {
    match bubblewrap {
        None => "openmoat run",
        Some(_) => "openmoat run --isolate",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lightweight_tier_on_linux_names_what_is_open_and_the_fix() {
        let with = notice(Some(true), false).unwrap();
        assert_eq!(with.lines().count(), 2, "{with}");
        for open in ["`.env`", "`.envrc`", "`.moat`", "`.git/hooks`"] {
            assert!(with.contains(open), "{with}");
        }
        assert!(
            with.ends_with("`openmoat run --isolate` closes this"),
            "{with}"
        );
        let without = notice(Some(false), false).unwrap();
        assert!(without.contains("apt install bubblewrap"), "{without}");
    }

    #[test]
    fn isolate_and_other_platforms_print_nothing() {
        assert_eq!(notice(Some(true), true), None);
        assert_eq!(notice(Some(false), true), None);
        assert_eq!(notice(None, false), None);
        assert_eq!(notice(None, true), None);
    }

    #[test]
    fn the_protection_line_names_isolate_on_linux() {
        assert_eq!(command(None), "`openmoat run`");
        assert_eq!(command(Some(true)), "`openmoat run --isolate`");
    }
}
