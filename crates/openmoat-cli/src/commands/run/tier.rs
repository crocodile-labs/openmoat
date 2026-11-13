//! What the Lightweight tier covers inside the project on Linux, and what it
//! leaves open there, as `moat run` says before the agent starts and `moat
//! doctor` says beforehand (ADR-089). Landlock only grants, so a deny rule for
//! a path inside a tree it grants cannot be enforced by Landlock alone:
//! - with a network namespace (bubblewrap installed and allowed), its mounts
//!   cover the project as under `--isolate` ([`NAMESPACED`]);
//! - without one, the project is granted entry by entry, and what lies deeper
//!   in a granted entry stays open, each path named ([`port_only`]).
//!
//! macOS's Seatbelt denies inside the project by path, so nothing is named there.

/// How many of the paths left open a line names before it counts the rest.
const NAMED: usize = 8;

/// What `moat run` prints when the agent gets a network namespace.
#[cfg_attr(
    not(any(target_os = "linux", test)),
    expect(
        dead_code,
        reason = "only Linux has a Lightweight tier with a gap to name"
    )
)]
pub const NAMESPACED: &str = "moat run: in the project, the paths the policy denies are \
     covered for the session as under `--isolate` (`.env` files hidden, `.git`, `.moat` and \
     agents' configuration read-only), but a match created after the start where nothing \
     stood (`.env.local`, a `.env` in a new folder) stays open; the hook still checks the \
     agent's own tool calls. `openmoat run --isolate` also hides the rest of the machine";

/// What `moat run` prints when the project is granted entry by entry, with
/// `open`, the paths the policy denies there that stay open (or why they could
/// not be listed).
#[cfg_attr(
    not(any(target_os = "linux", test)),
    expect(
        dead_code,
        reason = "only Linux has a Lightweight tier with a gap to name"
    )
)]
pub fn port_only(open: &Result<Vec<String>, String>) -> String {
    format!(
        "moat run: without bubblewrap the project is granted entry by entry: commands cannot \
         create, rename or remove entries directly in it (create what they need before the \
         run), `.env` files there stay unreadable and `.git` and `.moat` read-only. {} With \
         bubblewrap (`apt install bubblewrap`) `openmoat run` covers these with mounts and \
         needs none of this; the hook still checks the agent's own tool calls",
        left_open(open)
    )
}

/// `moat doctor`'s row where `moat run` would grant the project entry by entry.
#[cfg_attr(
    not(any(target_os = "linux", test)),
    expect(
        dead_code,
        reason = "only Linux has a Lightweight tier with a gap to name"
    )
)]
pub fn doctor_line(open: &Result<Vec<String>, String>) -> String {
    format!(
        "openmoat run     without a network namespace the project here is granted entry by \
         entry: commands cannot create entries directly in it. {} Install bubblewrap \
         (`apt install bubblewrap`) to cover them",
        left_open(open)
    )
}

/// The sentence naming `open`.
#[cfg_attr(
    not(any(target_os = "linux", test)),
    expect(
        dead_code,
        reason = "only Linux has a Lightweight tier with a gap to name"
    )
)]
fn left_open(open: &Result<Vec<String>, String>) -> String {
    match open {
        Ok(paths) if paths.is_empty() => {
            "Nothing else the policy denies in the project is open to commands.".to_owned()
        }
        Ok(paths) => {
            let mut named = paths
                .iter()
                .take(NAMED)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            if paths.len() > NAMED {
                named = format!("{named} and {} more", paths.len() - NAMED);
            }
            format!(
                "These paths the policy denies lie in a folder granted whole and stay open to \
                 commands: {named}."
            )
        }
        Err(why) => format!(
            "Which paths the policy denies deeper in the project stay open could not be \
             listed ({why})."
        ),
    }
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
    fn granted_entry_by_entry_names_what_it_covers_the_cost_and_each_open_path() {
        let none = port_only(&Ok(Vec::new()));
        for said in [
            "entry by entry",
            "cannot create, rename or remove entries directly in it",
            "`.env` files there stay unreadable",
            "`.git` and `.moat` read-only",
            "Nothing else the policy denies",
            "apt install bubblewrap",
        ] {
            assert!(none.contains(said), "{said}: {none}");
        }
        let paths: Vec<String> = (0..10).map(|i| format!("/p/sub{i}/.env")).collect();
        let some = port_only(&Ok(paths));
        assert!(some.contains("/p/sub0/.env, /p/sub1/.env"), "{some}");
        assert!(some.contains("/p/sub7/.env and 2 more"), "{some}");
        assert!(!some.contains("/p/sub8/.env"), "{some}");
        let unknown = port_only(&Err("too many files".into()));
        assert!(
            unknown.contains("could not be listed (too many files)"),
            "{unknown}"
        );
        let doctor = doctor_line(&Ok(vec!["/p/a/.env".into()]));
        assert!(doctor.starts_with("openmoat run     "), "{doctor}");
        assert!(doctor.contains("/p/a/.env"), "{doctor}");
    }

    #[test]
    fn the_namespace_names_what_stays_open_after_the_start() {
        assert!(NAMESPACED.contains("as under `--isolate`"));
        assert!(NAMESPACED.contains("created after the start"));
    }

    #[test]
    fn the_protection_line_names_isolate_on_linux() {
        assert_eq!(command(None), "`openmoat run`");
        assert_eq!(command(Some(true)), "`openmoat run --isolate`");
    }
}
