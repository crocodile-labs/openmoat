//! `moat doctor` rows that warn without counting as a problem.

use std::fs;
use std::path::Path;

use openmoat_core::Policy;
use openmoat_hosts::Host;

use crate::hangs;
use crate::home::Home;
use crate::install::{GUARD_BUDGET_S, HookState, HostConfig};
use crate::sandbox::{self, Grants, exposure};
use crate::time;

/// The Linux setting that lets a process type into a terminal it shares.
const LEGACY_TIOCSTI: &str = "/proc/sys/dev/tty/legacy_tiocsti";

/// How far back the hang row looks.
const HANG_WINDOW_MS: i64 = 7 * 24 * 3_600_000;

/// The contents of [`LEGACY_TIOCSTI`] on Linux, empty on a kernel without the
/// setting (before 6.2, where `TIOCSTI` is always allowed); `None` elsewhere.
pub(super) fn legacy_tiocsti() -> Option<String> {
    cfg!(target_os = "linux").then(|| fs::read_to_string(LEGACY_TIOCSTI).unwrap_or_default())
}

/// The name of the first host with its hook installed whose Linux sandbox
/// does not refuse `TIOCSTI` ([`openmoat_hosts::SandboxSpec::tiocsti_open_on_linux`]).
pub(super) fn tiocsti_open(home: &Home, binary: &Path) -> anyhow::Result<Option<&'static str>> {
    for host in Host::ALL {
        if host
            .spec()
            .sandbox
            .as_ref()
            .is_some_and(|s| s.tiocsti_open_on_linux)
            && HostConfig::for_host(home, host)?.state(binary) == HookState::Installed
        {
            return Ok(Some(host.display_name()));
        }
    }
    Ok(None)
}

/// With such a host set up (`open` names it, see [`tiocsti_open`]), a warning
/// when `setting` (see [`legacy_tiocsti`]) is not `0`: its Linux sandbox does
/// not refuse `TIOCSTI`, so a sandboxed script could leave a command in the
/// terminal's input that the user's shell runs after the session. Only the
/// kernel stops it.
pub(super) fn tiocsti(open: Option<&str>, setting: Option<&str>) -> Option<String> {
    let name = open?;
    let value = setting.map(str::trim).filter(|v| *v != "0")?;
    Some(if value.is_empty() {
        format!(
            "{name:<16} this kernel (before Linux 6.2) always lets a command type into your \
             terminal (TIOCSTI), and {name}'s sandbox cannot stop it; a 6.2+ kernel with \
             dev.tty.legacy_tiocsti=0 does"
        )
    } else {
        format!(
            "{name:<16} dev.tty.legacy_tiocsti is {value}: {name}'s sandbox cannot stop a command \
             typing into your terminal (TIOCSTI); `sudo sysctl dev.tty.legacy_tiocsti=0` turns that off"
        )
    })
}

/// On Linux, a warning when a tree `moat run` grants in this directory (the
/// project, a read root, the temp directory) holds the state directory:
/// Landlock cannot keep the audit log and the lock from commands there, so
/// `moat run` refuses to start.
pub(super) fn state_in_grant(home: &Home, policy: &Policy, linux: bool) -> Option<String> {
    if !linux {
        return None;
    }
    let ctx = crate::context::eval_context(home, None, None).ok()?;
    let rules = sandbox::landlock_rules(policy, &ctx, Grants::default()).ok()?;
    let tmpdir = sandbox::session_tmpdir();
    let why = exposure::refusal(home.root(), &rules.rules, tmpdir.as_deref(), false)?;
    Some(format!("openmoat run     {why}"))
}

/// A warning on the standing grants that `--for` ended or ends within a day
/// ([`crate::approvals::expiry_summary`]); an unreadable overlay has its own row.
pub(super) fn grant_expiry(home: &Home, now_ms: i64) -> Option<String> {
    let overlay = crate::approvals::Overlay::load(&home.overlay_path()).ok()?;
    let summary = crate::approvals::expiry_summary(&overlay, now_ms)?;
    Some(format!("approvals        {summary}"))
}

/// The row that says which agents' tool commands do not receive `openmoat
/// run`'s relay token (ADR-075). What each host's spec says, from its own
/// documentation or source: `openmoat bench --report` tries only the sandbox
/// rule, and the weekly real-agent job the rest.
pub(super) fn relay_token() -> String {
    let (withheld, kept): (Vec<_>, Vec<_>) = openmoat_hosts::Host::EVERY
        .into_iter()
        .partition(|host| host.spec().tool_token.withheld());
    let names = |hosts: &[openmoat_hosts::Host]| {
        hosts
            .iter()
            .map(|host| host.spec().display_name)
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "relay token      under `openmoat run`, tool commands do not receive it for {}; \
         they still do for {} (docs/LIMITS.md). This row is not tested here: it says how those \
         agents start tool commands, not what this machine did",
        names(&withheld),
        names(&kept)
    )
}

/// The row that says the `moat` name goes away.
pub(super) const RENAMED: &str = "command          `moat` is the old name of `openmoat`; it still \
                                  works for now and will be removed in a later release";

/// A warning when the lock records `binary`'s `moat` alias: a lock written
/// before the rename. It still works; `openmoat init` moves it to `binary`.
pub(super) fn alias_lock(recorded: &str, binary: &Path) -> Option<String> {
    let alias = crate::install::alias_of(binary)?;
    (alias.to_string_lossy() == recorded).then(|| {
        format!(
            "binary           the lock records {recorded}, the old `moat` name of {}; it still \
             works, and `openmoat init` moves the hooks and the lock to openmoat",
            binary.display()
        )
    })
}

/// A warning for each agent whose hook still runs `binary`'s `moat` alias.
pub(super) fn alias_hooks(home: &Home, binary: &Path) -> Vec<String> {
    Host::ALL
        .into_iter()
        .filter_map(|host| HostConfig::for_host(home, host).ok())
        .filter(|config| config.runs_alias(binary))
        .map(|config| {
            format!(
                "{:<16} hook runs the old `moat` name; it still works, and `openmoat init` \
                 switches it to openmoat",
                config.host.display_name()
            )
        })
        .collect()
}

/// On a Mac with `version` (see [`crate::os_version::macos`]), a warning when
/// it is too old for `moat run`, which refuses there.
pub(super) fn old_macos(version: Option<&str>) -> Option<String> {
    let reason = crate::os_version::run_floor(version)?;
    Some(format!(
        "openmoat run     {reason}; the agent hooks still apply the policy"
    ))
}

/// Calls the guard denied in the last week because no decision came in time.
pub(super) fn hangs(home: &Home, now_ms: i64) -> Option<String> {
    let path = home.hangs_path();
    let found = hangs::since(&path, now_ms - HANG_WINDOW_MS)?;
    let phase = found.common_phase.map_or_else(String::new, |p| {
        format!(", most while {} (phase {})", p.doing(), p.name())
    });
    Some(format!(
        "guard            {} call(s) denied with no decision within {GUARD_BUDGET_S} s \
         in the last 7 days, the latest at {}{phase}; not in the audit log, listed in {}",
        found.count,
        time::timestamp(found.newest_ms),
        path.display()
    ))
}

/// The private keys of the state directory that others may read or replace:
/// `openmoat proxy`, `openmoat run` and the guard refuse to use them
/// (`key_file`), and this row says which and how to fix it.
pub(super) fn key_modes(home: &Home) -> Vec<String> {
    [
        crate::proxy_session::key_path(home),
        crate::proxy_ca::key_path(home),
    ]
    .iter()
    .filter_map(|path| crate::key_file::problem(path))
    .map(|problem| format!("private key      {problem}"))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_key_others_may_read_is_a_row() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("state"));
        assert!(key_modes(&home).is_empty(), "no key yet");
        crate::proxy_session::Key::load_or_create(&home).unwrap();
        assert_eq!(key_modes(&home), Vec::<String>::new());
        let key = crate::proxy_session::key_path(&home);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let rows = key_modes(&home);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(rows[0].contains("mode 644"), "{rows:?}");
    }

    #[test]
    fn tiocsti_warns_only_for_codex_on_a_kernel_that_allows_it() {
        let codex = Some("Codex");
        let warning = tiocsti(codex, Some("1\n")).unwrap();
        assert!(warning.contains("legacy_tiocsti is 1:"), "{warning}");
        assert!(warning.contains("Codex's sandbox"), "{warning}");
        assert!(
            warning.contains("sysctl dev.tty.legacy_tiocsti=0"),
            "{warning}"
        );
        assert_eq!(tiocsti(codex, Some("0\n")), None);
        assert_eq!(tiocsti(codex, None), None, "not Linux");
        let old_kernel = tiocsti(codex, Some("")).unwrap();
        assert!(old_kernel.contains("before Linux 6.2"), "{old_kernel}");
        assert_eq!(tiocsti(None, Some("1\n")), None);
    }

    /// A state directory in the temp directory, a read root on every system.
    #[cfg(unix)]
    #[test]
    fn a_state_directory_inside_a_grant_is_a_warning_on_linux_only() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("state"));
        fs::create_dir_all(home.root()).unwrap();
        let policy = Policy::parse(openmoat_core::DEFAULT_POLICY).unwrap();
        let row = state_in_grant(&home, &policy, true).unwrap();
        assert!(row.starts_with("openmoat run     "), "{row}");
        assert!(row.contains("Move MOAT_HOME out of /"), "{row}");
        assert_eq!(state_in_grant(&home, &policy, false), None);
    }

    #[test]
    fn an_old_macos_is_a_moat_run_warning() {
        let row = old_macos(Some("12.7.6")).unwrap();
        assert!(row.starts_with("openmoat run     needs macOS 13"), "{row}");
        assert!(row.contains("hooks still apply the policy"), "{row}");
        assert_eq!(old_macos(Some("13.0")), None);
        assert_eq!(old_macos(None), None, "not macOS, or unreadable");
    }

    #[test]
    fn hangs_older_than_a_week_are_not_reported() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().to_path_buf());
        let now = HANG_WINDOW_MS * 2;
        assert_eq!(hangs(&home, now), None);
        fs::write(home.hangs_path(), format!("1 codex\n{now} cursor\n")).unwrap();
        let row = hangs(&home, now).unwrap();
        assert!(row.contains("1 call(s) denied"), "{row}");
        assert!(!row.contains("most while"), "{row}");
        fs::write(
            home.hangs_path(),
            format!("{now} codex taint 30010\n{now} cursor\n"),
        )
        .unwrap();
        let row = hangs(&home, now).unwrap();
        assert!(row.contains("2 call(s) denied"), "{row}");
        assert!(
            row.contains("most while reading the session's earlier calls (phase taint)"),
            "{row}"
        );
    }
}
