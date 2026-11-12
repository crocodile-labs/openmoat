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

/// How far back the row on calls the guard could not decide looks.
const KERNEL_ERROR_WINDOW_MS: i64 = 24 * 3_600_000;

/// The longest part of the newest such call's reason the row quotes.
const REASON_CHARS: usize = 200;

/// Calls the guard denied in the last day because it could not decide them
/// (`kernel-error`: the audit log could not be read, the session's earlier
/// calls could not be read in time, a state file is broken): recorded in the
/// audit log, but a person sees each only as one more refused call in the
/// agent. A guard that fails every call must not leave doctor saying all is
/// well, so this row says how many, when the latest was, on which agent and
/// why, and what to do next. A session id is not printed: it can be a
/// credential-like handle, and `openmoat why <id>` shows the call in full.
pub(super) fn kernel_errors(store: &openmoat_audit::Store, now_ms: i64) -> Option<String> {
    let seen = store
        .rule_since(
            crate::commands::guard::KERNEL_ERROR_RULE,
            now_ms - KERNEL_ERROR_WINDOW_MS,
        )
        .ok()??;
    let newest = &seen.newest;
    let reason = newest.reasons.first().map_or_else(String::new, |reason| {
        let mut shown: String = reason.chars().take(REASON_CHARS).collect();
        if shown.len() < reason.len() {
            shown.push('…');
        }
        format!(": {shown}")
    });
    let sessions = if seen.sessions > 1 {
        format!(" in {} sessions", seen.sessions)
    } else {
        String::new()
    };
    Some(format!(
        "guard            {} call(s){sessions} denied in the last 24 hours because OpenMoat could \
         not decide them (kernel-error); the latest at {}, from {}{reason}. \
         `openmoat why {}` shows it in full; if calls keep being denied this way, \
         `openmoat doctor --bundle moat-bundle.json` writes a file for a bug report",
        seen.count,
        time::timestamp(newest.ts_ms),
        newest.host,
        newest.id,
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

    fn record(store: &openmoat_audit::Store, session: &str, rules: &[&str], reason: &str) {
        let mut decision = openmoat_core::Decision::new(openmoat_core::Verdict::Deny);
        decision.rules = rules.iter().map(|r| (*r).to_owned()).collect();
        decision.reasons.push(reason.to_owned());
        store
            .record(&openmoat_audit::NewEvent {
                host: "some-agent",
                session_id: session,
                call_id: None,
                cwd: Some("/p"),
                tool: "Bash",
                action: None,
                decision: &decision,
                latency_us: 0,
            })
            .unwrap();
    }

    /// A guard that fails its calls is a row that needs the person: how many,
    /// the latest, its session and reason, and what to run next; other denies
    /// are not counted, and a day later the row is gone.
    #[test]
    fn calls_the_guard_could_not_decide_are_a_row() {
        let store = openmoat_audit::Store::open_in_memory().unwrap();
        let now = time::now_ms();
        assert_eq!(kernel_errors(&store, now), None);
        record(&store, "s0", &["deny-ssh"], "a key");
        record(&store, "s0", &["kernel-errors-of-a-pack"], "not this rule");
        assert_eq!(kernel_errors(&store, now), None);
        let behind = crate::taint::behind(2_048);
        record(&store, "s1", &["kernel-error"], "the lock is broken");
        record(&store, "s2", &["kernel-error"], &behind);
        let row = kernel_errors(&store, now).unwrap();
        assert!(
            row.starts_with("guard            2 call(s) in 2 sessions denied"),
            "{row}"
        );
        assert!(row.contains("(kernel-error)"), "{row}");
        assert!(row.contains("from some-agent: "), "{row}");
        assert!(!row.contains("s2"), "no session id is printed: {row}");
        assert!(row.contains(": OpenMoat was still reading"), "{row}");
        assert!(row.contains('…'), "the reason is cut short: {row}");
        assert!(row.contains("`openmoat why 4`"), "{row}");
        assert!(row.contains("openmoat doctor --bundle"), "{row}");
        assert_eq!(
            kernel_errors(&store, now + KERNEL_ERROR_WINDOW_MS + 60_000),
            None
        );
    }

    /// The row keeps doctor's closing line from saying all is well.
    #[test]
    fn calls_the_guard_could_not_decide_are_not_all_good() {
        let store = openmoat_audit::Store::open_in_memory().unwrap();
        record(&store, "s1", &["kernel-error"], "the lock is broken");
        let row = kernel_errors(&store, time::now_ms()).unwrap();
        let mut report = super::super::rows::Report::new(crate::render::Deferred::quiet());
        report.warn(&row);
        let footer = super::super::human::footer_line(&report.human, 0, true);
        assert_eq!(
            footer,
            "1 thing needs you · each agent on each OS, and the tests behind it: \
             docs/PROTECTION.md"
        );
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
