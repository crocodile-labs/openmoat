//! The systemd user unit for `moat proxy`: a deterministic ini-style string
//! unit tests can lock byte for byte.
//!
//! Only what the service needs is set: `Description`, `ExecStart` naming the
//! pinned `moat` binary, `Environment=MOAT_HOME=…` (a path, never a secret),
//! `Restart=on-failure` so a lock-drift exit (which is a clean exit) does not
//! loop-restart, and `WantedBy=default.target` so `systemctl --user enable`
//! starts it on login.

use std::fmt::Write as _;
use std::path::Path;

/// The systemd unit name, written as `moat-proxy.service` in the user unit
/// directory.
pub const NAME: &str = "moat-proxy.service";

/// What goes into the unit; `moat_home` is a path, never a secret.
pub struct Spec<'a> {
    pub binary: &'a Path,
    pub moat_home: &'a Path,
}

/// A deterministic unit file. systemd accepts unquoted values that contain
/// most path characters; a backslash, tab or newline is escaped C-style
/// because systemd would otherwise read it as a line continuation or token.
pub fn render(spec: &Spec<'_>) -> String {
    let mut out = String::new();
    out.push_str("# OpenMoat egress proxy, installed by `openmoat proxy install`.\n");
    out.push_str("# Managed by moat; do not edit by hand.\n");
    out.push_str("\n[Unit]\n");
    out.push_str("Description=OpenMoat default-deny egress proxy\n");
    // `moat sandbox sync` restarts it, so start late enough that /home is up;
    // `default.target` is the user session's analogue of `multi-user.target`.
    out.push_str("After=default.target\n");
    out.push_str("\n[Service]\n");
    out.push_str("Type=simple\n");
    let _ = writeln!(
        out,
        "ExecStart={} proxy",
        escape(&spec.binary.to_string_lossy())
    );
    let _ = writeln!(
        out,
        "Environment=MOAT_HOME={}",
        escape(&spec.moat_home.to_string_lossy())
    );
    // `on-failure` restarts the crash case (segfault, OOM, hostile kill) but
    // leaves a lock-drift exit (code 64) alone: `moat doctor` surfaces it.
    out.push_str("Restart=on-failure\n");
    out.push_str("RestartSec=2\n");
    // A classic flood-prevention knob so a tight crash loop does not fill the
    // journal: five restarts in 30 s stop the unit (`systemctl --user status`
    // then shows `failed`).
    out.push_str("StartLimitBurst=5\n");
    out.push_str("StartLimitIntervalSec=30\n");
    // Hardening that costs nothing: the proxy writes only to the audit log
    // under `MOAT_HOME`, so it cannot gain by writing elsewhere.
    out.push_str("NoNewPrivileges=yes\n");
    out.push_str("PrivateTmp=yes\n");
    out.push_str("ProtectSystem=full\n");
    out.push_str("\n[Install]\n");
    out.push_str("WantedBy=default.target\n");
    out
}

/// Escape characters systemd reads as syntax when they appear in a bare value:
/// a trailing backslash would eat the newline; a tab or newline would end
/// the token. A space or `=` is fine in a `KEY=value` line.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn unit_names_the_binary_and_moat_home_and_restarts_only_on_failure() {
        assert_eq!(NAME, "moat-proxy.service");
        let text = render(&Spec {
            binary: &PathBuf::from("/home/u/.cargo/bin/moat"),
            moat_home: &PathBuf::from("/home/u/.moat"),
        });
        assert!(text.contains("Description=OpenMoat"));
        assert!(text.contains("ExecStart=/home/u/.cargo/bin/moat proxy"));
        assert!(text.contains("Environment=MOAT_HOME=/home/u/.moat"));
        assert!(text.contains("Restart=on-failure"));
        assert!(!text.contains("Restart=always"));
        assert!(text.contains("WantedBy=default.target"));
        assert!(text.contains("NoNewPrivileges=yes"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn render_is_deterministic() {
        let spec = Spec {
            binary: &PathBuf::from("/opt/moat"),
            moat_home: &PathBuf::from("/x/.moat"),
        };
        assert_eq!(render(&spec), render(&spec));
    }

    #[test]
    fn backslashes_tabs_and_newlines_in_a_path_are_escaped() {
        let home = PathBuf::from("/home/weird\t\\path");
        let text = render(&Spec {
            binary: &PathBuf::from("/bin/moat"),
            moat_home: &home,
        });
        assert!(
            text.contains("Environment=MOAT_HOME=/home/weird\\t\\\\path"),
            "{text}"
        );
    }
}
