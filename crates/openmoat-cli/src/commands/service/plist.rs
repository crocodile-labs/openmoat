//! The launchd user agent plist: a deterministic XML string, so a unit test
//! can lock the exact bytes `moat proxy install` and `openmoat approvals
//! install` write.
//!
//! Only the keys the service needs are rendered: `Label`, `ProgramArguments`,
//! `EnvironmentVariables` (just `MOAT_HOME`, a path, never a secret),
//! `RunAtLoad`, `KeepAlive` with `SuccessfulExit=false` so a lock-drift exit
//! does not loop-restart, `ProcessType=Background`, `StandardOutPath` and
//! `StandardErrorPath` so launchd writes the proxy's logs somewhere the user
//! can read. A [`Job::private`] job also gets `Umask` 077, so its logs and
//! everything else it creates are owner-only.
//!
//! `openmoat-core` must never see this file (`openmoat-core` is pure), so this
//! stays in the CLI next to the other platform code.

use std::fmt::Write as _;
use std::path::Path;

use super::Job;

/// `Umask` 077, as the decimal integer launchd's XML takes.
const PRIVATE_UMASK: u32 = 0o077;

/// What goes into the plist. The caller fills everything in: `moat_home` is a
/// path, never a secret, and `binary` is the pinned `moat` the hooks run.
pub struct Spec<'a> {
    pub job: &'a Job,
    pub binary: &'a Path,
    pub moat_home: &'a Path,
    pub stdout_log: &'a Path,
    pub stderr_log: &'a Path,
}

/// Deterministic XML. Keys are in alphabetical order inside each `<dict>`,
/// which launchd accepts; a byte comparison in the unit test is then stable.
///
/// Every path and value is escaped: a `&`, `<` or `>` in `MOAT_HOME` becomes
/// `&amp;`, `&lt;` or `&gt;`.
pub fn render(spec: &Spec<'_>) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    );
    out.push_str("<plist version=\"1.0\">\n<dict>\n");
    key_string(&mut out, "EnvironmentVariables");
    out.push_str("  <dict>\n");
    out.push_str("    <key>MOAT_HOME</key>\n");
    let _ = writeln!(
        out,
        "    <string>{}</string>",
        xml_escape(&spec.moat_home.to_string_lossy())
    );
    out.push_str("  </dict>\n");
    key_bool(&mut out, "KeepAlive", "dict", "SuccessfulExit", false);
    key_value(&mut out, "Label", "string", spec.job.label);
    let binary = spec.binary.to_string_lossy();
    let arguments: Vec<&str> = std::iter::once(binary.as_ref())
        .chain(spec.job.args.iter().copied())
        .collect();
    key_array_of_strings(&mut out, "ProgramArguments", &arguments);
    key_value(&mut out, "ProcessType", "string", "Background");
    out.push_str("  <key>RunAtLoad</key>\n  <true/>\n");
    key_value(
        &mut out,
        "StandardErrorPath",
        "string",
        &spec.stderr_log.to_string_lossy(),
    );
    key_value(
        &mut out,
        "StandardOutPath",
        "string",
        &spec.stdout_log.to_string_lossy(),
    );
    if spec.job.private {
        key_value(&mut out, "Umask", "integer", &PRIVATE_UMASK.to_string());
    }
    out.push_str("</dict>\n</plist>\n");
    out
}

fn key_string(out: &mut String, name: &str) {
    let _ = writeln!(out, "  <key>{name}</key>");
}

fn key_value(out: &mut String, name: &str, kind: &str, value: &str) {
    let _ = writeln!(
        out,
        "  <key>{name}</key>\n  <{kind}>{}</{kind}>",
        xml_escape(value)
    );
}

fn key_array_of_strings(out: &mut String, name: &str, values: &[&str]) {
    let _ = writeln!(out, "  <key>{name}</key>\n  <array>");
    for v in values {
        let _ = writeln!(out, "    <string>{}</string>", xml_escape(v));
    }
    out.push_str("  </array>\n");
}

/// One-key dict with a boolean value, as `KeepAlive = {SuccessfulExit=false}`
/// expresses: restart on crash, do not loop-restart a clean exit (the lock
/// drift case).
fn key_bool(out: &mut String, outer: &str, kind: &str, inner: &str, value: bool) {
    let v = if value { "<true/>" } else { "<false/>" };
    let _ = writeln!(
        out,
        "  <key>{outer}</key>\n  <{kind}>\n    <key>{inner}</key>\n    {v}\n  </{kind}>"
    );
}

/// XML character escapes. `MOAT_HOME` is a user path, so this handles the
/// characters a filesystem allows that are also XML special.
fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// The names of the variables a plist's `EnvironmentVariables` dictionaries
/// set, for [`super::read_back()`]; `None` for a file not in the XML form
/// [`render`] writes (a binary plist `plutil` converted, a broken dictionary).
pub fn environment(text: &str) -> Option<Vec<String>> {
    if !text.starts_with("<?xml") {
        return None;
    }
    let mut names = Vec::new();
    let mut lines = text.lines().map(str::trim);
    while let Some(line) = lines.next() {
        if line != "<key>EnvironmentVariables</key>" {
            continue;
        }
        match lines.next()? {
            "<dict/>" => continue,
            "<dict>" => {}
            _ => return None,
        }
        loop {
            let line = lines.next()?;
            if line == "</dict>" {
                break;
            }
            if let Some(name) = line
                .strip_prefix("<key>")
                .and_then(|l| l.strip_suffix("</key>"))
            {
                names.push(name.to_owned());
            } else if !(line.starts_with("<string>") && line.ends_with("</string>")) {
                return None;
            }
        }
    }
    Some(names)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::commands::service::{APPROVALS, PROXY};

    fn spec() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        (
            PathBuf::from("/opt/homebrew/bin/moat"),
            PathBuf::from("/Users/u/.moat"),
            PathBuf::from("/Users/u/.moat/logs/proxy.out.log"),
            PathBuf::from("/Users/u/.moat/logs/proxy.err.log"),
        )
    }

    /// The proxy's plist is byte for byte what earlier releases wrote, so an
    /// installed proxy service still reads back unchanged.
    #[test]
    fn the_proxy_plist_keeps_its_bytes() {
        let (bin, home, out_log, err_log) = spec();
        let text = render(&Spec {
            job: &PROXY,
            binary: &bin,
            moat_home: &home,
            stdout_log: &out_log,
            stderr_log: &err_log,
        });
        let expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n  <key>EnvironmentVariables</key>\n  <dict>\n    \
<key>MOAT_HOME</key>\n    <string>/Users/u/.moat</string>\n  </dict>\n  <key>KeepAlive</key>\n  \
<dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>\n  <key>Label</key>\n  \
<string>dev.openmoat.proxy</string>\n  <key>ProgramArguments</key>\n  <array>\n    \
<string>/opt/homebrew/bin/moat</string>\n    <string>proxy</string>\n  </array>\n  \
<key>ProcessType</key>\n  <string>Background</string>\n  <key>RunAtLoad</key>\n  <true/>\n  \
<key>StandardErrorPath</key>\n  <string>/Users/u/.moat/logs/proxy.err.log</string>\n  \
<key>StandardOutPath</key>\n  <string>/Users/u/.moat/logs/proxy.out.log</string>\n\
</dict>\n</plist>\n";
        assert_eq!(text, expected);
    }

    /// The listener's plist runs `approvals listen --service` from the pinned
    /// binary at login, restarts it when it fails, logs under the state
    /// directory and makes every file it creates owner-only.
    #[test]
    fn the_listener_plist_runs_the_service_listener_owner_only() {
        let text = render(&Spec {
            job: &APPROVALS,
            binary: &PathBuf::from("/opt/homebrew/bin/openmoat"),
            moat_home: &PathBuf::from("/Users/u/.moat"),
            stdout_log: &PathBuf::from("/Users/u/.moat/logs/approvals.out.log"),
            stderr_log: &PathBuf::from("/Users/u/.moat/logs/approvals.err.log"),
        });
        assert!(text.contains("  <key>Label</key>\n  <string>dev.openmoat.approvals</string>\n"));
        assert!(text.contains(
            "  <array>\n    <string>/opt/homebrew/bin/openmoat</string>\n    \
             <string>approvals</string>\n    <string>listen</string>\n    \
             <string>--service</string>\n  </array>\n"
        ));
        assert!(text.contains("  <key>RunAtLoad</key>\n  <true/>\n"));
        assert!(text.contains("<key>SuccessfulExit</key>\n    <false/>"));
        assert!(text.contains("<string>/Users/u/.moat/logs/approvals.err.log</string>"));
        // 077 octal: owner-only files.
        assert!(text.ends_with("  <key>Umask</key>\n  <integer>63</integer>\n</dict>\n</plist>\n"));
        assert_eq!(environment(&text), Some(vec!["MOAT_HOME".to_owned()]));
    }

    #[test]
    fn plist_is_deterministic_and_names_what_the_proxy_needs() {
        let (bin, home, out_log, err_log) = spec();
        let text = render(&Spec {
            job: &PROXY,
            binary: &bin,
            moat_home: &home,
            stdout_log: &out_log,
            stderr_log: &err_log,
        });
        assert!(text.contains("<key>Label</key>"));
        assert!(text.contains("dev.openmoat.proxy"));
        assert!(text.contains("<key>MOAT_HOME</key>"));
        assert!(text.contains("/Users/u/.moat"));
        assert!(text.contains("<key>ProgramArguments</key>"));
        assert!(text.contains("/opt/homebrew/bin/moat"));
        assert!(text.contains("<string>proxy</string>"));
        assert!(text.contains("<key>RunAtLoad</key>"));
        assert!(text.contains("<true/>"));
        assert!(text.contains("<key>SuccessfulExit</key>"));
        assert!(text.contains("<false/>"));
        assert!(text.contains("StandardOutPath"));
        assert!(text.contains("StandardErrorPath"));
        // Byte-for-byte stability: two renders match.
        let again = render(&Spec {
            job: &PROXY,
            binary: &bin,
            moat_home: &home,
            stdout_log: &out_log,
            stderr_log: &err_log,
        });
        assert_eq!(text, again);
    }

    #[test]
    fn xml_special_characters_in_paths_are_escaped() {
        let home = PathBuf::from("/Users/a&b/<moat>");
        let text = render(&Spec {
            job: &PROXY,
            binary: &PathBuf::from("/bin/moat"),
            moat_home: &home,
            stdout_log: &PathBuf::from("/tmp/out"),
            stderr_log: &PathBuf::from("/tmp/err"),
        });
        assert!(text.contains("/Users/a&amp;b/&lt;moat&gt;"));
        assert!(!text.contains("/Users/a&b/<moat>"));
    }

    #[test]
    fn environment_names_each_variable_the_plist_sets() {
        let (bin, home, out_log, err_log) = spec();
        let text = render(&Spec {
            job: &PROXY,
            binary: &bin,
            moat_home: &home,
            stdout_log: &out_log,
            stderr_log: &err_log,
        });
        assert_eq!(environment(&text), Some(vec!["MOAT_HOME".to_owned()]));
        let tampered = text.replace(
            "    <key>MOAT_HOME</key>\n",
            "    <key>DYLD_INSERT_LIBRARIES</key>\n    <string>/x.dylib</string>\n    \
             <key>MOAT_HOME</key>\n",
        );
        assert_eq!(
            environment(&tampered),
            Some(vec![
                "DYLD_INSERT_LIBRARIES".to_owned(),
                "MOAT_HOME".to_owned()
            ])
        );
        assert_eq!(environment("bplist00"), None);
        let broken = text.replace(
            "  <dict>\n    <key>MOAT_HOME",
            "  <array>\n    <key>MOAT_HOME",
        );
        assert_eq!(environment(&broken), None);
    }
}
