//! Cursor's `hooks.json` entries:
//! `{"version": 1, "hooks": {"<event>": [{"command": "<shell string>",
//! "timeout", "failClosed"}]}}`. Cursor is fail-open unless `failClosed` is
//! set, so every entry sets it.

use serde_json::{Value, json};

use crate::HookSpec;
use crate::wire::guard_command::{GuardCommand, split_guard};
use crate::wire::hook_file::HookFile;

/// Cursor's `hooks.json` entries.
#[derive(Debug)]
pub(crate) struct Cursor;

impl HookFile for Cursor {
    fn entry(&self, spec: &HookSpec, id: &str, guard: &GuardCommand, _block: bool) -> Value {
        json!({
            "command": command(guard, id),
            "timeout": spec.timeout,
            "failClosed": true,
        })
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        entry
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|c| split_guard(c, id).is_some())
    }

    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        binary_of(entry.get("command")?.as_str()?, id)
    }

    fn has_version(&self) -> bool {
        true
    }

    fn fail_closed_key(&self) -> Option<&'static str> {
        Some("failClosed")
    }
}

/// Cursor takes one shell string, which its shell expands. On POSIX the
/// binary path goes in single quotes, inside which `$`, a backtick and `\`
/// mean nothing (a `'` is written `'\''`), so a path such as
/// `/opt/$(x)/openmoat` runs that file and nothing else. Windows paths
/// cannot hold `"`, so they keep double quotes.
fn command(guard: &GuardCommand, id: &str) -> String {
    command_for(guard, id, cfg!(windows))
}

/// [`command`] for POSIX or for Windows.
fn command_for(guard: &GuardCommand, id: &str, windows: bool) -> String {
    let (binary, args) = (&guard.binary, guard.shell_args(id));
    if windows {
        format!("\"{binary}\"{args}")
    } else {
        format!("'{}'{args}", binary.replace('\'', r"'\''"))
    }
}

/// The binary a command written by [`command_for`] runs, also from the
/// double-quoted form earlier releases wrote on POSIX (`"` escaped as
/// `\"`); `None` when it is not OpenMoat's guard for `id`.
fn binary_of(command: &str, id: &str) -> Option<String> {
    let (quoted, _) = split_guard(command, id)?;
    if let Some(inner) = quoted.strip_prefix('\'').and_then(|q| q.strip_suffix('\'')) {
        return Some(inner.replace(r"'\''", "'"));
    }
    if let Some(inner) = quoted.strip_prefix('"').and_then(|q| q.strip_suffix('"')) {
        return Some(inner.replace("\\\"", "\""));
    }
    Some(quoted.to_owned())
}

#[cfg(test)]
mod tests {
    use super::binary_of;
    use crate::GuardCommand;

    fn command_for(binary: &str, id: &str, windows: bool) -> String {
        super::command_for(&GuardCommand::new(binary), id, windows)
    }

    #[test]
    fn the_posix_path_is_single_quoted_so_the_shell_expands_nothing() {
        for path in [
            "/Applications/My Tools/openmoat",
            "/opt/$(touch x)/openmoat",
            "/opt/`id`/openmoat",
            "/opt/a\\b/openmoat",
            "/opt/it's/openmoat",
            "/opt/\"q\"/openmoat",
        ] {
            let command = command_for(path, "cursor", false);
            assert!(command.starts_with('\''), "{command}");
            assert_eq!(binary_of(&command, "cursor").as_deref(), Some(path), "{command}");
        }
        assert_eq!(
            command_for("/opt/$(x)/openmoat", "cursor", false),
            "'/opt/$(x)/openmoat' guard --host cursor"
        );
        assert_eq!(
            command_for("/opt/it's/openmoat", "cursor", false),
            r"'/opt/it'\''s/openmoat' guard --host cursor"
        );
    }

    #[test]
    fn windows_keeps_double_quotes_and_the_old_form_still_reads() {
        let windows = command_for(r"C:\Program Files\openmoat.exe", "cursor", true);
        assert_eq!(windows, r#""C:\Program Files\openmoat.exe" guard --host cursor"#);
        assert_eq!(
            binary_of(&windows, "cursor").as_deref(),
            Some(r"C:\Program Files\openmoat.exe")
        );
        let old = r#""/opt/a \"b\"/moat" guard --host cursor"#;
        assert_eq!(binary_of(old, "cursor").as_deref(), Some(r#"/opt/a "b"/moat"#));
        assert_eq!(binary_of("'/x/openmoat' guard --host other", "cursor"), None);
    }
}
