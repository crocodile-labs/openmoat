//! Settings an administrator deploys for every user of the machine, which a
//! host reads before the person's own and which outrank them: Claude Code's
//! managed settings, Gemini CLI's system settings and system defaults, Codex's
//! `requirements.toml`. One of them can turn every hook off, OpenMoat's
//! included, or run only the hooks it lists itself. The agent cannot write
//! them (`managed-settings` in the default policy); `moat status` and
//! `moat doctor` read them to say when the installed hook does not run.

use serde_json::{Map, Value};

use super::Platform;

/// Where a host reads its system-wide settings, and the key that makes it run
/// only the hooks they list ([`crate::HostSpec::system_settings`]).
#[derive(Debug)]
#[non_exhaustive]
pub struct SystemSettingsSpec {
    /// The files, each on the platforms that read it.
    pub files: &'static [SystemFile],
    /// A directory beside each file whose `*.json` files the host merges over
    /// it (Claude Code's `managed-settings.d`); `None` when it reads none.
    pub drop_ins: Option<&'static str>,
    /// The key that, set to `true`, makes the host skip the person's own hooks
    /// and run only those the system files list (`allowManagedHooksOnly`,
    /// `allow_managed_hooks_only`); `None` for a host without one.
    pub managed_only: Option<&'static str>,
    /// The key the system files list their own hooks under.
    pub hooks_key: &'static str,
}

/// One system settings file ([`SystemSettingsSpec::files`]).
#[derive(Debug)]
#[non_exhaustive]
pub struct SystemFile {
    /// Its absolute path, with `/` separators.
    pub path: &'static str,
    /// The platforms that read it there.
    pub platforms: &'static [Platform],
    /// The environment variable that names the file instead, when the host
    /// has one (`GEMINI_CLI_SYSTEM_SETTINGS_PATH`).
    pub variable: Option<&'static str>,
}

impl SystemFile {
    /// A file read at `path` on `platforms`, with no variable to move it.
    #[must_use]
    pub const fn at(path: &'static str, platforms: &'static [Platform]) -> Self {
        Self {
            path,
            platforms,
            variable: None,
        }
    }

    /// This file, read where `variable` names when it is set.
    #[must_use]
    pub const fn moved_by(self, variable: &'static str) -> Self {
        Self {
            variable: Some(variable),
            ..self
        }
    }
}

impl SystemSettingsSpec {
    /// Why `roots`, the system files the host read (a drop-in after the file
    /// it is merged over), make it run only their own hooks, none of them
    /// OpenMoat's: the key named, or `None`. A hook entry is OpenMoat's when its
    /// command runs `openmoat guard` or `moat guard`.
    #[must_use]
    pub fn managed_only_without_openmoat(&self, roots: &[&Map<String, Value>]) -> Option<String> {
        let key = self.managed_only?;
        let on = roots
            .iter()
            .filter_map(|root| root.get(key))
            .next_back()
            .is_some_and(|v| v == &Value::Bool(true));
        let ours = roots
            .iter()
            .filter_map(|root| root.get(self.hooks_key))
            .any(runs_openmoat);
        (on && !ours).then(|| {
            format!(
                "`{key}` runs only the hooks these settings list, and none of them is OpenMoat's"
            )
        })
    }
}

/// Whether any string in `value` is a command that runs the guard.
fn runs_openmoat(value: &Value) -> bool {
    match value {
        Value::String(s) => s.contains("moat") && s.contains(" guard"),
        Value::Array(items) => items.iter().any(runs_openmoat),
        Value::Object(map) => map.values().any(runs_openmoat),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SPEC: SystemSettingsSpec = SystemSettingsSpec {
        files: &[],
        drop_ins: None,
        managed_only: Some("allowManagedHooksOnly"),
        hooks_key: "hooks",
    };

    fn object(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => Map::new(),
        }
    }

    #[test]
    fn managed_only_is_named_unless_the_system_files_run_openmoat() {
        let on = object(json!({"allowManagedHooksOnly": true}));
        assert!(SPEC.managed_only_without_openmoat(&[&on]).is_some());
        let ours = object(
            json!({"allowManagedHooksOnly": true, "hooks": {"PreToolUse": [
                {"hooks": [{"type": "command", "command": "/usr/local/bin/openmoat guard --host claude-code"}]}
            ]}}),
        );
        assert_eq!(SPEC.managed_only_without_openmoat(&[&ours]), None);
        // A drop-in may carry the hooks or turn the key off again.
        let hooks = object(json!({"hooks": {"x": "/opt/moat guard"}}));
        assert_eq!(SPEC.managed_only_without_openmoat(&[&on, &hooks]), None);
        let off = object(json!({"allowManagedHooksOnly": false}));
        assert_eq!(SPEC.managed_only_without_openmoat(&[&on, &off]), None);
        let other = object(json!({"hooks": {"x": "/opt/lint.sh"}}));
        assert!(SPEC.managed_only_without_openmoat(&[&on, &other]).is_some());
    }

    #[test]
    fn a_host_without_the_key_never_names_it() {
        let none = SystemSettingsSpec {
            managed_only: None,
            ..SPEC
        };
        let on = object(json!({"allowManagedHooksOnly": true}));
        assert_eq!(none.managed_only_without_openmoat(&[&on]), None);
    }
}
