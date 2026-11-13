//! Codex's Windows sandbox modes (<https://learn.chatgpt.com/docs/windows/windows-sandbox.md>,
//! read 2026-11-12): `[windows] sandbox = "mxc"`, `"elevated"` or
//! `"unelevated"` in `config.toml`, and `[features] prefer_mxc = true`. MXC
//! and `elevated` enumerate deny-read globs when each sandboxed process
//! starts; `unelevated` "doesn't support denied read paths" and "has weaker
//! network isolation". With no mode selected "Codex prefers `elevated`",
//! which needs one administrator-approved setup; the page does not say what
//! runs when that setup was never done. A managed `requirements.toml` can
//! narrow the modes further (`allow_mxc`, `allowed_sandbox_implementations`),
//! which is not read here.

use serde_json::{Map, Value};

use crate::contract::{WindowsSandboxLevel, WindowsSandboxMode, WindowsSandboxReader};

/// What to set for a mode that enforces OpenMoat's read denies.
const STRONGER: &str = "set `[windows] sandbox = \"elevated\"` (one administrator-approved \
                        `codex sandbox setup --elevated`) or `[features] prefer_mxc = true` on \
                        Windows 11 24H2 or later";

#[derive(Debug)]
pub(crate) struct Codex;

impl WindowsSandboxReader for Codex {
    fn mode(&self, root: &Map<String, Value>) -> WindowsSandboxMode {
        let chosen = root.get("windows").and_then(|w| w.get("sandbox"));
        let prefer_mxc = root
            .get("features")
            .and_then(|f| f.get("prefer_mxc"))
            .is_some_and(|v| v == &Value::Bool(true));
        let (level, text) = match chosen {
            Some(Value::String(mode)) if mode == "mxc" || mode == "elevated" => (
                WindowsSandboxLevel::Holds,
                format!(
                    "`[windows] sandbox = \"{mode}\"`: Codex's {mode} sandbox enforces the read \
                     and write denies OpenMoat writes"
                ),
            ),
            Some(Value::String(mode)) if mode == "unelevated" => (
                WindowsSandboxLevel::ReadsOpen,
                format!(
                    "`[windows] sandbox = \"unelevated\"`: Codex's docs say this mode does not \
                     support denied read paths and has weaker network isolation, so OpenMoat's \
                     read denies hold only through the hook; {STRONGER}"
                ),
            ),
            Some(other) => (
                WindowsSandboxLevel::Unknown,
                format!("`[windows] sandbox = {other}` is not a mode Codex documents; {STRONGER}"),
            ),
            None if prefer_mxc => (
                WindowsSandboxLevel::Unknown,
                "`[features] prefer_mxc = true`: Codex uses its MXC sandbox, which enforces \
                 OpenMoat's read denies, where this Windows supports it (Windows 11 24H2 or \
                 later); set `[windows] sandbox = \"mxc\"` to know it runs"
                    .to_owned(),
            ),
            None => (
                WindowsSandboxLevel::Unknown,
                format!(
                    "no `[windows] sandbox` in config.toml: Codex prefers `elevated`, and its \
                     docs do not say which mode runs where that was never set up (`unelevated` \
                     does not enforce OpenMoat's read denies); {STRONGER}"
                ),
            ),
        };
        WindowsSandboxMode { level, text }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn mode(root: &Value) -> WindowsSandboxMode {
        Codex.mode(root.as_object().unwrap())
    }

    #[test]
    fn mxc_and_elevated_hold_the_read_denies() {
        for chosen in ["mxc", "elevated"] {
            let found = mode(&json!({"windows": {"sandbox": chosen}}));
            assert_eq!(found.level, WindowsSandboxLevel::Holds, "{chosen}");
            assert!(found.text.contains(chosen), "{}", found.text);
        }
    }

    #[test]
    fn unelevated_leaves_reads_open_and_names_the_fix() {
        let found = mode(&json!({"windows": {"sandbox": "unelevated"}}));
        assert_eq!(found.level, WindowsSandboxLevel::ReadsOpen);
        assert!(found.text.contains("denied read paths"), "{}", found.text);
        assert!(found.text.contains("sandbox = \"elevated\""), "{}", found.text);
        // an explicit mode wins over the preference
        let both = mode(&json!({"windows": {"sandbox": "unelevated"}, "features": {"prefer_mxc": true}}));
        assert_eq!(both.level, WindowsSandboxLevel::ReadsOpen);
    }

    #[test]
    fn no_mode_or_an_undocumented_one_is_unknown() {
        for root in [
            json!({}),
            json!({"features": {"prefer_mxc": true}}),
            json!({"features": {"prefer_mxc": "yes"}}),
            json!({"windows": {"sandbox": "restricted-token"}}),
            json!({"windows": {"sandbox": 1}}),
            json!({"windows": "elevated"}),
        ] {
            assert_eq!(mode(&root).level, WindowsSandboxLevel::Unknown, "{root}");
        }
        assert!(mode(&json!({"windows": {"sandbox": 1}})).text.contains("sandbox = 1"));
    }
}
