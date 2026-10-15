//! Human approvals that outlive one prompt.
//!
//! Two files under `~/.moat`, both pinned by the policy lock so an agent cannot
//! grant itself anything:
//! - `approvals.json`: session grants, an exact command or exact files for one host
//!   session, valid for [`GRANT_TTL_MS`] after they are written;
//! - `policy.d/approved.yaml`: permanent allow rules appended by `moat allow --always`,
//!   `--site` and `--dir`, merged into the user policy at load time so `policy.yaml` is never rewritten.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use openmoat_core::{Action, RuleGroup};
use serde::{Deserialize, Serialize};

use crate::home::write_private;
use crate::time;

mod asked;
pub use asked::{approvable, describe, files};

/// Version 2 grants an [`Action`]; version 1 granted only a `command` string.
const GRANTS_VERSION: u32 = 2;
const OVERLAY_VERSION: u32 = 1;
pub const OVERLAY_PREFIX: &str = "approved-";
/// How long a session grant stays valid. Hosts do not tell OpenMoat when a session
/// ends, so a fixed lifetime is what bounds a grant.
pub const GRANT_TTL_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub host: String,
    pub session_id: String,
    /// What is approved, as [`approvable`] spells it.
    pub action: Action,
    /// Milliseconds since the epoch. A grant written without one reads as 0,
    /// long expired: a grant whose age is unknown must not stay valid forever.
    #[serde(default)]
    pub granted_at_ms: i64,
}

/// A version 1 grant: a shell command.
#[derive(Deserialize)]
struct GrantV1 {
    host: String,
    session_id: String,
    command: String,
    #[serde(default)]
    granted_at_ms: i64,
}

#[derive(Deserialize)]
struct GrantsV1 {
    entries: Vec<GrantV1>,
}

impl Grant {
    /// Valid for [`GRANT_TTL_MS`] from its creation. A creation time in the
    /// future (a clock set back, a hand edit) is not valid either.
    #[must_use]
    pub fn active(&self, now_ms: i64) -> bool {
        (0..GRANT_TTL_MS).contains(&now_ms.saturating_sub(self.granted_at_ms))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grants {
    pub version: u32,
    pub entries: Vec<Grant>,
}

impl Default for Grants {
    fn default() -> Self {
        Self {
            version: GRANTS_VERSION,
            entries: Vec::new(),
        }
    }
}

impl Grants {
    /// Missing file means no grants; a malformed or newer file is an error.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let parse = || format!("parsing {}", path.display());
        let value: serde_json::Value = serde_json::from_str(&text).with_context(parse)?;
        match value.get("version").and_then(serde_json::Value::as_u64) {
            Some(1) => {
                let old: GrantsV1 = serde_json::from_value(value).with_context(parse)?;
                let entries = old.entries.into_iter().map(|g| Grant {
                    host: g.host,
                    session_id: g.session_id,
                    action: Action::Shell {
                        command: g.command.trim().to_owned(),
                    },
                    granted_at_ms: g.granted_at_ms,
                });
                Ok(Self {
                    version: GRANTS_VERSION,
                    entries: entries.collect(),
                })
            }
            Some(2) => serde_json::from_value(value).with_context(parse),
            version => bail!(
                "{} has version {}; this build supports {GRANTS_VERSION}",
                path.display(),
                version.map_or_else(|| "none".to_owned(), |v| v.to_string())
            ),
        }
    }

    /// Write the file, dropping grants that expired by `now_ms` so it does not
    /// grow without bound.
    pub fn save(&mut self, path: &Path, now_ms: i64) -> Result<()> {
        self.entries.retain(|g| g.active(now_ms));
        write_private(
            path,
            (serde_json::to_string_pretty(self)? + "\n").as_bytes(),
        )
    }

    /// Grant `action` (spelled by [`approvable`]) to the host session as of
    /// `now_ms`; granting it again restarts its lifetime.
    pub fn grant(&mut self, host: &str, session_id: &str, action: &Action, now_ms: i64) {
        self.entries
            .retain(|g| !(g.host == host && g.session_id == session_id && g.action == *action));
        self.entries.push(Grant {
            host: host.to_owned(),
            session_id: session_id.to_owned(),
            action: action.clone(),
            granted_at_ms: now_ms,
        });
    }

    /// Exact match of `action` (spelled by [`approvable`]) for this host session
    /// among grants still valid at `now_ms`; no prefix or glob semantics.
    #[must_use]
    pub fn matches(&self, host: &str, session_id: &str, action: &Action, now_ms: i64) -> bool {
        self.active(now_ms)
            .any(|g| g.host == host && g.session_id == session_id && g.action == *action)
    }

    /// Grants still valid at `now_ms`.
    pub fn active(&self, now_ms: i64) -> impl Iterator<Item = &Grant> {
        self.entries.iter().filter(move |g| g.active(now_ms))
    }
}

/// Allow rules appended by `moat allow --always`, `--site` and `--dir`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overlay {
    pub version: u32,
    #[serde(default)]
    pub allow: Vec<RuleGroup>,
}

impl Default for Overlay {
    fn default() -> Self {
        Self {
            version: OVERLAY_VERSION,
            allow: Vec::new(),
        }
    }
}

impl Overlay {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let overlay: Self = openmoat_core::yaml::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))?;
        if overlay.version != OVERLAY_VERSION {
            bail!(
                "{} has version {}; this build supports {OVERLAY_VERSION}",
                path.display(),
                overlay.version
            );
        }
        if let Some(bad) = overlay
            .allow
            .iter()
            .find(|g| !g.id.starts_with(OVERLAY_PREFIX))
        {
            bail!(
                "{}: rule `{}` must have an id starting with `{OVERLAY_PREFIX}`",
                path.display(),
                bad.id
            );
        }
        Ok(overlay)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = format!(
            "# Permanent allow rules added with `moat allow`. Remove one with\n\
             # `moat allow --remove <id>`, or edit freely, then run `moat doctor --accept`.\n{}",
            openmoat_core::yaml::to_string(self)?
        );
        write_private(path, text.as_bytes())
    }

    /// Append an allow rule for one shell command, matched literally: glob
    /// characters in the command are not wildcards in the rule. Shell rules are
    /// prefixes, so extra arguments after the approved command are accepted.
    pub fn allow_command(&mut self, command: &str) -> Result<&RuleGroup> {
        let pattern = openmoat_core::literal_shell_pattern(command)
            .with_context(|| format!("cannot approve `{command}`"))?;
        Ok(self.push("moat allow --always", |g| g.shell = vec![pattern]))
    }

    /// Append an `fs.read` and `fs.write` allow for exactly these paths. A path
    /// holding glob characters is refused: the rule would read them as wildcards.
    pub fn allow_files(&mut self, reads: &[String], writes: &[String]) -> Result<&RuleGroup> {
        if let Some(bad) = reads
            .iter()
            .chain(writes)
            .find(|p| p.contains(['*', '?', '[', ']', '{', '}', '\\']))
        {
            bail!(
                "{bad} contains glob characters; write it in the policy with `moat edit` instead"
            );
        }
        Ok(self.push("moat allow --always", |g| {
            g.fs_read = reads.to_vec();
            g.fs_write = writes.to_vec();
        }))
    }

    /// Whether a rule here already allows `action` (spelled by [`approvable`]).
    #[must_use]
    pub fn covers(&self, action: &Action) -> bool {
        if let Action::Shell { command } = action {
            let pattern = openmoat_core::literal_shell_pattern(command).ok();
            return self
                .allow
                .iter()
                .any(|g| pattern.as_ref().is_some_and(|p| g.shell.contains(p)));
        }
        let (reads, writes) = files(action);
        !(reads.is_empty() && writes.is_empty())
            && self.allow.iter().any(|g| {
                reads.iter().all(|p| g.fs_read.contains(p))
                    && writes.iter().all(|p| g.fs_write.contains(p))
            })
    }

    /// Append a `net` allow for one host name, which also covers web fetches.
    /// Only a plain name or address is accepted: a wildcard, scheme or port would
    /// widen the rule beyond what the person typed.
    pub fn allow_site(&mut self, host: &str) -> Result<&RuleGroup> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let plain = host.split('.').all(|label| {
            !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
        if !plain {
            bail!(
                "`{host}` is not a host name such as docs.rs; wildcards, URLs and ports \
                 are not accepted here (write those in the policy with `moat edit`)"
            );
        }
        Ok(self.push("moat allow --site", |g| g.net = vec![host]))
    }

    /// Append an `fs.read` and `fs.write` allow for each spelling of a directory
    /// and everything below it. Writes into a `.git` there are left out, as
    /// `project-fs` leaves out the project's: git runs what its hooks and config
    /// name later, outside any sandbox, so such a write is not allowed by this rule.
    pub fn allow_dir(&mut self, spellings: &[String]) -> &RuleGroup {
        let patterns: Vec<String> = spellings
            .iter()
            .flat_map(|dir| [dir.clone(), format!("{dir}/**")])
            .collect();
        let git: Vec<String> = spellings
            .iter()
            .flat_map(|dir| [format!("!{dir}/.git/**"), format!("!{dir}/**/.git/**")])
            .collect();
        self.push("moat allow --dir", |g| {
            g.fs_read.clone_from(&patterns);
            g.fs_write = patterns.into_iter().chain(git).collect();
        })
    }

    /// Remove the rule with this id, returning it.
    pub fn remove(&mut self, id: &str) -> Option<RuleGroup> {
        let index = self.allow.iter().position(|g| g.id == id)?;
        Some(self.allow.remove(index))
    }

    fn push(&mut self, how: &str, fill: impl FnOnce(&mut RuleGroup)) -> &RuleGroup {
        // One past the highest existing number: ids stay unique after a person
        // deletes an earlier rule, and a duplicate id would fail the policy lint.
        let n = self
            .allow
            .iter()
            .filter_map(|g| g.id.strip_prefix(OVERLAY_PREFIX)?.parse::<u64>().ok())
            .max()
            .unwrap_or(0)
            + 1;
        let mut rule = RuleGroup {
            id: format!("{OVERLAY_PREFIX}{n}"),
            reason: Some(format!(
                "approved with `{how}` on {}",
                time::timestamp(time::now_ms())
            )),
            ..RuleGroup::default()
        };
        fill(&mut rule);
        self.allow.push(rule);
        &self.allow[self.allow.len() - 1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(command: &str) -> Action {
        approvable(
            &Action::Shell {
                command: command.to_owned(),
            },
            None,
            "/h",
        )
        .unwrap()
    }

    #[test]
    fn overlay_ids_stay_unique_after_a_deletion() {
        let mut o = Overlay::default();
        for c in ["a", "b", "c"] {
            o.allow_command(c).unwrap();
        }
        o.allow.remove(0);
        assert_eq!(o.allow_command("d").unwrap().id, "approved-4");
        let ids: std::collections::BTreeSet<_> = o.allow.iter().map(|g| &g.id).collect();
        assert_eq!(ids.len(), o.allow.len());
    }

    #[test]
    fn sites_dirs_and_removal() {
        let mut o = Overlay::default();
        assert_eq!(o.allow_site(" Docs.RS. ").unwrap().net, ["docs.rs"]);
        for bad in [
            "*",
            "*.example.com",
            "https://x.dev",
            "x.dev:443",
            "",
            "a..b",
            "::1",
        ] {
            let error = o.allow_site(bad).unwrap_err().to_string();
            assert!(error.contains("in the policy"), "{bad}: {error}");
        }
        let dir = o.allow_dir(&["/w/a".to_owned(), "/real/a".to_owned()]);
        assert_eq!(dir.id, "approved-2");
        assert_eq!(dir.fs_read, ["/w/a", "/w/a/**", "/real/a", "/real/a/**"]);
        assert_eq!(
            dir.fs_write,
            [
                "/w/a",
                "/w/a/**",
                "/real/a",
                "/real/a/**",
                "!/w/a/.git/**",
                "!/w/a/**/.git/**",
                "!/real/a/.git/**",
                "!/real/a/**/.git/**"
            ],
            "writes into a `.git` there are left out, as for the project"
        );
        assert_eq!(o.remove("approved-1").unwrap().net, ["docs.rs"]);
        assert!(o.remove("approved-1").is_none());
        assert_eq!(o.allow.len(), 1);
    }

    /// 2026-10-03 00:00:00 UTC; tests pass time in, they never read the clock.
    const NOW: i64 = 1_790_985_600_000;

    #[test]
    fn grants_match_exactly_per_host_session() {
        let mut g = Grants::default();
        g.grant("claude-code", "s1", &sh(" npm install left-pad "), NOW);
        g.grant("claude-code", "s1", &sh("npm install left-pad"), NOW);
        assert_eq!(g.entries.len(), 1, "duplicates collapse");
        assert!(g.matches("claude-code", "s1", &sh("npm install left-pad"), NOW));
        assert!(!g.matches("claude-code", "s2", &sh("npm install left-pad"), NOW));
        assert!(!g.matches("cursor", "s1", &sh("npm install left-pad"), NOW));
        assert!(!g.matches("claude-code", "s1", &sh("npm install left-pad --save"), NOW));
    }

    #[test]
    fn grants_expire_after_the_ttl() {
        let mut g = Grants::default();
        g.grant("codex", "k1", &sh("cargo add serde"), NOW);
        let ok = |g: &Grants, at| g.matches("codex", "k1", &sh("cargo add serde"), at);
        assert!(ok(&g, NOW + GRANT_TTL_MS - 1));
        assert!(!ok(&g, NOW + GRANT_TTL_MS), "expired at the TTL");
        assert!(!ok(&g, NOW - 1), "a grant from the future is not valid");

        g.grant("codex", "k1", &sh("cargo add serde"), NOW + GRANT_TTL_MS);
        assert_eq!(g.entries.len(), 1);
        assert!(ok(&g, NOW + GRANT_TTL_MS + 1), "granting again restarts it");
    }

    #[test]
    fn version_1_grants_migrate_and_one_without_a_timestamp_is_expired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.json");
        let v1 = format!(
            r#"{{"version":1,"entries":[{{"host":"codex","session_id":"k1","command":"ls"}},
            {{"host":"codex","session_id":"k2","command":" ls ","granted_at_ms":{NOW}}}]}}"#
        );
        fs::write(&path, v1).unwrap();
        let g = Grants::load(&path).unwrap();
        assert_eq!(g.version, 2);
        assert_eq!(g.entries[0].granted_at_ms, 0);
        assert!(!g.matches("codex", "k1", &sh("ls"), NOW));
        assert!(g.matches("codex", "k2", &sh("ls"), NOW));
        fs::write(&path, r#"{"version":3,"entries":[]}"#).unwrap();
        assert!(Grants::load(&path).is_err(), "a newer file is refused");
    }

    #[test]
    fn saving_prunes_expired_grants() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.json");
        let mut g = Grants::default();
        g.grant("codex", "old", &sh("ls"), NOW - GRANT_TTL_MS);
        g.grant("codex", "new", &sh("ls"), NOW - 1);
        assert_eq!(g.active(NOW).count(), 1);
        g.save(&path, NOW).unwrap();
        let loaded = Grants::load(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].session_id, "new");
    }

    #[test]
    fn grants_and_overlay_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let grants_path = dir.path().join("approvals.json");
        let mut g = Grants::default();
        g.grant("codex", "k1", &sh("cargo add serde"), NOW);
        g.save(&grants_path, NOW).unwrap();
        assert_eq!(Grants::load(&grants_path).unwrap(), g);
        assert_eq!(
            Grants::load(&dir.path().join("missing.json")).unwrap(),
            Grants::default()
        );

        let overlay_path = dir.path().join("approved.yaml");
        let mut o = Overlay::default();
        assert_eq!(
            o.allow_command("npm install left-pad").unwrap().id,
            "approved-1"
        );
        assert_eq!(
            o.allow_command("pip install requests").unwrap().id,
            "approved-2"
        );
        o.save(&overlay_path).unwrap();
        let loaded = Overlay::load(&overlay_path).unwrap();
        assert_eq!(loaded.allow.len(), 2);
        assert_eq!(loaded.allow[1].shell, ["pip install requests"]);
        assert!(
            loaded.allow[0]
                .reason
                .as_deref()
                .unwrap()
                .contains("moat allow --always")
        );

        fs::write(
            &overlay_path,
            "version: 1\nallow:\n  - id: sneaky\n    shell: ['*']\n",
        )
        .unwrap();
        assert!(
            Overlay::load(&overlay_path)
                .unwrap_err()
                .to_string()
                .contains("approved-")
        );
    }
}
