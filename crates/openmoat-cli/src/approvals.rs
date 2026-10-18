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
    /// The id of the newest audit event when the grant was written (0 for an
    /// empty log): it saw every event up to this one. Ids only grow, so this
    /// orders the grant against later calls even if the clock steps back. A
    /// grant written by an older build has none and is ordered by time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_row: Option<i64>,
    /// Also answers every other session-taint ask of this host session that
    /// comes from untrusted content, until the session reads untrusted content
    /// again (`moat allow --last`, answer `s`). Never a secret taint. A build
    /// that does not know the field reads it as a grant for `action` alone.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub covers_taint: bool,
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
                    audit_row: None,
                    covers_taint: false,
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
    /// `now_ms`, having seen the audit log up to `audit_row`; granting it again
    /// restarts its lifetime.
    pub fn grant(
        &mut self,
        host: &str,
        session_id: &str,
        action: &Action,
        now_ms: i64,
        audit_row: Option<i64>,
    ) {
        self.entries
            .retain(|g| !(g.host == host && g.session_id == session_id && g.action == *action));
        self.entries.push(Grant {
            host: host.to_owned(),
            session_id: session_id.to_owned(),
            action: action.clone(),
            granted_at_ms: now_ms,
            audit_row,
            covers_taint: false,
        });
    }

    /// Exact match of `action` (spelled by [`approvable`]) for this host session
    /// among grants still valid at `now_ms`; no prefix or glob semantics.
    /// A call without a session id never matches: every such call shares the
    /// placeholder id, so a grant for it would hold in every session.
    #[must_use]
    pub fn matches(&self, host: &str, session_id: &str, action: &Action, now_ms: i64) -> bool {
        self.granted_at(host, session_id, action, now_ms).is_some()
    }

    /// When the grant [`Grants::matches`] finds was made, if there is one.
    #[must_use]
    pub fn granted_at(
        &self,
        host: &str,
        session_id: &str,
        action: &Action,
        now_ms: i64,
    ) -> Option<i64> {
        self.newest(host, session_id, action, now_ms)
            .map(|g| g.granted_at_ms)
    }

    /// The newest grant [`Grants::matches`] finds, if there is one.
    #[must_use]
    pub fn newest(
        &self,
        host: &str,
        session_id: &str,
        action: &Action,
        now_ms: i64,
    ) -> Option<&Grant> {
        if openmoat_hosts::is_unknown_session(session_id) {
            return None;
        }
        self.active(now_ms)
            .filter(|g| g.host == host && g.session_id == session_id && g.action == *action)
            .max_by_key(|g| g.granted_at_ms)
    }

    /// Make the grant for `action` in this host session also answer the
    /// session's other taint asks from untrusted content ([`Grant::covers_taint`]).
    pub fn cover_taint(&mut self, host: &str, session_id: &str, action: &Action) {
        for g in &mut self.entries {
            if g.host == host && g.session_id == session_id && g.action == *action {
                g.covers_taint = true;
            }
        }
    }

    /// The newest grant of this host session that answers its taint asks from
    /// untrusted content, if one is still valid at `now_ms`.
    #[must_use]
    pub fn covering_taint(&self, host: &str, session_id: &str, now_ms: i64) -> Option<&Grant> {
        if openmoat_hosts::is_unknown_session(session_id) {
            return None;
        }
        self.active(now_ms)
            .filter(|g| g.covers_taint && g.host == host && g.session_id == session_id)
            .max_by_key(|g| g.granted_at_ms)
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
    /// So are the files CI, a commit-hook manager or the editor runs later
    /// ([`RUNS_LATER`](crate::sandbox::RUNS_LATER)), which `runs-later` asks for.
    pub fn allow_dir(&mut self, spellings: &[String]) -> &RuleGroup {
        let patterns: Vec<String> = spellings
            .iter()
            .flat_map(|dir| [dir.clone(), format!("{dir}/**")])
            .collect();
        let git: Vec<String> = spellings
            .iter()
            .flat_map(|dir| {
                [format!("!{dir}/.git/**"), format!("!{dir}/**/.git/**")]
                    .into_iter()
                    .chain(
                        crate::sandbox::RUNS_LATER
                            .iter()
                            .map(move |f| format!("!{dir}/{f}")),
                    )
            })
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
mod tests;
