//! MCP servers that start outside what OpenMoat checks, for `moat status` and
//! `moat doctor` (ADR-049): a server that runs a local command and is not
//! wrapped starts with the person's permissions before OpenMoat sees any of
//! its calls; a wrapped one without `--sandbox` is checked before it starts but
//! runs unconfined; and a project's server the host is set to start without
//! asking (its spec's `McpAutoStart`) starts as soon as a session opens the
//! project. Warnings only: the person decides.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use openmoat_hosts::{AutoStart, Host, McpAutoStart, McpSyntax};
use serde_json::{Map, Value};

use super::servers::{self, Source};
use super::{set_up_hosts, wrap};
use crate::home::Home;
use crate::install::HostConfig;

/// Why one server starts outside what OpenMoat checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// Not run through `moat mcp proxy`; `user` when its file is the
    /// person's own, which `moat mcp wrap` can change.
    Unwrapped { user: bool },
    /// Run through the proxy without its sandbox.
    Unsandboxed,
    /// A project's server the host starts without asking, as `by` says.
    AutoStarted { by: String },
}

/// One server that starts outside what OpenMoat checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outside {
    pub host: Host,
    pub name: String,
    pub file: PathBuf,
    pub kind: Kind,
}

impl Outside {
    /// One line for a person.
    pub fn describe(&self) -> String {
        let mut text = format!(
            "`{}` ({}, {}) ",
            self.name,
            self.host.display_name(),
            self.file.display()
        );
        let _ = match &self.kind {
            Kind::Unwrapped { user: true } => write!(
                text,
                "starts outside OpenMoat with your permissions, unchecked; `openmoat mcp wrap {}` \
                 checks its definition before it starts and sandboxes it",
                self.name
            ),
            Kind::Unwrapped { user: false } => write!(
                text,
                "is a project's server that starts outside OpenMoat with your permissions, \
                 unchecked (`openmoat mcp wrap` changes only your own files)"
            ),
            Kind::Unsandboxed => write!(
                text,
                "runs through OpenMoat without the sandbox, with your permissions; \
                 `openmoat mcp wrap --sandbox {}` starts it in `openmoat run`'s sandbox",
                self.name
            ),
            Kind::AutoStarted { by } => write!(
                text,
                "starts as soon as a session opens this project, without asking ({by})"
            ),
        };
        text
    }
}

/// Every server the set-up hosts read for a session in `cwd` that starts
/// outside what OpenMoat checks.
pub fn report(home: &Home, binary: &Path, cwd: Option<&Path>) -> Result<Vec<Outside>> {
    let mut out = Vec::new();
    for host in set_up_hosts(home, binary) {
        let sources = servers::sources(home, host, cwd)?;
        let scan = servers::scan(&sources);
        let user: BTreeSet<&Path> = sources
            .iter()
            .filter(|s| s.user)
            .map(|s| s.path.as_path())
            .collect();
        let started = match (host.spec().mcp.as_ref().and_then(|m| m.auto_start), cwd) {
            (Some(reader), Some(cwd)) => auto_start(home, host, reader, cwd, &sources)?,
            _ => Started::default(),
        };
        for server in &scan.servers {
            let in_user = user.contains(server.file.as_path());
            let mut push = |kind| {
                out.push(Outside {
                    host,
                    name: server.name.clone(),
                    file: server.file.clone(),
                    kind,
                });
            };
            match wrap::sandboxed(&server.entry) {
                Some(false) => push(Kind::Unsandboxed),
                None if wrap::starts_process(&server.entry) => {
                    push(Kind::Unwrapped { user: in_user });
                }
                // Sandboxed, or a remote server, which runs no command here.
                _ => {}
            }
            if !in_user && let Some(by) = started.by(&server.name) {
                push(Kind::AutoStarted { by });
            }
        }
    }
    Ok(out)
}

/// What a host's settings say about starting a project's servers.
#[derive(Debug, Default)]
pub struct Started {
    /// Where every server is turned on.
    all: Option<String>,
    /// Server name → where it is turned on.
    named: BTreeMap<String, String>,
    /// Servers turned off.
    off: BTreeSet<String>,
}

impl Started {
    /// Add what the settings at `place` say.
    pub fn add(&mut self, place: &str, found: Vec<AutoStart>) {
        for setting in found {
            match setting {
                AutoStart::All { key } => {
                    self.all
                        .get_or_insert_with(|| format!("`{key}` in {place}"));
                }
                AutoStart::Named { key, name } => {
                    self.named
                        .entry(name)
                        .or_insert_with(|| format!("`{key}` in {place}"));
                }
                AutoStart::Off { name, .. } => {
                    self.off.insert(name);
                }
                _ => {}
            }
        }
    }

    /// Where server `name` is turned on; `None` when it is not, or is off.
    pub fn by(&self, name: &str) -> Option<String> {
        if self.off.contains(name) {
            return None;
        }
        self.named.get(name).or(self.all.as_ref()).cloned()
    }
}

/// What `host`'s settings files and its user MCP file say about starting the
/// servers of the project in `cwd`.
fn auto_start(
    home: &Home,
    host: Host,
    reader: &dyn McpAutoStart,
    cwd: &Path,
    sources: &[Source],
) -> Result<Started> {
    let mut started = Started::default();
    let user_home = crate::home::user_home()?;
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(spec) = host.spec().project_settings.as_ref() {
        let dir = HostConfig::for_host(home, host)?.dir().to_path_buf();
        files.extend(
            std::iter::once(spec.user_file)
                .chain(spec.user_more.iter().copied())
                .map(|name| dir.join(name)),
        );
        for name in spec.files() {
            files.extend(crate::project_settings::candidates(
                cwd, &user_home, spec, name,
            ));
        }
    }
    for path in files {
        if let Some(Value::Object(root)) = read_json(&path) {
            started.add(&path.display().to_string(), reader.settings(&root));
        }
    }
    let dirs = project_keys(cwd, &user_home);
    for source in sources.iter().filter(|s| s.user) {
        if source.reader.syntax() != McpSyntax::Json {
            continue;
        }
        let Some(doc) = read_json(&source.path) else {
            continue;
        };
        for dir in &dirs {
            if let Some(entry) = reader.project_entry(&doc, dir) {
                let place = format!("{} for {dir}", source.path.display());
                started.add(&place, reader.settings(&Map::clone(entry)));
            }
        }
    }
    Ok(started)
}

/// The spellings a host may key the project in `cwd` by: the directory and
/// its project root, as given and with links resolved.
fn project_keys(cwd: &Path, user_home: &Path) -> Vec<String> {
    let mut dirs = vec![cwd.to_path_buf()];
    if let Some(root) = crate::project::root_of(cwd, user_home) {
        dirs.push(root);
    }
    let resolved: Vec<PathBuf> = dirs
        .iter()
        .filter_map(|d| std::fs::canonicalize(d).ok())
        .collect();
    let mut keys: Vec<String> = Vec::new();
    for dir in dirs.into_iter().chain(resolved) {
        let key = dir.display().to_string();
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys
}

/// `path` parsed as JSON; `None` when it is absent or cannot be read (the
/// project settings warnings name a file that cannot be read).
fn read_json(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

#[cfg(test)]
mod tests;
