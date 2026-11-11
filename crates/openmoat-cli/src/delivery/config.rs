//! `~/.moat/delivery.yaml`: where the audit log goes (ADR-081).
//!
//! The file lives in the state directory, which `kernel-self` keeps from the
//! agent, and is honoured only while the policy lock pins these exact bytes:
//! a file the lock does not know, or one that changed since a person accepted
//! it (`openmoat doctor --accept`), sends nothing. Whatever a sink reads (its
//! HMAC key, a header's token) comes from a file inside the state directory's
//! `delivery/`, which `kernel-self` also keeps the agent from reading, or from
//! the keychain, never from the environment, which the guard that starts a
//! delivery inherits from the agent's host. A CA may be anywhere in the state
//! directory: it is not secret.

use std::path::{Component, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_core::SecretSource;
use serde::Deserialize;

use crate::home::Home;
use crate::integrity::{Lock, sha256_hex};

/// The most sinks one configuration names.
pub const MAX_SINKS: usize = 4;

/// The default and the bounds of `max_backlog`: how many events a sink may
/// fall behind before the oldest are skipped, and the skip recorded.
pub const DEFAULT_MAX_BACKLOG: u64 = 100_000;
const BACKLOG_RANGE: std::ops::RangeInclusive<u64> = 100..=10_000_000;

/// The default and the bounds of `batch_bytes`: the most bytes of events in
/// one request (one event larger than that still goes alone).
pub const DEFAULT_BATCH_BYTES: usize = 512 * 1024;
const BATCH_RANGE: std::ops::RangeInclusive<usize> = 4 * 1024..=8 * 1024 * 1024;

/// The configuration as the file holds it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    machine: String,
    #[serde(default)]
    start: Start,
    #[serde(default)]
    max_backlog: Option<u64>,
    #[serde(default)]
    batch_bytes: Option<usize>,
    sinks: Vec<SinkFile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SinkFile {
    id: String,
    #[serde(default)]
    otlp: Option<String>,
    #[serde(default)]
    webhook: Option<String>,
    #[serde(default)]
    secret: Option<SecretSource>,
    #[serde(default)]
    headers: Vec<HeaderFile>,
    #[serde(default)]
    ca_file: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderFile {
    name: String,
    value: SecretSource,
    #[serde(default)]
    prefix: String,
}

/// Where a new sink starts in the log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Start {
    /// The events recorded since a person accepted the configuration.
    #[default]
    New,
    /// The whole log, up to `max_backlog` events of it.
    All,
}

/// The format a sink receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// OTLP/HTTP logs, JSON encoding.
    Otlp,
    /// The generic webhook body, signed with HMAC-SHA-256.
    Webhook,
}

impl Kind {
    pub fn id(self) -> &'static str {
        match self {
            Self::Otlp => "otlp",
            Self::Webhook => "webhook",
        }
    }
}

/// A header a sink sends: its name, and the value read from `value`.
#[derive(Debug, Clone)]
pub struct Header {
    pub name: String,
    pub value: SecretSource,
    pub prefix: String,
}

/// One destination.
#[derive(Debug, Clone)]
pub struct Sink {
    pub id: String,
    pub kind: Kind,
    pub url: String,
    pub endpoint: openmoat_proxy::Endpoint,
    /// The HMAC key's source (webhook only, required there).
    pub secret: Option<SecretSource>,
    pub headers: Vec<Header>,
    /// A CA to verify the endpoint with instead of the system's roots.
    pub ca_file: Option<PathBuf>,
}

/// The checked configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub machine: String,
    pub start: Start,
    pub max_backlog: u64,
    pub batch_bytes: usize,
    pub sinks: Vec<Sink>,
}

/// The configuration, when the file exists; refused unless the policy lock
/// pins these bytes. `None` when there is no file.
pub fn load_pinned(home: &Home) -> Result<Option<(Config, Lock)>> {
    let path = home.delivery_config_path();
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    ensure!(
        meta.file_type().is_file(),
        "{} is not a regular file; audit delivery is off",
        path.display()
    );
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let lock = Lock::load(&home.lock_path())?;
    match lock.pinned_digest(&path) {
        Some(pinned) if pinned == sha256_hex(&bytes) => {}
        Some(_) => bail!(
            "{} changed since it was accepted; nothing is sent until you run `openmoat doctor \
             --accept` from your terminal",
            path.display()
        ),
        None => bail!(
            "{} is not pinned by the policy lock; nothing is sent until you run `openmoat doctor \
             --accept` from your terminal",
            path.display()
        ),
    }
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("reading {} (must be UTF-8)", path.display()))?;
    let config = parse(text, home).with_context(|| format!("reading {}", path.display()))?;
    Ok(Some((config, lock)))
}

/// Parse and check `text`; file sources are resolved against `home`.
pub fn parse(text: &str, home: &Home) -> Result<Config> {
    let file: File = openmoat_core::yaml::from_str(text)?;
    ensure!(file.version == 1, "version must be 1");
    ensure!(
        valid_name(&file.machine, 64, true),
        "machine must be 1 to 64 letters, digits, `.`, `-` or `_`"
    );
    ensure!(!file.sinks.is_empty(), "name at least one sink");
    ensure!(file.sinks.len() <= MAX_SINKS, "at most {MAX_SINKS} sinks");
    let max_backlog = file.max_backlog.unwrap_or(DEFAULT_MAX_BACKLOG);
    ensure!(
        BACKLOG_RANGE.contains(&max_backlog),
        "max_backlog must be between {} and {}",
        BACKLOG_RANGE.start(),
        BACKLOG_RANGE.end()
    );
    let batch_bytes = file.batch_bytes.unwrap_or(DEFAULT_BATCH_BYTES);
    ensure!(
        BATCH_RANGE.contains(&batch_bytes),
        "batch_bytes must be between {} and {}",
        BATCH_RANGE.start(),
        BATCH_RANGE.end()
    );
    let mut sinks: Vec<Sink> = Vec::new();
    for sink in file.sinks {
        let id = sink.id.clone();
        let checked = check_sink(sink, home).with_context(|| format!("sink `{id}`"))?;
        ensure!(
            sinks.iter().all(|s| s.id != checked.id),
            "two sinks are named `{id}`"
        );
        sinks.push(checked);
    }
    Ok(Config {
        machine: file.machine,
        start: file.start,
        max_backlog,
        batch_bytes,
        sinks,
    })
}

fn check_sink(sink: SinkFile, home: &Home) -> Result<Sink> {
    ensure!(
        valid_name(&sink.id, 32, false),
        "an id is 1 to 32 lowercase letters, digits and `-`"
    );
    let (kind, url) = match (sink.otlp, sink.webhook) {
        (Some(url), None) => (Kind::Otlp, url),
        (None, Some(url)) => (Kind::Webhook, url),
        _ => bail!("give exactly one of `otlp:` and `webhook:`"),
    };
    let endpoint = openmoat_proxy::Endpoint::parse(&url)?;
    if kind == Kind::Webhook {
        ensure!(
            endpoint.scheme == openmoat_proxy::Scheme::Https,
            "a webhook is sent over https only"
        );
        ensure!(
            sink.secret.is_some(),
            "a webhook needs `secret:`, the key its bodies are signed with"
        );
    } else {
        ensure!(
            sink.secret.is_none(),
            "`secret:` signs webhook bodies; an OTLP sink authenticates with `headers:`"
        );
    }
    let secret = sink
        .secret
        .map(|source| check_source(source, home))
        .transpose()
        .context("secret")?;
    let mut headers = Vec::new();
    for header in sink.headers {
        let value =
            check_source(header.value, home).with_context(|| format!("header {}", header.name))?;
        ensure!(
            !header.name.to_ascii_lowercase().starts_with("x-openmoat-"),
            "header {}: the X-OpenMoat- headers are OpenMoat's own",
            header.name
        );
        headers.push(Header {
            name: header.name,
            value,
            prefix: header.prefix,
        });
    }
    let ca_file = sink
        .ca_file
        .map(|path| inside_state_dir(&path, home))
        .transpose()
        .context("ca_file")?;
    Ok(Sink {
        id: sink.id,
        kind,
        url,
        endpoint,
        secret,
        headers,
        ca_file,
    })
}

/// `source` with a file's path made absolute. A file source must lie inside
/// the state directory's `delivery/`, which `kernel-self` keeps the agent from
/// reading as well as writing (most of the state directory stays readable);
/// the environment is refused (module docs).
fn check_source(source: SecretSource, home: &Home) -> Result<SecretSource> {
    match source {
        SecretSource::File(path) => {
            let resolved = inside_state_dir(&path, home)?;
            let dir = home.delivery_dir();
            ensure!(
                resolved.starts_with(&dir) && resolved != dir,
                "`{path}` must be inside {}, which the agent cannot read",
                dir.display()
            );
            Ok(SecretSource::File(resolved.to_string_lossy().into_owned()))
        }
        SecretSource::Env(_) => bail!(
            "`env:` is refused here: delivery runs in the environment of the agent's hook; use a \
             file inside {} or the keychain",
            home.delivery_dir().display()
        ),
        keychain @ SecretSource::Keychain { .. } => Ok(keychain),
        SecretSource::Command(_) => bail!(
            "`command:` is refused here: only `openmoat proxy` runs a program for a value; use a \
             file inside {} or the keychain",
            home.delivery_dir().display()
        ),
    }
}

/// `path` (absolute, or `~/…` under the user's home) when it names a file
/// inside the state directory with no `..` in it.
pub fn inside_state_dir(path: &str, home: &Home) -> Result<PathBuf> {
    let resolved = match path.strip_prefix("~/") {
        Some(rest) => crate::home::user_home()?.join(rest),
        None => PathBuf::from(path),
    };
    ensure!(
        resolved.is_absolute(),
        "`{path}` must be absolute or start with ~/"
    );
    ensure!(
        !resolved.components().any(|c| c == Component::ParentDir),
        "`{path}` must not contain .."
    );
    ensure!(
        resolved.starts_with(home.root()) && resolved != home.root(),
        "`{path}` must be inside {}, where the agent cannot read or change it",
        home.root().display()
    );
    Ok(resolved)
}

fn valid_name(name: &str, max: usize, upper: bool) -> bool {
    !name.is_empty()
        && name.len() <= max
        && name.chars().all(|c| {
            c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || c == '-'
                || (upper && (c.is_ascii_uppercase() || c == '.' || c == '_'))
        })
}

#[cfg(test)]
mod tests;
