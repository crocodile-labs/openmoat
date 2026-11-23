//! Which release of a package a stdio MCP server runs, read offline when its
//! definition is accepted, so a new release holds the server as a changed
//! definition does (ADR-114).
//!
//! A definition such as `npx -y postmark-mcp` does not change when the package
//! does: `postmark-mcp` 1.0.16 added a hidden BCC to every mail it sent, and a
//! definition pinned by its text alone accepted it unseen
//! (<https://security.snyk.io/vuln/SNYK-JS-POSTMARKMCP-13052679>). So the pin
//! of a definition also records the release its command resolves to, from
//! what the command line says and what the local package manager left on
//! disk, without any network request:
//!
//! - npm (`npx`, `npm exec`): the version and `integrity` (the registry's
//!   SHA-512) of the package in the `package-lock.json` of npx's own install
//!   of it under the npm cache (`$npm_config_cache`, else `~/.npm`, `_npx/*/`),
//!   the newest one when several; else the exact version the command line
//!   names (`pkg@1.0.15`);
//! - `PyPI` (`uvx`, `uv tool run`, `pipx run`): the version of its install by
//!   `uv tool install` (`$UV_TOOL_DIR`, else `~/.local/share/uv/tools/<name>`),
//!   with the SHA-256 of its `RECORD` file (which lists every installed file
//!   with its hash); else the exact version the command line names
//!   (`pkg==1.0.15`, `pkg@1.0.15`);
//! - container images (`docker run`, `podman run`): the digest the command
//!   line names (`image@sha256:…`); a tag alone is recorded as the tag, which
//!   a registry may move.
//!
//! What cannot be read is not recorded and holds nothing: the server starts,
//! its package manager installs what it installs, and the next check reads it.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::integrity::sha256_hex;

/// The release a server's command runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// `npm`, `pypi` or `oci`.
    pub ecosystem: String,
    pub package: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The package's hash as its package manager recorded it, or the
    /// image's digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
}

impl Provenance {
    /// One line for a person.
    pub fn shown(&self) -> String {
        let mut text = format!("{} package {}", self.ecosystem, self.package);
        if let Some(version) = &self.version {
            let _ = write!(text, " {version}");
        }
        if let Some(integrity) = &self.integrity {
            let short: String = integrity.chars().take(24).collect();
            let _ = write!(text, " ({short}…)");
        }
        crate::render::clean(&text).into_owned()
    }
}

/// Where the package managers keep what they installed.
#[derive(Debug, Clone)]
pub struct Roots {
    /// npm's cache (`_npx` is inside it).
    pub npm_cache: Option<PathBuf>,
    /// `uv tool install`'s directory.
    pub uv_tools: Option<PathBuf>,
}

impl Roots {
    /// The directories of this user's package managers, from the environment
    /// and the home directory.
    pub fn of_user() -> Self {
        let home = crate::home::user_home().ok();
        let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
        let npm_cache = var("npm_config_cache")
            .or_else(|| var("NPM_CONFIG_CACHE"))
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|h| h.join(".npm")));
        let uv_tools = var("UV_TOOL_DIR")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|h| h.join(".local/share/uv/tools")));
        Self {
            npm_cache,
            uv_tools,
        }
    }
}

/// Read the release each server `scan` found runs into `scan.provenance`:
/// the command after `openmoat mcp proxy … --` for a wrapped one.
pub fn fill(scan: &mut super::servers::Scan, roots: &Roots) {
    for server in scan.servers.iter().filter(|s| !s.runs_in_host) {
        let found = super::wrap::server_command(&server.entry, server.form)
            .and_then(|argv| of_command(&argv, roots));
        if let Some(found) = found {
            scan.provenance.insert(server.id.clone(), found);
        }
    }
}

/// The release `argv`, a server's command line, runs; `None` when it runs
/// no package OpenMoat knows how to read.
pub fn of_command(argv: &[String], roots: &Roots) -> Option<Provenance> {
    let (program, words) = argv.split_first()?;
    let stem = Path::new(program)
        .file_stem()?
        .to_str()?
        .to_ascii_lowercase();
    match stem.as_str() {
        "npx" => npm(words, roots),
        "npm" if matches!(words.first().map(String::as_str), Some("exec" | "x")) => {
            npm(&words[1..], roots)
        }
        "uvx" => pypi(words, roots),
        "uv" if words.get(..2).is_some_and(|a| a == ["tool", "run"]) => pypi(&words[2..], roots),
        "pipx" if words.first().is_some_and(|a| a == "run") => pypi(&words[1..], roots),
        "docker" | "podman" if words.first().is_some_and(|a| a == "run") => oci(&words[1..]),
        _ => None,
    }
}

/// The package spec of an `npx` command line: `--package`/`-p`'s, else the
/// first argument that is not a flag.
fn npm(args: &[String], roots: &Roots) -> Option<Provenance> {
    let mut spec = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--" {
            break;
        }
        if arg == "-p" || arg == "--package" {
            spec = rest.next().cloned();
            break;
        }
        if let Some(value) = arg.strip_prefix("--package=") {
            spec = Some(value.to_owned());
            break;
        }
        if !arg.starts_with('-') {
            spec = Some(arg.clone());
            break;
        }
    }
    let spec = spec?;
    // `@scope/name@version` or `name@version`.
    let (name, version) = match spec.strip_prefix('@') {
        Some(scoped) => match scoped.split_once('@') {
            Some((n, v)) => (format!("@{n}"), Some(v.to_owned())),
            None => (spec.clone(), None),
        },
        None => match spec.split_once('@') {
            Some((n, v)) => (n.to_owned(), Some(v.to_owned())),
            None => (spec.clone(), None),
        },
    };
    if name.is_empty() || (name.contains(['/', '\\', ':']) && !name.starts_with('@')) {
        // A path or URL, not a registry package.
        return None;
    }
    let installed = roots
        .npm_cache
        .as_deref()
        .and_then(|cache| npx_installed(cache, &name));
    let (version, integrity) = match installed {
        Some((v, i)) => (Some(v), i),
        None => (version.filter(|v| is_exact(v)), None),
    };
    Some(Provenance {
        ecosystem: "npm".to_owned(),
        package: name,
        version,
        integrity,
    })
}

/// The version and integrity of `name` in npx's newest install of it.
fn npx_installed(cache: &Path, name: &str) -> Option<(String, Option<String>)> {
    let entries = fs::read_dir(cache.join("_npx")).ok()?;
    let mut best: Option<(SystemTime, String, Option<String>)> = None;
    for entry in entries.flatten() {
        let lock = entry.path().join("package-lock.json");
        let Ok(text) = fs::read_to_string(&lock) else {
            continue;
        };
        let Ok(doc) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Some(package) = doc
            .get("packages")
            .and_then(|p| p.get(format!("node_modules/{name}")))
        else {
            continue;
        };
        let Some(version) = package.get("version").and_then(Value::as_str) else {
            continue;
        };
        let integrity = package
            .get("integrity")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let modified = fs::metadata(&lock)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        if best.as_ref().is_none_or(|(t, ..)| modified > *t) {
            best = Some((modified, version.to_owned(), integrity));
        }
    }
    best.map(|(_, v, i)| (v, i))
}

/// The package of a `uvx` command line: `--from`'s, else the first argument
/// that is not a flag.
fn pypi(args: &[String], roots: &Roots) -> Option<Provenance> {
    let mut spec = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--from" {
            spec = rest.next().cloned();
            break;
        }
        if let Some(value) = arg.strip_prefix("--from=") {
            spec = Some(value.to_owned());
            break;
        }
        if !arg.starts_with('-') {
            spec = Some(arg.clone());
            break;
        }
    }
    let spec = spec?;
    let (name, version) = if let Some((n, v)) = spec.split_once("==") {
        (n, Some(v))
    } else if let Some((n, v)) = spec.split_once('@') {
        (n, Some(v))
    } else {
        (spec.as_str(), None)
    };
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty() || name.contains(['/', '\\', ':']) {
        return None;
    }
    let installed = roots
        .uv_tools
        .as_deref()
        .and_then(|tools| uv_installed(tools, &name));
    let (version, integrity) = match installed {
        Some((v, i)) => (Some(v), i),
        None => (
            version
                .map(str::trim)
                .filter(|v| is_exact(v))
                .map(str::to_owned),
            None,
        ),
    };
    Some(Provenance {
        ecosystem: "pypi".to_owned(),
        package: name,
        version,
        integrity,
    })
}

/// The version of a `uv tool install` of `name`, with the SHA-256 of its
/// `RECORD`.
fn uv_installed(tools: &Path, name: &str) -> Option<(String, Option<String>)> {
    let lib = tools
        .join(name)
        .join(if cfg!(windows) { "Lib" } else { "lib" });
    // A distribution's name as its `.dist-info` folder spells it.
    let folded = name.replace(['-', '.'], "_");
    let mut site = Vec::new();
    for python in fs::read_dir(&lib).ok()?.flatten() {
        site.push(python.path().join("site-packages"));
    }
    // Windows keeps `Lib/site-packages` without a Python directory.
    site.push(lib.join("site-packages"));
    for dir in site {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let file = entry.file_name();
            let Some(stem) = file.to_str().and_then(|f| f.strip_suffix(".dist-info")) else {
                continue;
            };
            let Some((dist, version)) = stem.split_once('-') else {
                continue;
            };
            if dist.to_ascii_lowercase().replace(['-', '.'], "_") != folded {
                continue;
            }
            let record = fs::read(entry.path().join("RECORD"))
                .ok()
                .map(|bytes| format!("sha256-record:{}", sha256_hex(&bytes)));
            return Some((version.to_owned(), record));
        }
    }
    None
}

/// The image of a `docker run` command line: the first argument after the
/// flags (and their values).
fn oci(args: &[String]) -> Option<Provenance> {
    /// `docker run` flags that take a value as the next argument.
    const WITH_VALUE: &[&str] = &[
        "-e",
        "--env",
        "-v",
        "--volume",
        "--name",
        "-p",
        "--publish",
        "--network",
        "--net",
        "-w",
        "--workdir",
        "-u",
        "--user",
        "--entrypoint",
        "--platform",
        "-l",
        "--label",
        "--env-file",
        "-h",
        "--hostname",
        "--add-host",
        "--cpus",
        "-m",
        "--memory",
        "--mount",
        "--pull",
        "--restart",
        "--runtime",
        "--cap-add",
        "--cap-drop",
        "--device",
        "--tmpfs",
        "--security-opt",
        "--ulimit",
        "--log-driver",
        "--log-opt",
        "--dns",
        "-a",
        "--attach",
        "--cidfile",
        "--gpus",
        "--ipc",
        "--pid",
        "--shm-size",
        "--stop-signal",
    ];
    let mut rest = args.iter();
    let image = loop {
        let arg = rest.next()?;
        if WITH_VALUE.contains(&arg.as_str()) {
            rest.next();
            continue;
        }
        if !arg.starts_with('-') {
            break arg;
        }
    };
    let (name, digest) = match image.split_once('@') {
        Some((n, d)) => (n, Some(d.to_owned())),
        None => (image.as_str(), None),
    };
    // A tag follows the last `:` after the last `/` (a registry may have a port).
    let last_slash = name.rfind('/').map_or(0, |i| i + 1);
    let (repository, tag) = match name[last_slash..].rfind(':') {
        Some(i) => (&name[..last_slash + i], Some(&name[last_slash + i + 1..])),
        None => (name, None),
    };
    Some(Provenance {
        ecosystem: "oci".to_owned(),
        package: repository.to_owned(),
        version: Some(tag.unwrap_or("latest").to_owned()),
        integrity: digest,
    })
}

/// Whether `version` names one release, not a range or a tag like `latest`.
fn is_exact(version: &str) -> bool {
    version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_'))
}

#[cfg(test)]
mod tests;
