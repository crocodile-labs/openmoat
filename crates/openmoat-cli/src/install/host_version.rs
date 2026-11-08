//! What the version of a host on this shell's search path means for
//! OpenMoat: whether it takes OpenMoat's hook and through which of its hooks
//! ([`InstallSpec::versions`](openmoat_hosts::InstallSpec::versions)), and
//! which of the host's published security advisories it is affected by
//! ([`HostSpec::advisories`](openmoat_hosts::HostSpec::advisories)).
//!
//! OpenCode 1 and 2 install the same `opencode` program and read the same
//! configuration directory; OpenMoat's one plugin serves both plugin APIs, but
//! OpenCode before 1.3.4 does not load it. Only the version the program
//! reports tells them apart, so `moat init` asks it before writing the plugin,
//! and `moat status` and `moat doctor` before calling the agent protected and
//! to name the hook it runs through. The same version names the advisories
//! `moat status` and `moat doctor` warn about: a flaw in the agent's own
//! process runs where no hook sees it, so an upgrade is the only fix.
//!
//! OpenMoat Bar runs `moat status` and `moat doctor` every minute with a few
//! seconds to answer, so those two keep what each program reported in
//! `host-versions.json` in the state directory, by the program file's path,
//! size and modification time: a program is asked again only once it was
//! installed, upgraded or replaced.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::UNIX_EPOCH;

use openmoat_hosts::{Advisory, Host};
use serde::{Deserialize, Serialize};

use super::claude_version::{Version, parse, run_version};

/// The state directory whose `host-versions.json` this process reads and
/// writes, once [`prefetch_present`] named it; `init` asks without it.
static CACHE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// The most programs `host-versions.json` keeps.
const CACHE_LIMIT: usize = 32;

/// What `--version` reported for one program file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Seen {
    path: String,
    len: u64,
    modified_ns: u128,
    version: Version,
}

/// The versions asked so far in this process, by program.
type Asked = Mutex<Vec<(&'static str, Option<Version>)>>;

/// Why `host`'s version on the search path does not take OpenMoat's hook, as
/// one line; `None` when its spec names no such versions, when no program is
/// found or its version cannot be read (a host OpenMoat cannot ask is set up as
/// one that takes the hook), or when it is a supported one.
pub fn unsupported(host: Host) -> Option<String> {
    let gate = host.spec().install.as_ref()?.versions.as_ref()?;
    let version = version(gate.program)?;
    gate.hook_of(version).is_none().then(|| {
        format!(
            "`{} --version` reports {}: {}",
            gate.program,
            dotted(version),
            gate.older
        )
    })
}

/// Which of `host`'s hooks the version on the search path runs OpenMoat
/// through, as `status` and `doctor` name it after "installed": the program,
/// its version and the hook, such as OpenCode 2's `execute.before`; `None`
/// when its spec names one hook for every version, no program is found, its
/// version cannot be read, or it is one OpenMoat does not support
/// ([`unsupported`]).
pub fn hook_api(host: Host) -> Option<String> {
    let gate = host.spec().install.as_ref()?.versions.as_ref()?;
    let version = version(gate.program)?;
    let hook = gate.hook_of(version)?;
    Some(format!("{} {}: {hook}", gate.program, dotted(version)))
}

/// One line for each copy of `host`'s program affected by published security
/// advisories on this system: the one on the search path, then each an
/// editor extension bundles ([`super::bundled`]), named with its editor.
/// Empty when its spec names none, no copy is found or none applies.
pub fn advisories(host: Host) -> Vec<String> {
    let advisories = &host.spec().advisories;
    if advisories.program.is_empty() {
        return Vec::new();
    }
    let platform = crate::os_version::platform();
    let line = |name: &str, version: Version| {
        let affecting: Vec<&Advisory> = advisories.affecting(version, platform).collect();
        advisory_line(name, version, &affecting)
    };
    let on_path = version(advisories.program).and_then(|v| line(host.display_name(), v));
    let bundled = super::bundled::copies(host).into_iter().filter_map(|copy| {
        let name = format!("{} in the {} extension", host.display_name(), copy.editor);
        line(&name, copy.version)
    });
    on_path.into_iter().chain(bundled).collect()
}

/// One line for each copy of `host`'s program an editor extension bundles
/// ([`super::bundled`]), for `moat status` and `moat doctor`: the editor, its
/// version and where it is, and, when the host's entries ask for `onFailure`,
/// whether the copy is too old to read it; `false` with such a line.
pub fn bundled_lines(host: Host) -> Vec<(bool, String)> {
    let blocks = host
        .spec()
        .install
        .as_ref()
        .is_some_and(|i| i.hooks.iter().any(|h| h.block_on_failure));
    super::bundled::copies(host)
        .into_iter()
        .map(|copy| {
            let old = blocks && !super::claude_version::supports_on_failure(copy.version);
            let note = if old {
                format!(
                    "; older than {}, so a failed hook runs the call: update the extension, \
                     then run `openmoat init`",
                    super::claude_version::on_failure_since()
                )
            } else {
                String::new()
            };
            let line = format!(
                "{} {} bundled by the {} extension at {}{note}",
                host.display_name(),
                dotted(copy.version),
                copy.editor,
                copy.dir.display()
            );
            (!old, line)
        })
        .collect()
}

/// [`prefetch`] for every host whose directory is on this machine (in
/// `home`'s record or where its variable or default puts it).
pub fn prefetch_present(home: &crate::home::Home) {
    if home.exists() {
        let _ = CACHE_DIR.set(home.root().to_path_buf());
    }
    prefetch(
        Host::ALL.into_iter().filter(|host| {
            super::HostConfig::for_host(home, *host).is_ok_and(|c| c.host_present())
        }),
    );
}

/// Ask every host in `hosts` for its version at once, so the [`advisories`]
/// and [`unsupported`] calls that follow find them known: each program may
/// take up to the probe's limit to answer.
pub fn prefetch(hosts: impl IntoIterator<Item = Host>) {
    let mut programs: Vec<&'static str> = hosts
        .into_iter()
        .flat_map(|host| {
            let spec = host.spec();
            let gate = spec.install.as_ref().and_then(|i| i.versions.as_ref());
            [gate.map(|g| g.program), Some(spec.advisories.program)]
        })
        .flatten()
        .filter(|program| !program.is_empty())
        .collect();
    programs.sort_unstable();
    programs.dedup();
    std::thread::scope(|scope| {
        for program in programs {
            scope.spawn(move || version(program));
        }
    });
}

/// The warning for `name` at `version` affected by `affecting` (in its
/// spec's order): the first one by id and summary, how many more, the
/// version that fixes them all and where the first is published.
fn advisory_line(name: &str, version: Version, affecting: &[&Advisory]) -> Option<String> {
    let first = affecting.first()?;
    let fixed = affecting.iter().map(|a| a.fixed).max()?;
    let more = match affecting.len() - 1 {
        0 => String::new(),
        1 => " and 1 more".to_owned(),
        n => format!(" and {n} more"),
    };
    Some(format!(
        "{name} {} has a known security advisory, {} ({}){more}; upgrade to {} or later: {}",
        dotted(version),
        first.id,
        first.summary,
        dotted(fixed),
        first.source
    ))
}

/// `host`'s program on the search path and the version it reports
/// (`claude 2.1.290`), for `openmoat bench --report`; `None` when its spec
/// names no program, none is found or its version cannot be read.
pub fn reported(host: Host) -> Option<String> {
    let spec = host.spec();
    let gate = spec.install.as_ref().and_then(|i| i.versions.as_ref());
    [gate.map(|g| g.program), Some(spec.advisories.program)]
        .into_iter()
        .flatten()
        .filter(|program| !program.is_empty())
        .find_map(|program| version(program).map(|v| format!("{program} {}", dotted(v))))
}

fn dotted((major, minor, patch): Version) -> String {
    format!("{major}.{minor}.{patch}")
}

/// The version `program` reports, asked once per process.
fn version(program: &'static str) -> Option<Version> {
    static ASKED: OnceLock<Asked> = OnceLock::new();
    let asked = ASKED.get_or_init(|| Mutex::new(Vec::new()));
    if let Some((_, known)) = asked.lock().ok()?.iter().find(|(name, _)| *name == program) {
        return *known;
    }
    let found = ask(program);
    let mut asked = asked.lock().ok()?;
    if !asked.iter().any(|(name, _)| *name == program) {
        asked.push((program, found));
    }
    found
}

fn ask(program: &str) -> Option<Version> {
    // Debug builds read `MOAT_<PROGRAM>_VERSION` instead of running the
    // program, so end-to-end tests do not depend on the machine; empty means
    // not found. Release builds do not contain this check.
    #[cfg(debug_assertions)]
    if let Some(value) = std::env::var_os(format!("MOAT_{}_VERSION", program.to_uppercase())) {
        return parse_any(&value.to_string_lossy());
    }
    let found = crate::environment::find_on_path(program)?;
    let dir = CACHE_DIR.get();
    let file = dir.and_then(|_| identify(&found));
    if let (Some(dir), Some(seen)) = (dir, &file)
        && let Some(known) = cached(dir, seen)
    {
        return Some(known);
    }
    let version = parse_any(&run_version(Command::new(&found))?)?;
    if let (Some(dir), Some(mut seen)) = (dir, file) {
        seen.version = version;
        remember(dir, seen);
    }
    Some(version)
}

/// `path` as `host-versions.json` names it, with no version yet.
fn identify(path: &Path) -> Option<Seen> {
    let meta = std::fs::metadata(path).ok()?;
    let modified_ns = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some(Seen {
        path: path.to_string_lossy().into_owned(),
        len: meta.len(),
        modified_ns,
        version: (0, 0, 0),
    })
}

fn read_cache(dir: &Path) -> Vec<Seen> {
    std::fs::read(dir.join("host-versions.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// The version kept in `dir` for the same file at the same size and time.
fn cached(dir: &Path, file: &Seen) -> Option<Version> {
    read_cache(dir)
        .into_iter()
        .find(|s| s.path == file.path && s.len == file.len && s.modified_ns == file.modified_ns)
        .map(|s| s.version)
}

/// Keep `seen` in `dir` in place of what was kept for its path; a file that
/// cannot be written only means the program is asked again next time.
fn remember(dir: &Path, seen: Seen) {
    static WRITING: Mutex<()> = Mutex::new(());
    let Ok(_one_at_a_time) = WRITING.lock() else {
        return;
    };
    let mut all = read_cache(dir);
    all.retain(|s| s.path != seen.path);
    all.insert(0, seen);
    all.truncate(CACHE_LIMIT);
    if let Ok(bytes) = serde_json::to_vec_pretty(&all) {
        let _ = crate::home::write_private(&dir.join("host-versions.json"), &bytes);
    }
}

/// The first word of `text` that reads as a version: `1.19.4`, and also
/// `codex-cli 0.164.0` or `Hermes Agent v0.22.5`, whose first word is a name.
fn parse_any(text: &str) -> Option<Version> {
    text.split_whitespace().find_map(parse)
}

#[cfg(test)]
mod tests;
