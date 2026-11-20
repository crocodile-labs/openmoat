//! Sandboxed start (ADR-106): a person's choice, made at `openmoat init`, that
//! typing a hook-only agent's command starts it in `openmoat run`'s sandbox.
//!
//! The mechanism is a shim per agent in OpenMoat's own directory
//! (`~/.moat/bin/<program>`), a two-line `sh` script that runs `openmoat run`
//! by its absolute path around the real program, found once at `init` on the
//! search path with that directory left out, so a shim never starts itself.
//! Nothing changes how the agent starts until the directory comes first on
//! `PATH`: `init` shows the line and the file it would go in, and writes it
//! only on a yes, after a backup (`rc.rs`). The shims are pinned by the lock
//! and kept from the agent by `kernel-self` (`~/.moat/**`); the record of them
//! is `start.json`. `openmoat uninstall` removes the shims and the line.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_hosts::Host;
use serde::{Deserialize, Serialize};

use crate::environment::find_in;
use crate::home::Home;
use crate::integrity::sha256_hex;
use crate::protection::os_sandbox::{self, RunCommand, RunHere};

pub mod rc;
mod shim;
#[cfg(test)]
mod tests;

pub use shim::Shim;

/// The record's file in the state directory.
pub const RECORD_FILE: &str = "start.json";

/// The record's format version.
const VERSION: u32 = 1;

/// Where the record of the shims is.
pub fn record_path(home: &Home) -> PathBuf {
    home.root().join(RECORD_FILE)
}

/// The directory of the shims, which the person's `PATH` puts first.
pub fn shim_dir(home: &Home) -> PathBuf {
    home.root().join("bin")
}

/// The shims `openmoat init` wrote, and the start-up file it added the
/// directory to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: u32,
    #[serde(default)]
    pub shims: Vec<Recorded>,
    /// The shell start-up file `init` added the `PATH` line to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rc: Option<rc::Written>,
}

/// One shim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recorded {
    /// The agent's id.
    pub host: String,
    /// The command a person types, the shim's file name.
    pub name: String,
    /// The real program the shim starts.
    pub program: PathBuf,
    /// The SHA-256 of the shim as written.
    pub sha256: String,
}

impl Default for Record {
    fn default() -> Self {
        Self {
            version: VERSION,
            shims: Vec::new(),
            rc: None,
        }
    }
}

impl Record {
    /// The record, from the bytes the lock check kept when it did; no shim
    /// when there is no file.
    pub fn load(home: &Home) -> Result<Self> {
        home.load_state(&record_path(home), Self::parse, |path| {
            if !path.exists() {
                return Ok(Self::default());
            }
            let text =
                fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            Self::parse(&text, path)
        })
    }

    fn parse(text: &str, path: &Path) -> Result<Self> {
        let record: Self =
            serde_json::from_str(text).with_context(|| format!("parsing {}", path.display()))?;
        if record.version != VERSION {
            bail!(
                "{} has version {}; this OpenMoat reads version {VERSION}",
                path.display(),
                record.version
            );
        }
        Ok(record)
    }

    pub fn save(&self, home: &Home) -> Result<()> {
        let record = Self {
            version: VERSION,
            ..self.clone()
        };
        let text = serde_json::to_string_pretty(&record)? + "\n";
        crate::home::write_private(&record_path(home), text.as_bytes())
    }

    /// The shim of `host`, if one was written.
    pub fn of(&self, host: Host) -> Option<&Recorded> {
        self.shims.iter().find(|s| s.host == host.id())
    }
}

/// Every shim file the record lists, for the lock to pin.
pub fn pinned_files(home: &Home) -> Vec<PathBuf> {
    let dir = shim_dir(home);
    Record::load(home)
        .map(|r| r.shims.iter().map(|s| dir.join(&s.name)).collect())
        .unwrap_or_default()
}

/// The shims `init` can offer for `hosts`: each agent with an `openmoat run`
/// command here (a hook-only agent whose facts are known), whose program the
/// search path `path` finds outside the shim directory, and that has no shim
/// yet. `binary` is the `openmoat` the shims run.
pub fn offers(
    home: &Home,
    binary: &Path,
    hosts: &[Host],
    path: &[PathBuf],
    here: &RunHere,
) -> Result<Vec<Shim>> {
    let record = Record::load(home)?;
    let dir = shim_dir(home);
    let outside: Vec<PathBuf> = path
        .iter()
        .filter(|d| !same_dir(d, &dir))
        .cloned()
        .collect();
    let mut offers = Vec::new();
    for host in hosts.iter().copied().filter(|h| record.of(*h).is_none()) {
        let Ok(run) = os_sandbox::command(home, host, here)? else {
            continue;
        };
        let Some(program) = find_in(&outside, &[], run.program) else {
            continue;
        };
        offers.push(Shim::new(host, binary, &program, &run));
    }
    Ok(offers)
}

/// Write each of `shims` into the shim directory and record it.
pub fn write(home: &Home, shims: &[Shim]) -> Result<Vec<PathBuf>> {
    let mut record = Record::load(home)?;
    let dir = shim_dir(home);
    crate::home::create_private_dir(&dir)?;
    let mut written = Vec::new();
    for shim in shims {
        let path = dir.join(shim.name);
        shim::write_executable(&path, shim.text.as_bytes())?;
        record.shims.retain(|s| s.host != shim.host.id());
        record.shims.push(Recorded {
            host: shim.host.id().to_owned(),
            name: shim.name.to_owned(),
            program: shim.program.clone(),
            sha256: sha256_hex(shim.text.as_bytes()),
        });
        written.push(path);
    }
    record.save(home)?;
    Ok(written)
}

/// Whether typing an agent's command starts it sandboxed, as `openmoat
/// status` and `openmoat doctor` say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Starts {
    /// The search path finds the shim first.
    Sandboxed,
    /// The shim is there, but the search path finds this program first.
    Outside(PathBuf),
    /// The shim's file is not what `init` wrote, or is gone.
    ShimChanged,
    /// The program the shim starts is gone (moved or uninstalled).
    ProgramGone(PathBuf),
}

/// How each recorded shim's agent starts with the search path `path`.
pub fn report(home: &Home, path: &[PathBuf]) -> Result<Vec<(Recorded, Starts)>> {
    let dir = shim_dir(home);
    let mut rows = Vec::new();
    for shim in Record::load(home)?.shims {
        let file = dir.join(&shim.name);
        let intact = fs::read(&file).is_ok_and(|b| sha256_hex(&b) == shim.sha256);
        let starts = if !intact {
            Starts::ShimChanged
        } else if !shim.program.is_file() {
            Starts::ProgramGone(shim.program.clone())
        } else {
            match find_in(path, &[], &shim.name) {
                Some(found) if same_file(&found, &file) => Starts::Sandboxed,
                Some(found) => Starts::Outside(found),
                None => Starts::Outside(PathBuf::new()),
            }
        };
        rows.push((shim, starts));
    }
    Ok(rows)
}

impl Starts {
    /// The row's text for an agent whose command is `name`.
    pub fn line(&self, name: &str, dir: &Path) -> String {
        match self {
            Self::Sandboxed => format!("typing `{name}` starts it in `openmoat run`"),
            Self::Outside(found) if found.as_os_str().is_empty() => format!(
                "a shim is in {}, but this shell's PATH does not include it: open a new shell, \
                 or put {} first on PATH",
                dir.display(),
                dir.display()
            ),
            Self::Outside(found) => format!(
                "a shim is in {}, but this shell's PATH finds {} first, which starts outside the \
                 sandbox: open a new shell, or put {} first on PATH",
                dir.display(),
                found.display(),
                dir.display()
            ),
            Self::ShimChanged => format!(
                "the shim {}/{name} is not the one `openmoat init` wrote: run `openmoat init` \
                 to write it again",
                dir.display()
            ),
            Self::ProgramGone(program) => format!(
                "the shim starts {}, which is gone: run `openmoat init` to find `{name}` again",
                program.display()
            ),
        }
    }

    /// Whether the row is a problem to show under "needs your attention".
    pub fn needs_attention(&self) -> bool {
        *self != Self::Sandboxed
    }
}

/// What `openmoat uninstall` did with one shim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removed {
    Deleted(PathBuf),
    /// Someone changed it since `init` wrote it: kept.
    Changed(PathBuf),
}

/// Remove the shims of `hosts`, and the `PATH` line once no shim is left.
/// The shims deleted, each shim's outcome, and the start-up file's.
pub fn remove(home: &Home, hosts: &[Host]) -> Result<(Vec<Removed>, Option<rc::Undone>)> {
    let mut record = Record::load(home)?;
    if record.shims.is_empty() && record.rc.is_none() {
        return Ok((Vec::new(), None));
    }
    let dir = shim_dir(home);
    let mut done = Vec::new();
    let (going, staying): (Vec<Recorded>, Vec<Recorded>) = record
        .shims
        .into_iter()
        .partition(|s| hosts.iter().any(|h| h.id() == s.host));
    for shim in going {
        let file = dir.join(&shim.name);
        match fs::read(&file) {
            Ok(bytes) if sha256_hex(&bytes) == shim.sha256 => {
                fs::remove_file(&file).with_context(|| format!("deleting {}", file.display()))?;
                done.push(Removed::Deleted(file));
            }
            Ok(_) => done.push(Removed::Changed(file)),
            Err(_) => {}
        }
    }
    record.shims = staying;
    let rc = if record.shims.is_empty() {
        let undone = record.rc.as_ref().map(rc::remove).transpose()?;
        record.rc = None;
        undone
    } else {
        None
    };
    record.save(home)?;
    Ok((done, rc))
}

/// Whether `a` and `b` name one directory.
fn same_dir(a: &Path, b: &Path) -> bool {
    a == b || matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
}

/// Whether `a` and `b` name one file.
fn same_file(a: &Path, b: &Path) -> bool {
    same_dir(a, b)
}

/// The words after `openmoat` of `run`'s start (`run`, `run --isolate`).
fn run_words(run: &RunCommand) -> Vec<&'static str> {
    run.start.split(' ').skip(1).collect()
}
