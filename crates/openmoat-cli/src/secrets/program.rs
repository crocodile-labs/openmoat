//! Whether the agent could change a `command` source's program (ADR-087).
//!
//! The program runs as the person, outside every sandbox, and its answer goes
//! into requests: a program the agent can replace is the agent's code. So it is
//! run only when the path the policy names, the file it resolves to and every
//! folder above that file (up to the person's home) are each
//!
//! - kept from the agent by the person's own policy (never a repository's,
//!   which the agent can write): a deny `fs.write` rule covers them,
//!   a folder together with everything in it (`openmoat_core::lint::write_denied`), or
//! - kept from every user but an administrator by the system: on Unix owned
//!   by root and writable by no group or other user.
//!
//! A script (a file starting with `#!`) names its interpreter, which must pass
//! the same check and must not be a script itself; `/usr/bin/env` is refused
//! there, since it looks the interpreter up in a search path. Neither path may
//! lie in a folder every user can write (`/tmp` and the like). Files the
//! program loads or reads once it runs are not checked.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_core::{Policy, REPO_RULE_PREFIX, SecretCommand};

/// How much of a file is read for a `#!` line.
const SHEBANG_MAX: u64 = 512;

/// A program the agent cannot change, and its interpreter when it is a script.
pub struct Checked {
    /// The resolved program file.
    pub path: PathBuf,
    /// The resolved interpreter its `#!` line names.
    pub interpreter: Option<PathBuf>,
}

/// What says the agent cannot change a file.
struct Rules<'a> {
    policy: &'a Policy,
    /// The person's home in slash form, without a trailing slash.
    home: &'a str,
    /// Folders the agent's sandboxes let it write: a deny rule inside them is
    /// not proof, since Landlock cannot hold a deny within a folder it grants.
    writable: &'a [String],
}

/// The resolved program file of `written` (absolute, home already expanded),
/// once it, and the interpreter it names if it is a script, are programs the
/// agent cannot change. `home` is the person's home in slash form; `writable`
/// the folders the agent's sandboxes let it write.
pub fn check(written: &str, policy: &Policy, home: &str, writable: &[String]) -> Result<Checked> {
    // The person's own rules only: a repository's are the agent's to write.
    let own = Policy {
        deny: policy
            .deny
            .iter()
            .filter(|g| !g.id.starts_with(REPO_RULE_PREFIX))
            .cloned()
            .collect(),
        ..policy.clone()
    };
    let rules = Rules {
        policy: &own,
        home: home.trim_end_matches('/'),
        writable,
    };
    let path = check_file(written, &rules)?;
    let Some(named) = interpreter_of(&path)? else {
        return Ok(Checked {
            path,
            interpreter: None,
        });
    };
    let interpreter = check_file(&named, &rules)
        .with_context(|| format!("checking {named}, the interpreter of {written}"))?;
    ensure!(
        interpreter_of(&interpreter)?.is_none(),
        "source command {written} is run by {named}, which is a script itself: name a program \
         that is not a script on its first line"
    );
    Ok(Checked {
        path,
        interpreter: Some(interpreter),
    })
}

/// The resolved file of `written`, once it is a file the agent cannot change.
fn check_file(written: &str, rules: &Rules<'_>) -> Result<PathBuf> {
    let home = rules.home;
    let real = std::fs::canonicalize(written)
        .with_context(|| format!("source command {written} cannot be found"))?;
    let meta = std::fs::metadata(&real).with_context(|| format!("reading {}", real.display()))?;
    ensure!(meta.is_file(), "source command {written} is not a file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        ensure!(
            meta.permissions().mode() & 0o111 != 0,
            "source command {written} is not executable"
        );
    }
    let shown = slashed(&real);
    for path in [written.replace('\\', "/"), shown.clone()] {
        if let Some(dir) = SecretCommand::shared_temp_dir(&path) {
            bail!("source command {path} is under {dir}, where any user can put a file");
        }
    }
    let as_written = denied(rules, written, false) || admin_only(Path::new(written));
    let open = open_folder(&real, rules);
    if as_written && open.is_none() {
        return Ok(real);
    }
    let open = open.map_or_else(|| written.replace('\\', "/"), |dir| slashed(&dir));
    if let Some(root) = granted(rules, &open) {
        bail!(
            "source command {written} could be changed by the agent: {open} is in {root}, which \
             the agent's sandbox lets it write, and a deny rule there is not enforced by every \
             sandbox; use a program outside it that only an administrator can change"
        );
    }
    let rule = if open == shown || open == written.replace('\\', "/") {
        policy_form(&open, home)
    } else {
        format!("{}/**", policy_form(&open, home))
    };
    bail!(
        "source command {written} could be changed by the agent: add a deny rule with \
         `fs.write: [\"{rule}\"]` to your policy, covering the file, the folder it is installed \
         in and every folder above it below your home, or use a program only an administrator \
         can change"
    )
}

/// The highest folder above `real` (or `real` itself) that neither the policy
/// nor the system keeps from the agent, up to and without the person's home
/// and a Windows drive's root; none when all are kept.
fn open_folder(real: &Path, rules: &Rules<'_>) -> Option<PathBuf> {
    let mut open = None;
    for (i, p) in real.ancestors().enumerate() {
        let text = slashed(p);
        if text == rules.home || text.is_empty() || (p.parent().is_none() && !cfg!(unix)) {
            break;
        }
        if !(admin_one(p) || denied(rules, &text, i > 0)) {
            open = Some(p.to_path_buf());
        }
    }
    open
}

/// Whether a deny `fs.write` rule covers `path` and, for a folder, anything
/// put in it, outside every folder a sandbox lets the agent write. A rule may
/// name a file under the home as `~/…` or by its full path.
fn denied(rules: &Rules<'_>, path: &str, folder: bool) -> bool {
    let path = path.replace('\\', "/");
    let covers = |p: &str| {
        [policy_form(p, rules.home), p.to_owned()]
            .iter()
            .any(|form| openmoat_core::lint::write_denied(rules.policy, form))
    };
    granted(rules, &path).is_none()
        && covers(&path)
        && (!folder || covers(&format!("{path}/.openmoat-new-file")))
}

/// The folder a sandbox lets the agent write that holds `path`, if any.
fn granted<'r>(rules: &Rules<'r>, path: &str) -> Option<&'r str> {
    rules
        .writable
        .iter()
        .map(String::as_str)
        .find(|root| path == *root || path.strip_prefix(*root).is_some_and(|r| r.starts_with('/')))
}

/// The interpreter a `#!` line at the start of `path` names; none when the
/// file is not a script. Refused when it is not an absolute path or is `env`,
/// which would look the real interpreter up in a search path.
fn interpreter_of(path: &Path) -> Result<Option<String>> {
    let mut head = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(SHEBANG_MAX).read_to_end(&mut head))
        .with_context(|| format!("reading {}", path.display()))?;
    let Some(line) = head.strip_prefix(b"#!") else {
        return Ok(None);
    };
    let line = line.split(|b| *b == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let named = line
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let shown = path.display();
    ensure!(
        named.starts_with('/'),
        "{shown} is a script whose first line does not name its interpreter by its full path"
    );
    ensure!(
        Path::new(&named).file_name().is_none_or(|n| n != "env"),
        "{shown} is a script started through {named}, which looks its interpreter up in a search \
         path: name the interpreter's full path on its first line, or use a program that is not \
         a script"
    );
    Ok(Some(named))
}

/// SHA-256 of the program file.
pub fn digest(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(crate::integrity::sha256_hex(&bytes))
}

/// `path` as policy rules name it: under the home as `~/…`.
fn policy_form(path: &str, home: &str) -> String {
    let path = path.replace('\\', "/");
    let home = home.trim_end_matches('/');
    match path.strip_prefix(home) {
        Some(rest) if rest.starts_with('/') => format!("~{rest}"),
        _ => path,
    }
}

fn slashed(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    // `canonicalize` on Windows gives a `\\?\` path.
    text.strip_prefix("//?/")
        .map_or(text.clone(), str::to_owned)
}

/// Whether only an administrator can change `path`: it (a link is not
/// followed) and every folder above it belong to root and no group or other
/// user may write them.
fn admin_only(path: &Path) -> bool {
    path.ancestors()
        .all(|p| p.as_os_str().is_empty() || admin_one(p))
}

/// Whether only an administrator can change `path` itself (a link is not
/// followed): it belongs to root and no group or other user may write it.
#[cfg(unix)]
fn admin_one(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::symlink_metadata(path)
        .is_ok_and(|m| m.uid() == 0 && (m.file_type().is_symlink() || m.mode() & 0o022 == 0))
}

/// No such check is made here: the policy must keep the program from the agent.
#[cfg(not(unix))]
fn admin_one(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests;
