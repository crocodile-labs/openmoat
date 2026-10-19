//! OpenSSH signatures over policy files (ADR-031): the system `ssh-keygen`,
//! `-Y verify` against `~/.moat/allowed_signers`, namespace [`NAMESPACE`].
//!
//! No signature code of OpenMoat's own: `ssh-keygen` is resolved through the
//! environment snapshot `moat init` recorded (`environment.rs`), like every
//! program the kernel relies on, so a planted one on the hook's `PATH` is never
//! run. Without it, the commands that need a signature refuse and nothing else
//! changes. The allowed-signers file is pinned by the lock, and only a file the
//! lock pins is trusted: `moat policy trust-key` re-pins after writing it.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, bail};

use crate::home::Home;
use crate::integrity::Lock;

/// The namespace every policy signature is made and checked in, so a key's
/// signature over something else (a git commit, a file) is no policy signature.
pub const NAMESPACE: &str = "openmoat-policy";

/// The program's name, as the environment snapshot records it.
const PROGRAM: &str = "ssh-keygen";

/// `ssh-keygen` as the environment snapshot resolves it: the pinned location,
/// else the first on the recorded search path. `None` without a snapshot.
pub fn locate(home: &Home) -> Option<PathBuf> {
    crate::environment::program(home, PROGRAM)
}

/// [`locate`], or an error saying signing needs OpenSSH's `ssh-keygen`.
pub fn require(home: &Home) -> Result<PathBuf> {
    locate(home).with_context(|| {
        format!(
            "signed policy needs OpenSSH's `{PROGRAM}`, and none was found on the search path \
             `moat init` recorded; install OpenSSH, then run `moat init` again"
        )
    })
}

/// The allowed-signers file, when the lock pins it: one written by anyone but
/// `moat policy trust-key` is not trusted.
pub fn trusted_signers(home: &Home) -> Option<PathBuf> {
    let path = home.signers_path();
    let lock = Lock::load(&home.lock_path()).ok()?;
    (path.is_file() && lock.pins(&path)).then_some(path)
}

/// The principals an allowed-signers file names, in order, each once.
#[must_use]
pub fn principals(signers: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in signers.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.split_whitespace().next()
            && !out.iter().any(|n| n == name)
        {
            out.push(name.to_owned());
        }
    }
    out
}

/// The allowed-signers line trusting `key` (the text of a `.pub` file) for
/// [`NAMESPACE`] only, under `principal`.
pub fn signer_line(principal: &str, key: &str) -> Result<String> {
    let valid = !principal.is_empty()
        && principal.len() <= 128
        && principal
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c));
    if !valid {
        bail!(
            "`{principal}` is not a signer name: use letters, digits and `@._+-` \
             (an email address works)"
        );
    }
    let line = key
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .context("the key file is empty")?;
    let mut words = line.split_whitespace();
    let (Some(kind), Some(blob)) = (words.next(), words.next()) else {
        bail!("not an OpenSSH public key: expected `<type> <base64> [comment]`");
    };
    let known = ["ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-"]
        .iter()
        .any(|p| kind.starts_with(p));
    let base64 = blob
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c));
    if !known || !base64 {
        bail!("not an OpenSSH public key: `{kind}` is not a key type ssh-keygen signs with");
    }
    Ok(format!(
        "{principal} namespaces=\"{NAMESPACE}\" {kind} {blob}"
    ))
}

/// The key's fingerprint as `ssh-keygen -l` prints it; an error when
/// `ssh-keygen` does not read the file as a public key.
pub fn fingerprint(program: &Path, key: &Path) -> Result<String> {
    let out = Command::new(program)
        .arg("-l")
        .arg("-f")
        .arg(key)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {}", program.display()))?;
    if !out.status.success() {
        bail!(
            "{} is not a public key ssh-keygen reads: {}",
            key.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The principal of `signers` whose key made `signature` over `data` in
/// [`NAMESPACE`], or `None` when no trusted key did. Each principal is tried
/// in turn: `ssh-keygen -Y verify` checks one at a time.
pub fn verify(
    program: &Path,
    signers: &Path,
    data: &[u8],
    signature: &Path,
) -> Result<Option<String>> {
    // A FIFO would hold the caller until the host gives up on the hook.
    if !signature.is_file() {
        bail!("signature {} is not a regular file", signature.display());
    }
    let text = std::fs::read_to_string(signers)
        .with_context(|| format!("reading {}", signers.display()))?;
    for principal in principals(&text) {
        if verify_as(program, signers, &principal, data, signature)? {
            return Ok(Some(principal));
        }
    }
    Ok(None)
}

fn verify_as(
    program: &Path,
    signers: &Path,
    principal: &str,
    data: &[u8],
    signature: &Path,
) -> Result<bool> {
    let mut child = Command::new(program)
        .args(["-Y", "verify", "-n", NAMESPACE, "-I", principal, "-f"])
        .arg(signers)
        .arg("-s")
        .arg(signature)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("running {}", program.display()))?;
    // ssh-keygen reads all of the data before it writes anything, so writing
    // first cannot block on a full output pipe.
    if let Some(mut stdin) = child.stdin.take() {
        // A write error is ssh-keygen having exited early: its status says why.
        let _ = stdin.write_all(data);
    }
    let status = child
        .wait()
        .with_context(|| format!("waiting for {}", program.display()))?;
    Ok(status.success())
}

#[cfg(test)]
mod tests;
