//! OpenSSH signatures over policy files (ADR-031): the system `ssh-keygen`,
//! `-Y verify` against `~/.moat/allowed_signers`, in the namespace of what is
//! signed ([`Signed`]): [`NAMESPACE`] for a repository policy,
//! [`PACK_NAMESPACE`] for a policy pack. The two files have the same shape, so
//! without separate namespaces a pack's signature would verify as a signed
//! repository policy, and the reverse.
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

/// The namespace a repository policy's signature is made and checked in, so a
/// key's signature over something else (a git commit, a file, a pack) is no
/// repository policy signature (ADR-037).
pub const NAMESPACE: &str = "openmoat-repo-policy";

/// The namespace earlier releases signed repository policies and packs in
/// alike. Nothing verifies in it any more: a pack signed in it, copied into a
/// project as `.moat/policy.yaml`, would verify as a signed repository policy.
#[cfg(test)]
pub const EARLIER_NAMESPACE: &str = "openmoat-policy";

/// The namespace a policy pack's signature is made and checked in.
pub const PACK_NAMESPACE: &str = "openmoat-pack";

/// What a signature is over, which decides its namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signed {
    /// A project's `.moat/policy.yaml` (`require_signed_repo_policy`).
    RepoPolicy,
    /// A pack `moat policy install` installs.
    Pack,
}

impl Signed {
    /// The `ssh-keygen -n` namespace of this kind of signature.
    #[must_use]
    pub fn namespace(self) -> &'static str {
        match self {
            Self::RepoPolicy => NAMESPACE,
            Self::Pack => PACK_NAMESPACE,
        }
    }
}

/// The program's name, as the environment snapshot records it.
const PROGRAM: &str = "ssh-keygen";

/// Longest principal [`signer_line`] accepts.
const MAX_PRINCIPAL_LEN: usize = 128;

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
             `openmoat init` recorded; install OpenSSH, then run `openmoat init` again"
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
/// [`NAMESPACE`] and [`PACK_NAMESPACE`] only, under `principal`.
pub fn signer_line(principal: &str, key: &str) -> Result<String> {
    let valid = !principal.is_empty()
        && principal.len() <= MAX_PRINCIPAL_LEN
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
        "{principal} namespaces=\"{NAMESPACE},{PACK_NAMESPACE}\" {kind} {blob}"
    ))
}

/// Whether two allowed-signers lines trust the same key under the same
/// principal, whatever namespaces they allow: `moat policy trust-key` replaces
/// a line an earlier release wrote for other namespaces (`openmoat-policy`).
#[must_use]
pub fn same_signer(a: &str, b: &str) -> bool {
    signer_key(a).is_some_and(|k| signer_key(b) == Some(k))
}

/// The principal, key type and key of an allowed-signers line.
fn signer_key(line: &str) -> Option<(&str, &str, &str)> {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        &[principal, .., kind, key] => Some((principal, kind, key)),
        _ => None,
    }
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

/// The principal of `signers` whose key made `signature` over `data`, a file
/// of the kind `what`, in that kind's namespace, or `None` when no trusted key
/// did. Each principal is tried in turn: `ssh-keygen -Y verify` checks one at
/// a time.
pub fn verify(
    program: &Path,
    signers: &Path,
    data: &[u8],
    signature: &Path,
    what: Signed,
) -> Result<Option<String>> {
    // A FIFO would hold the caller until the host gives up on the hook.
    if !signature.is_file() {
        bail!("signature {} is not a regular file", signature.display());
    }
    let text = std::fs::read_to_string(signers)
        .with_context(|| format!("reading {}", signers.display()))?;
    for principal in principals(&text) {
        if verify_as(
            program,
            signers,
            (&principal, what.namespace()),
            data,
            signature,
        )? {
            return Ok(Some(principal));
        }
    }
    Ok(None)
}

/// [`verify`] for one `(principal, namespace)`.
fn verify_as(
    program: &Path,
    signers: &Path,
    (principal, namespace): (&str, &str),
    data: &[u8],
    signature: &Path,
) -> Result<bool> {
    let mut child = Command::new(program)
        .args(["-Y", "verify", "-n", namespace, "-I", principal, "-f"])
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
