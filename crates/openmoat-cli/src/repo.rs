//! The repository policy of a session's project (ADR-022): found, read and
//! hashed here, merged by `openmoat_core::RepoPolicy`.
//!
//! The file is attacker-controlled input. One that exists but cannot be read
//! or parsed is an error, so `guard` denies with `kernel-error` rather than
//! dropping the team's deny rules. Its allow rules apply only while the file
//! is the one a person accepted with `moat trust`.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_core::{EvalContext, Policy, RepoPolicy};

use crate::context;
use crate::home::{self, Home};
use crate::integrity::{Lock, sha256_hex};
use crate::trust::Trust;

/// A repository policy as read from disk.
pub struct Found {
    pub path: PathBuf,
    /// The project root with its symlinks resolved, which trust is bound to.
    pub root: String,
    /// SHA-256 of the bytes that were parsed.
    pub digest: String,
    /// The text that was parsed, which a signature must cover.
    pub text: String,
    pub policy: RepoPolicy,
}

/// The detached signature beside a repository policy (ADR-031).
fn signature_path(found: &Found) -> std::path::PathBuf {
    found.path.with_file_name("policy.yaml.sig")
}

/// The principal whose trusted key signed this repository policy, when the
/// user policy asks for signed repository policies (`require_signed_repo_policy`)
/// and there is a signature; `None` otherwise. A signature that does not verify
/// is `None` too, and with the setting on the file is then not trusted.
pub fn signed_by(home: &Home, user: &Policy, found: &Found) -> Result<Option<String>> {
    let signature = signature_path(found);
    if !user.require_signed_repo_policy || fs::symlink_metadata(&signature).is_err() {
        return Ok(None);
    }
    let (Some(program), Some(signers)) = (
        crate::signing::locate(home),
        crate::signing::trusted_signers(home),
    ) else {
        return Ok(None);
    };
    crate::signing::verify(&program, &signers, found.text.as_bytes(), &signature)
        .with_context(|| format!("checking the signature {}", signature.display()))
}

/// The project root as `trust.json` records it: symlinks resolved, so every
/// spelling of one checkout shares a record and another checkout does not.
pub fn root_key(root: &Path) -> Result<String> {
    let real = fs::canonicalize(root).with_context(|| format!("resolving {}", root.display()))?;
    Ok(context::path_string(&real))
}

/// The project's repository policy, if it has one.
pub fn find(home: &Home, root: &Path) -> Result<Option<Found>> {
    let path = root.join(home::DIR_NAME).join("policy.yaml");
    let meta = match fs::metadata(&path) {
        // `.moat` a file (`moat run --isolate` puts an empty placeholder there
        // for the session) holds no policy, as when it is missing.
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return Ok(None);
        }
        meta => meta.with_context(|| format!("reading repository policy {}", path.display()))?,
    };
    // `$MOAT_HOME` set to the project's `.moat`: that is OpenMoat's own state.
    let canonical = |p: &Path| fs::canonicalize(p).ok();
    if path.parent().and_then(canonical) == canonical(home.root()) {
        return Ok(None);
    }
    // A FIFO would block the hook until the host times it out, and a host may
    // proceed then; a directory or a device is no policy either.
    if !meta.is_file() {
        bail!("repository policy {} is not a regular file", path.display());
    }
    let text = context::read_policy(&path)?;
    let policy = RepoPolicy::parse(&text)
        .with_context(|| format!("invalid repository policy {}", path.display()))?;
    Ok(Some(Found {
        root: root_key(root)?,
        digest: sha256_hex(text.as_bytes()),
        text,
        path,
        policy,
    }))
}

/// The person's trust records. Only a file the lock pins counts: `moat trust`
/// re-pins after writing it, so an unpinned one was written by someone else.
pub fn trust(home: &Home) -> Result<Trust> {
    let path = home.trust_path();
    if !Lock::load(&home.lock_path()).is_ok_and(|lock| lock.pins(&path)) {
        return Ok(Trust::default());
    }
    Trust::load(&path)
}

/// Whether the repository policy's allow rules apply. With
/// `require_signed_repo_policy` only a signature from a trusted key counts, so
/// a file `moat trust` accepted but no trusted key signed only tightens; without
/// it only `moat trust` counts.
pub fn is_trusted(home: &Home, user: &Policy, found: &Found) -> Result<bool> {
    if user.require_signed_repo_policy {
        return Ok(signed_by(home, user, found)?.is_some());
    }
    Ok(trust(home)?.trusts(&found.root, &found.digest))
}

/// The user policy with the recorded `moat` binary's paths in `kernel-self`
/// and the project's repository policy merged in, as `guard` decides with it.
pub fn effective_policy(home: &Home, ctx: &EvalContext) -> Result<Policy> {
    effective_policy_with(home, None, ctx)
}

/// [`effective_policy`] with the user policy parsed from `checked`, the bytes
/// the lock check verified, when it kept them (`Home::load_checked_policy`).
pub fn effective_policy_with(
    home: &Home,
    checked: Option<Vec<u8>>,
    ctx: &EvalContext,
) -> Result<Policy> {
    let mut user = home.load_checked_policy(checked)?;
    crate::install::self_paths::protect_recorded(home, &mut user)?;
    let Some(root) = &ctx.project else {
        return Ok(user);
    };
    let Some(found) = find(home, Path::new(root))? else {
        return Ok(user);
    };
    let trusted = is_trusted(home, &user, &found)?;
    found
        .policy
        .merge(&user, trusted)
        .with_context(|| format!("merging repository policy {}", found.path.display()))
}

/// One line for `status` and `doctor` about the repository policy of the
/// project around the current directory: its digest and which form applies.
pub fn summary(home: &Home) -> Result<Option<String>> {
    let Some(root) = context::eval_context(home, None, None)?.project else {
        return Ok(None);
    };
    let Some(found) = find(home, Path::new(&root))? else {
        return Ok(None);
    };
    let p = &found.policy;
    let rules = format!(
        "{} deny, {} ask, {} allow",
        p.deny.len(),
        p.ask.len(),
        p.allow.len()
    );
    let (signer, signed_only) = match home.load_policy() {
        Ok(user) => (
            signed_by(home, &user, &found)?,
            user.require_signed_repo_policy,
        ),
        Err(_) => (None, false),
    };
    let form = match (trust(home)?.repos.get(&found.root), signer) {
        (_, Some(signer)) => format!("trusted: signed by {signer} ({rules})"),
        _ if signed_only && p.allow.is_empty() => format!("tightening only ({rules})"),
        _ if signed_only => {
            format!("not signed by a trusted key: tightening only, allow rules ignored ({rules})")
        }
        (Some(digest), _) if *digest == found.digest => format!("trusted ({rules})"),
        (Some(_), None) => {
            format!(
                "changed since `openmoat trust`: tightening only, allow rules ignored ({rules})"
            )
        }
        (None, None) if p.allow.is_empty() => format!("tightening only ({rules})"),
        (None, None) => format!("not trusted: tightening only, allow rules ignored ({rules})"),
    };
    Ok(Some(format!(
        "{}  sha256:{}  {form}",
        found.path.display(),
        found.digest
    )))
}

#[cfg(test)]
mod tests;
