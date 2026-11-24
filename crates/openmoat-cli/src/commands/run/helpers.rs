//! The local helpers of a run's `helper:` secrets (ADR-118): git's
//! credential helper and the AWS tools' `credential_process`, both
//! `openmoat credential`, which asks this run's proxy for the secret's
//! current minted value.
//!
//! - git: two entries per secret in `GIT_CONFIG_*` (protected configuration,
//!   read after every file): `credential.https://<host>.helper` set empty,
//!   which drops every helper the person's files name for that host, then
//!   set to `openmoat credential git <id>`. git asks it for that host only.
//! - AWS: a config file of the run's own (`AWS_CONFIG_FILE`) with one
//!   profile per secret, `openmoat-<id>`, whose `credential_process` is
//!   `openmoat credential aws <id>`; `AWS_PROFILE` names it when there is one
//!   such secret. `AWS_SHARED_CREDENTIALS_FILE` points at an empty file of
//!   the run's, and the key variables are removed: both come before
//!   `credential_process` in the AWS tools' order and would be used instead.
//!
//! Nothing here holds a value: the file and the variables name only the
//! helper. The directory is removed when the run ends.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result};
use openmoat_core::Policy;
use openmoat_core::mint::Helper;

use crate::home::write_private;
use crate::sandbox::git_env::{self, Lookup};

/// The AWS variables that would be used before a profile's `credential_process`.
const AWS_REMOVED: [&str; 4] = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_DEFAULT_PROFILE",
];

/// The run's helper settings; their directory is removed when dropped.
#[derive(Debug, Default)]
pub struct Helpers {
    dir: Option<PathBuf>,
    vars: Vec<(String, String)>,
    removed: Vec<&'static str>,
}

/// `text` quoted for a POSIX shell, which runs a git `!` helper.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The `GIT_CONFIG_*` entries for the policy's `helper: git` secrets, run as `moat`.
pub fn git_entries(policy: &Policy, moat: &str) -> Vec<(String, String)> {
    policy
        .secrets
        .iter()
        .filter(|s| matches!(s.helper, Some(Helper::Git { .. })))
        .flat_map(|s| {
            let key = format!("credential.https://{}.helper", s.host);
            let helper = format!("!{} credential git {}", quoted(moat), quoted(&s.id));
            [(key.clone(), String::new()), (key, helper)]
        })
        .collect()
}

/// The AWS config file for the policy's `helper: aws` secrets, run as
/// `moat`, and the profile to use when there is one; `None` without any.
pub fn aws_config(policy: &Policy, moat: &str) -> Option<(String, Option<String>)> {
    let ids: Vec<&str> = policy
        .secrets
        .iter()
        .filter(|s| s.helper == Some(Helper::Aws))
        .map(|s| s.id.as_str())
        .collect();
    let mut text = String::from("# Written by `openmoat run` for this run only (ADR-118).\n");
    for id in &ids {
        // The AWS tools split `credential_process` on spaces, honouring double quotes.
        let _ = write!(
            text,
            "[profile openmoat-{id}]\ncredential_process = \"{moat}\" credential aws {id}\n"
        );
    }
    match ids.as_slice() {
        [] => None,
        [one] => Some((text, Some(format!("openmoat-{one}")))),
        _ => Some((text, None)),
    }
}

impl Helpers {
    /// The settings for `policy`, written in a new directory in `temp`; `git`
    /// reads the `GIT_CONFIG_*` variables the agent gets so far. Nothing for
    /// a policy without `helper:` secrets.
    pub fn prepare(policy: &Policy, temp: &Path, git: Lookup) -> Result<Self> {
        let has_helper = policy.secrets.iter().any(|s| s.helper.is_some());
        if !has_helper {
            return Ok(Self::default());
        }
        let moat = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .context("locating the openmoat binary for the credential helpers")?;
        let moat = crate::context::path_string(&moat);
        let mut helpers = Self {
            dir: None,
            vars: git_env::append(git, git_entries(policy, &moat))?,
            removed: Vec::new(),
        };
        if let Some((config, profile)) = aws_config(policy, &moat) {
            let dir = temp.join(format!("moat-run-{}-helpers", std::process::id()));
            let config_file = dir.join("aws-config");
            let credentials_file = dir.join("aws-credentials");
            helpers.dir = Some(dir);
            write_private(&config_file, config.as_bytes())?;
            write_private(&credentials_file, b"")?;
            let path = |p: &Path| crate::context::path_string(p);
            helpers
                .vars
                .push(("AWS_CONFIG_FILE".into(), path(&config_file)));
            helpers.vars.push((
                "AWS_SHARED_CREDENTIALS_FILE".into(),
                path(&credentials_file),
            ));
            match profile {
                Some(profile) => helpers.vars.push(("AWS_PROFILE".into(), profile)),
                None => helpers.removed.push("AWS_PROFILE"),
            }
            helpers.removed.extend(AWS_REMOVED);
        }
        Ok(helpers)
    }

    /// The directory of the run's helper files, which a sandbox that hides
    /// the temp directory (`openmoat run --isolate`) binds in read-only.
    pub fn dir(&self) -> Option<String> {
        self.dir.as_deref().map(crate::context::path_string)
    }

    /// Set the variables on the agent's command.
    pub fn apply(&self, command: &mut Command) {
        for name in &self.removed {
            command.env_remove(name);
        }
        command.envs(self.vars.iter().map(|(k, v)| (k, v)));
    }
}

impl Drop for Helpers {
    fn drop(&mut self) {
        if let Some(dir) = &self.dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

#[cfg(test)]
mod tests;
