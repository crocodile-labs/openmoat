//! What the guard learns about a call outside its payload before deciding it:
//! the session's directory for a host that sends the tool's own
//! ([`SessionDir::HookProcess`]), the directories a host's settings add to a
//! workspace-wide search ([`openmoat_hosts::HostSpec::workspace_dirs`]), and
//! whether OpenMoat's sandbox confines a call the host says it sandboxes.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use openmoat_hosts::{HookRequest, Host, SessionDir};

use crate::context::{absolute, path_string};
use crate::home::{Home, user_home};
use crate::install::{HostConfig, read_or_empty};
use crate::project;

/// `request` with every fact the guard adds.
pub(super) fn placed(home: &Home, host: Host, request: HookRequest) -> Result<HookRequest> {
    let mut request = in_session(host, request, &std::env::current_dir)?;
    if request.searches_workspace() {
        request = in_workspace(home, host, request)?;
    }
    request.sandboxed = request.sandboxed && crate::protection::os_sandboxed_by_lock(home, host);
    Ok(request)
}

/// For a host whose hooks run in the session's directory and whose payload
/// names the tool's (Codex), `request` decided from `session` (the hook's own
/// working directory) when the tool runs outside the session's project: a
/// model-chosen `workdir` never decides which directory is the project. A
/// session outside any project (started in the home directory) keeps a tool
/// directory inside a git work tree, the project a person checked out.
fn in_session(
    host: Host,
    request: HookRequest,
    session: &dyn Fn() -> std::io::Result<PathBuf>,
) -> Result<HookRequest> {
    if host.spec().session_dir != SessionDir::HookProcess {
        return Ok(request);
    }
    let Some(tool) = request.cwd.as_deref().filter(|c| !c.is_empty()) else {
        return Ok(request);
    };
    let session = session().context("determining the hook's working directory")?;
    let home = absolute(&user_home()?)?;
    let tool = absolute(Path::new(tool))?;
    let keep = match project::root_of(&session, &home) {
        Some(root) => project::contains(&root, &tool),
        None => git_root(&tool, &home).is_some(),
    };
    Ok(if keep {
        request
    } else {
        request.from_session_dir(&path_string(&session))
    })
}

/// The nearest directory at or above `start` holding `.git`, when it may be
/// a project root ([`project::trusted`]).
fn git_root(start: &Path, home: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .filter(|root| project::trusted(root, home))
        .map(Path::to_path_buf)
}

/// `request`'s workspace-wide searches reading the directories the host's
/// user and project settings add. A settings file that cannot be read leaves
/// the search needing review: what it adds is unknown.
fn in_workspace(home: &Home, host: Host, request: HookRequest) -> Result<HookRequest> {
    let Some(read) = host.spec().workspace_dirs else {
        return Ok(request);
    };
    let mut files = vec![HostConfig::for_host(home, host)?.settings_path];
    if let (Some(cwd), Some(settings)) = (request.cwd.as_deref(), &host.spec().project_settings) {
        let cwd = absolute(Path::new(cwd))?;
        let user_home = absolute(&user_home()?)?;
        let mut dirs = vec![cwd.clone()];
        dirs.extend(project::root_of(&cwd, &user_home).filter(|root| *root != cwd));
        for dir in dirs {
            let file = dir.join(settings.dir).join(settings.shared);
            if !files.contains(&file) {
                files.push(file);
            }
        }
    }
    let mut extra = Vec::new();
    for file in files {
        match read_or_empty(&file) {
            Ok(settings) => extra.extend(read(&settings)),
            Err(_) => return Ok(request),
        }
    }
    Ok(request.with_workspace_dirs(&extra))
}

#[cfg(test)]
mod tests;
