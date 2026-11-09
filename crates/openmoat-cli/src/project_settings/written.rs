//! A write that would leave a host's project settings file turning that
//! host's hook off: denied in the guard, before the file changes.
//!
//! The policy decides a write by its path only, so a project's
//! `.codex/config.toml`, `.pi/settings.json` or `opencode.json` is a `review`
//! (`runs-later`): the person sees the change, and most changes there (a model,
//! an MCP server, a formatter) are theirs to make. Content that turns the
//! host's hook off is never one of those: `[features] hooks = false`, a pi
//! `extensions` entry that excludes OpenMoat's extension, an OpenCode
//! `-openmoat` plugin entry. A host that answers a `review` without a person
//! (OpenCode 2 `--auto`) would otherwise start its next session in that
//! project unprotected.
//!
//! The content a call leaves is known when the tool sends the whole file
//! (`Write`, pi and OpenCode `write`), when its replacements apply to the
//! file as it is (`Edit`, `MultiEdit`, pi and OpenCode `edit`, as ADR-048
//! replays them), and when its `apply_patch` envelope replays on the files as
//! they are (Codex, OpenCode). That content is read as the host reads the file
//! and handed to the host's own reader (`SettingsReader::project_switched_off`),
//! the one `moat status` and `moat doctor` use. An edit or patch that does not
//! replay keeps the policy's verdict: it fails, or its outcome is not known
//! before it runs (`docs/LIMITS.md`).
//!
//! A shell command that creates or replaces such a file (a redirect, `tee`,
//! `cp` or `mv` onto it, `sed -i`) cannot be replayed at all, so it is denied
//! outright (ADR-072), for the hosts OpenMoat is set up for and only where the
//! host would load the file: in the working directory or the project root
//! ([`super::candidates`]). A same-named file elsewhere (a template, a test
//! fixture) and a read, a removal or a move away keep their verdict.

use std::path::{Path, PathBuf};

use openmoat_core::{Action, Decision, EvalContext, Verdict};
use openmoat_hosts::{HookRequest, Host, ProjectSettingsSpec, SettingsFile};

use crate::home::Home;
use crate::install::HostConfig;

/// One file the call writes and the whole content it leaves there.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    /// The path, absolute and slash-separated.
    path: String,
    content: String,
}

/// `decision` with a deny ([`super::RULE`]) in its place when `request` leaves
/// a host's project settings file turning that host's hook off; unchanged
/// otherwise, and when it already denies. Only tightens.
#[must_use]
pub fn checked(
    home: &Home,
    request: &HookRequest,
    ctx: &EvalContext,
    decision: Decision,
) -> Decision {
    let hook_file = |host: Host| {
        HostConfig::for_host(home, host)
            .ok()
            .map(|c| c.settings_path)
    };
    tightened(request, ctx, &hook_file, decision)
}

/// [`checked`] with `hook_file` giving OpenMoat's hook file of a host.
fn tightened(
    request: &HookRequest,
    ctx: &EvalContext,
    hook_file: &dyn Fn(Host) -> Option<PathBuf>,
    decision: Decision,
) -> Decision {
    if decision.verdict == Verdict::Deny {
        return decision;
    }
    let mut found = switched_off(&outcomes(request, ctx), hook_file, Path::new(&ctx.home));
    found.extend(shell_replaced(request, ctx, hook_file));
    if found.is_empty() {
        return decision;
    }
    let mut deny = Decision::new(Verdict::Deny);
    deny.rules.push(super::RULE.to_owned());
    deny.reasons.extend(found);
    deny
}

/// The files `request` writes whose whole content afterwards is known, with
/// that content; a file whose outcome is not known is left out.
fn outcomes(request: &HookRequest, ctx: &EvalContext) -> Vec<Outcome> {
    let resolve = |raw: &str| {
        openmoat_core::resolve_path(raw, &ctx.home, ctx.project.as_deref(), Some(&ctx.cwd))
    };
    match &request.action {
        Some(Action::FsWrite { path }) => {
            // Only a host's settings file is read or copied; any other write
            // costs no more than this check.
            let Some(path) = resolve(path).filter(|p| !settings_files_at(p).is_empty()) else {
                return Vec::new();
            };
            let content = match (&request.content, request.edits.is_empty()) {
                (Some(content), _) => Some(content.clone()),
                (None, false) => text_of(&path)
                    .and_then(|text| crate::taint::provenance::apply_edits(&text, &request.edits)),
                (None, true) => None,
            };
            content
                .map(|content| vec![Outcome { path, content }])
                .unwrap_or_default()
        }
        Some(Action::Patch { .. }) => {
            let Some(patch) = &request.patch else {
                return Vec::new();
            };
            let read = |raw: &str| resolve(raw).and_then(|path| text_of(&path));
            openmoat_core::patch_replay(patch, &read)
                .into_iter()
                .filter_map(|r| {
                    Some(Outcome {
                        path: resolve(&r.path)?,
                        content: r.content?,
                    })
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

/// The file at `path` as text; `None` when it is missing, too large or not
/// UTF-8.
fn text_of(path: &str) -> Option<String> {
    let bytes = super::read_bytes(Path::new(path)).ok()??;
    String::from_utf8(bytes).ok()
}

/// One sentence per outcome that is a host's project settings file and turns
/// that host's hook off, `hook_file` giving OpenMoat's hook file of a host and
/// `user_home` the home `~` names.
fn switched_off(
    outcomes: &[Outcome],
    hook_file: &dyn Fn(Host) -> Option<PathBuf>,
    user_home: &Path,
) -> Vec<String> {
    let mut found = Vec::new();
    for outcome in outcomes {
        for (host, spec) in settings_files_at(&outcome.path) {
            let Some(hook) = hook_file(host) else {
                continue;
            };
            let path = Path::new(&outcome.path);
            let comments = spec.reader.reads_comments();
            // Text the host cannot parse loads nothing: it refuses the file.
            let Ok(root) = super::parse(path, outcome.content.as_bytes(), comments) else {
                continue;
            };
            let base = path.parent().unwrap_or(path);
            let file = SettingsFile::new(&root, base, &hook, Some(user_home));
            let off = spec.reader.project_switched_off(&file);
            if !off.is_empty() {
                found.push(format!(
                    "{} ({} project settings): this write {}; a {} session started here \
                     would run without OpenMoat. Leave that setting out",
                    path.display(),
                    host.display_name(),
                    off.join("; "),
                    host.display_name(),
                ));
            }
        }
    }
    found
}

/// One sentence per host whose project settings file `request`'s shell command
/// creates or replaces, where that host would load it and OpenMoat's hook file
/// of that host exists (a host OpenMoat is not set up for has no hook to lose).
fn shell_replaced(
    request: &HookRequest,
    ctx: &EvalContext,
    hook_file: &dyn Fn(Host) -> Option<PathBuf>,
) -> Vec<String> {
    let Some(Action::Shell { command }) = request.action.as_ref().map(Action::shown) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for path in openmoat_core::replaced_files(command, &ctx.home, &ctx.cwd) {
        for (host, spec) in settings_files_at(&path) {
            if hook_file(host).is_some_and(|hook| hook.exists()) && loaded_here(&path, ctx, spec) {
                found.push(format!(
                    "{path} ({} project settings): a shell command writes this file and OpenMoat \
                     cannot tell what it will hold; it can turn {}'s hook off. Change it with the \
                     agent's file tools, so the result can be checked, or by hand",
                    host.display_name(),
                    host.display_name(),
                ));
            }
        }
    }
    found
}

/// Whether `path` is a settings file `spec`'s host would load for a session in
/// the working directory or at its project root.
fn loaded_here(path: &str, ctx: &EvalContext, spec: &ProjectSettingsSpec) -> bool {
    let written = spellings(path);
    let (cwd, user_home) = (Path::new(&ctx.cwd), Path::new(&ctx.home));
    spec.files().into_iter().any(|name| {
        super::candidates(cwd, user_home, spec, name)
            .iter()
            .any(|candidate| {
                spellings(&candidate.to_string_lossy().replace('\\', "/"))
                    .iter()
                    .any(|spelling| written.contains(spelling))
            })
    })
}

/// The hosts whose project settings directory holds a file at `path`, as
/// written or with its folders' links resolved, compared without regard to
/// case (a write the file system folds onto the file reaches it).
fn settings_files_at(path: &str) -> Vec<(Host, &'static ProjectSettingsSpec)> {
    let spellings = spellings(path);
    Host::ALL
        .into_iter()
        .filter_map(|host| Some((host, host.spec().project_settings.as_ref()?)))
        .filter(|(_, spec)| {
            spec.files().into_iter().any(|name| {
                let rel = if spec.dir.is_empty() {
                    name.to_lowercase()
                } else {
                    format!("{}/{name}", spec.dir).to_lowercase()
                };
                spellings
                    .iter()
                    .any(|s| *s == rel || s.ends_with(&format!("/{rel}")))
            })
        })
        .collect()
}

/// `path` in lower case, and again with its links resolved: the file's own
/// when it exists (a link the write follows), else its folder's.
fn spellings(path: &str) -> Vec<String> {
    let mut out = vec![path.to_lowercase()];
    let path = Path::new(path);
    let real = std::fs::canonicalize(path).ok().or_else(|| {
        let name = path.file_name()?;
        Some(std::fs::canonicalize(path.parent()?).ok()?.join(name))
    });
    if let Some(real) = real {
        out.push(real.to_string_lossy().replace('\\', "/").to_lowercase());
    }
    out
}

#[cfg(test)]
mod tests;
