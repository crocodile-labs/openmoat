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
//! the one `moat status` and `moat doctor` use. Any other write (a shell
//! redirect, an edit or patch that does not replay) keeps the policy's
//! verdict: its outcome is not known before it runs (`docs/LIMITS.md`).

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
    let found = switched_off(&outcomes(request, ctx), hook_file, Path::new(&ctx.home));
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
