//! What `openmoat why` says about one decision, worked out from the audit
//! event and what was read for it ([`Inputs`]), with no file access here.

use openmoat_audit::{Event, KnownSecrets};
use openmoat_core::{Policy, Verdict};
use serde::Serialize;

use crate::notice;
use crate::report::Paths;

/// A policy file as read, for finding where a rule is.
pub struct File {
    /// The path as shown (`~/.moat/policy.yaml`).
    pub shown: String,
    pub text: String,
}

/// What was read for the explanation.
pub struct Inputs<'a> {
    /// The person's policy as `guard` merges it, for titles; `None` when it
    /// does not load.
    pub policy: Option<&'a Policy>,
    /// The policy file, the `openmoat allow` rules, and the repository's policy.
    pub files: Files,
    /// How the policy decides each part of the call now, or why that could
    /// not be worked out.
    pub now: Result<Vec<Part>, String>,
    /// Whether this is the newest review, which `openmoat allow --last` approves.
    pub newest_review: bool,
    pub paths: &'a Paths,
}

/// The files a rule can come from.
#[derive(Default)]
pub struct Files {
    pub policy: Option<File>,
    pub approved: Option<File>,
    pub repository: Option<File>,
}

/// One decision, explained.
#[derive(Debug, Serialize)]
pub struct Explanation {
    pub event: String,
    pub time: String,
    pub host: String,
    pub session: String,
    pub tool: String,
    pub call: String,
    pub verdict: Verdict,
    /// The line the agent's host received, as earlier releases sent it whole.
    pub line: String,
    /// The rules that decided it, in the order they were tried.
    pub rules: Vec<Rule>,
    /// How the policy decides each part of the call now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_now: Option<Vec<Part>>,
    /// Why [`Self::decided_now`] is missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_now_error: Option<String>,
    /// What else about the session or the call shaped the decision.
    pub context: Vec<String>,
    /// How a person changes the outcome.
    pub change: Vec<String>,
    /// The deciding rule's page on openmoat.dev.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
}

/// One deciding rule.
#[derive(Debug, Serialize)]
pub struct Rule {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `your policy`, `your approvals`, `repository policy`, `policy pack <name>`,
    /// `your policy's defaults` or `built-in check`.
    pub origin: String,
    /// `<file>:<line>` where the rule is, when it is in a file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// How the policy decides one part of the call (an atomic action).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Part {
    /// The part, as the engine describes it (`read ~/.ssh/id_ed25519`).
    pub what: String,
    pub verdict: Verdict,
    pub rules: Vec<String>,
}

/// The explanation of `event`.
pub fn explain(event: &Event, inputs: &Inputs<'_>) -> Explanation {
    let known = KnownSecrets::default();
    let show = |text: &str| notice::shown(inputs.paths, &known, text);
    // One reason per rule when they line up; else every reason on the first.
    let aligned = event.rules.len() == event.reasons.len();
    let rules: Vec<Rule> = event
        .rules
        .iter()
        .enumerate()
        .map(|(n, id)| {
            let group = inputs.policy.and_then(|p| p.own_group(id));
            let reason = if aligned {
                event.reasons.get(n).cloned()
            } else {
                (n == 0).then(|| event.reasons.join("; "))
            };
            let (origin, source) = origin(id, &inputs.files);
            Rule {
                id: show(id),
                title: group.and_then(|g| g.title.clone()),
                why: group.and_then(|g| g.why.clone()),
                reason: reason.filter(|r| !r.is_empty()).map(|r| show(&r)),
                origin,
                source,
            }
        })
        .collect();
    let rules_text = event.rules.join(", ");
    let line = format!(
        "moat: {} [{rules_text}] — {}",
        event.verdict.as_str(),
        event.reasons.join("; ")
    );
    let (decided_now, decided_now_error) = match &inputs.now {
        Ok(parts) => {
            let shown = parts.iter().map(|p| Part {
                what: show(&p.what),
                ..p.clone()
            });
            (Some(shown.collect()), None)
        }
        Err(why) => (None, Some(why.clone())),
    };
    Explanation {
        event: event.id.to_string(),
        time: crate::time::timestamp(event.ts_ms),
        host: show(&event.host),
        session: show(&event.session_id),
        tool: show(&event.tool),
        call: show(&notice::call_text(&event.tool, event.action.as_ref())),
        verdict: event.verdict,
        line: show(&line),
        context: event
            .rules
            .iter()
            .filter_map(|r| context(r))
            .map(str::to_owned)
            .collect(),
        change: change(event, &rules, inputs.newest_review),
        page: event
            .rules
            .first()
            .and_then(|r| openmoat_hosts::rule_page(r)),
        decided_now,
        decided_now_error,
        rules,
    }
}

/// Where rule `id` comes from, and the file and line it is at.
fn origin(id: &str, files: &Files) -> (String, Option<String>) {
    let at = |file: &Option<File>, find: &str| {
        let file = file.as_ref()?;
        line_of(&file.text, find).map(|n| format!("{}:{n}", file.shown))
    };
    if let Some(local) = id.strip_prefix(openmoat_core::REPO_RULE_PREFIX) {
        return ("repository policy".to_owned(), at(&files.repository, local));
    }
    if let Some(rest) = id.strip_prefix("pack:") {
        let name = rest.split(':').next().unwrap_or(rest);
        return (format!("policy pack `{name}`"), None);
    }
    if let Some(source) = at(&files.policy, id) {
        return ("your policy".to_owned(), Some(source));
    }
    if let Some(source) = at(&files.approved, id) {
        return ("your approvals (`openmoat allow`)".to_owned(), Some(source));
    }
    if id == "default" || id.starts_with("default.") {
        let source = files.policy.as_ref().and_then(|f| {
            let n = f.text.lines().position(|l| l.starts_with("defaults:"))?;
            Some(format!("{}:{}", f.shown, n + 1))
        });
        return (
            "your policy's defaults (no rule matched)".to_owned(),
            source,
        );
    }
    ("built-in check".to_owned(), None)
}

/// The 1-based line of `- id: <id>` in a policy's text.
pub fn line_of(text: &str, id: &str) -> Option<usize> {
    text.lines()
        .position(|line| {
            let Some(rest) = line.trim_start().strip_prefix("- id:") else {
                return false;
            };
            let value = rest.split(" #").next().unwrap_or(rest).trim();
            value.trim_matches(|c| c == '"' || c == '\'') == id
        })
        .map(|n| n + 1)
}

/// What a built-in rule says about the session or the call.
fn context(rule: &str) -> Option<&'static str> {
    Some(match rule {
        "session-taint" => {
            "this session read untrusted content or a secret earlier, so calls that write \
             or send need review (session taint)"
        }
        "session-code" => {
            "the command runs code this session wrote, with no OS sandbox below the hook"
        }
        "mcp-cross-server" => "the call carries text another MCP server returned (ADR-058)",
        "mcp-server-changed" | "mcp-tool-held" => {
            "an MCP server's definition or tools changed and are not accepted yet: \
             `openmoat mcp accept`"
        }
        "kernel-integrity" => {
            "OpenMoat's own files changed since they were pinned: `openmoat doctor` shows what"
        }
        "unchecked" => "the hook payload shows only part of the call",
        "unparseable" => "OpenMoat could not read all of the command",
        "approved-session" => "you approved this call for the session with `openmoat allow`",
        "push-secret" | "push-runs-later" | "push-unchecked" => {
            "a push is checked for what the commits it publishes hold"
        }
        _ => return None,
    })
}

/// How a person changes the outcome. Never a way for the agent to reach the
/// same end with another call: these are the person's own commands.
fn change(event: &Event, rules: &[Rule], newest_review: bool) -> Vec<String> {
    match event.verdict {
        Verdict::Review if newest_review => vec![
            "approve it for this session: `openmoat allow --last`".to_owned(),
            "approve it for good: `openmoat allow --last --always`".to_owned(),
        ],
        Verdict::Review => vec![
            "run `openmoat` to see what waits for your approval; `openmoat allow --last` \
             approves the newest review"
                .to_owned(),
        ],
        Verdict::Deny => rules.iter().map(deny_change).collect(),
        _ => vec![
            "nothing was blocked; to hold such calls for review, add a `review:` rule with \
             `openmoat edit`"
                .to_owned(),
        ],
    }
}

fn deny_change(rule: &Rule) -> String {
    let id = &rule.id;
    match (rule.origin.as_str(), &rule.source) {
        ("your policy", Some(at)) => format!(
            "`{id}` is a deny rule of your policy ({at}); only you can change it, with \
             `openmoat edit`. An allow rule never overrides a deny"
        ),
        ("repository policy", at) => format!(
            "`{id}` comes from the repository's policy{}; its owners can change it",
            at.as_ref().map(|a| format!(" ({a})")).unwrap_or_default()
        ),
        _ if id == "default.net" => {
            "your policy denies hosts it does not list: `openmoat allow --site <host>` lists one"
                .to_owned()
        }
        _ if id.starts_with("kernel-") => {
            "run `openmoat doctor` in your terminal to see what OpenMoat found".to_owned()
        }
        _ => format!("`{id}`: change your policy with `openmoat edit`"),
    }
}
