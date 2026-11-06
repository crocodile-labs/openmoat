//! The block message (ADR-059): what an agent and its person read when
//! OpenMoat denies a call or holds it for review, in every host's reason field.
//!
//! ```text
//! OpenMoat blocked: reading or changing your keys and credential files
//!   call   Read ~/.ssh/id_ed25519
//!   rule   moat: deny [secrets-paths] — secret material: read /Users/me/.ssh/id_ed25519
//!   why    a key or token that leaves this machine cannot be taken back
//!   next   if you need this, do it yourself in your own terminal
//!   more   openmoat why --last · https://openmoat.dev/r/secrets-paths
//! ```
//!
//! At most six lines of plain text: no colour, since the host renders it. The
//! `rule` line is the line earlier releases sent whole, so what looks for
//! `moat: <verdict> [<rule>]` still finds it. The text reaches the model too:
//! the one `next` step is for the person (do it yourself, or approve it), never
//! a way for the agent to reach the same end by another call.

use openmoat_core::{Decision, Notice, Verdict};

/// Where each rule's page is: the rule id follows.
pub const RULE_PAGE: &str = "https://openmoat.dev/r/";

/// The command that explains the newest deny or review.
const WHY_LAST: &str = "openmoat why --last";

/// What a person can do about a deny. Not "ask the agent to try another
/// way": the agent reads this too.
const DENY_NEXT: &str = "if you need this, do it yourself in your own terminal";

/// What a person does with a review the host puts to them.
const REVIEW_NEXT: &str = "approve it in this prompt only if you expected it";

/// The one line earlier releases sent: verdict, rule ids, then `reasons`.
pub(crate) fn line(decision: &Decision, reasons: &str) -> String {
    let verdict = decision.verdict.as_str();
    let rules = decision.rules.join(", ");
    match (rules.is_empty(), reasons.is_empty()) {
        (true, true) => format!("moat: {verdict}"),
        (false, true) => format!("moat: {verdict} [{rules}]"),
        (true, false) => format!("moat: {verdict} — {reasons}"),
        (false, false) => format!("moat: {verdict} [{rules}] — {reasons}"),
    }
}

/// The block message for a `deny` or `review` whose decision carries a
/// [`Notice`]; `None` for any other decision, which keeps [`line()`].
pub(crate) fn message(decision: &Decision) -> Option<String> {
    let notice = decision.notice.as_deref()?;
    let held = match decision.verdict {
        Verdict::Review => true,
        Verdict::Deny => notice.unasked.is_some(),
        _ => return None,
    };
    let heading = if held {
        "OpenMoat is holding this for you"
    } else {
        "OpenMoat blocked"
    };
    let reasons = notice
        .detail
        .clone()
        .unwrap_or_else(|| decision.reasons.join("; "));
    let mut lines = vec![format!("{heading}: {}", notice.title)];
    if let Some(call) = &notice.call {
        lines.push(row("call", call));
    }
    lines.push(row("rule", &line(decision, &reasons)));
    if let Some(why) = &notice.why {
        lines.push(row("why", why));
    }
    lines.push(row("next", &next(decision.verdict, notice)));
    lines.push(row("more", &more(decision, held)));
    Some(lines.join("\n"))
}

/// One labelled line, the label padded so the texts line up.
fn row(label: &str, text: &str) -> String {
    format!("  {label:<6} {text}")
}

/// The one thing the person can do.
fn next(verdict: Verdict, notice: &Notice) -> String {
    match (&notice.unasked, verdict) {
        (Some(why), _) => format!(
            "{why}, so approve it in your terminal: run `openmoat`, or `openmoat allow --last`, \
             then retry"
        ),
        (None, Verdict::Review) => REVIEW_NEXT.to_owned(),
        (None, _) => DENY_NEXT.to_owned(),
    }
}

/// `openmoat why --last`, and for a deny the deciding rule's page.
fn more(decision: &Decision, held: bool) -> String {
    let page = decision
        .rules
        .first()
        .filter(|_| !held)
        .and_then(|rule| rule_page(rule))
        .map(|page| format!(" · {page}"));
    format!("{WHY_LAST}{}", page.unwrap_or_default())
}

/// The page on openmoat.dev that explains `rule`, for an id the site can have
/// one for: lowercase letters, digits, `-` and `.`, as OpenMoat's own ids are.
/// A pack's or a repository's rule (`pack:…`, `repo:…`) has none.
#[must_use]
pub fn rule_page(rule: &str) -> Option<String> {
    let plain = !rule.is_empty()
        && rule
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'));
    plain.then(|| format!("{RULE_PAGE}{rule}"))
}

#[cfg(test)]
mod tests;
