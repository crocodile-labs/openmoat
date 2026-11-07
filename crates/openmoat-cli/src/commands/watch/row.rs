//! One audit event as `openmoat watch` shows it: a line with the time, the
//! agent, a mark, the tool, what the call names and, at the right, the verdict
//! and rule; a deny or review gets a second line saying what was stopped.

use openmoat_audit::{Event, KnownSecrets};
use openmoat_core::{Policy, Verdict};

use crate::notice;
use crate::report::{Mark, Paths, Style};
use crate::time::clock;

/// Below this width the verdict column is left out; the mark still shows it.
pub const NARROW: usize = 80;

/// The width the agent column is padded to.
const HOST_WIDTH: usize = 12;

/// The width the tool column is padded to.
const TOOL_WIDTH: usize = 6;

/// Where the second line of a deny or review starts: under the tool.
const INDENT: usize = 25;

/// How rows are laid out.
pub struct View<'a> {
    pub style: Style,
    /// Columns to fit in; `None` for output that is not a terminal, which gets
    /// whole lines with the verdict after the call, for a script to read.
    pub width: Option<usize>,
    pub paths: Paths,
    /// The person's policy, for the rules' titles; `None` when it does not load.
    pub policy: Option<&'a Policy>,
}

/// The lines for `event`.
pub fn rows(event: &Event, view: &View<'_>) -> Vec<String> {
    let known = KnownSecrets::default();
    let (mark, symbol) = mark(event.verdict);
    let target = notice::target(event.action.as_ref())
        .map(|t| notice::shown(&view.paths, &known, &t))
        .unwrap_or_default();
    let tool = notice::shown(&view.paths, &known, &event.tool);
    let host = notice::shown(&view.paths, &known, &event.host);
    let tag = tag(event);
    let prefix_chars = 10 + HOST_WIDTH + 1 + 2 + TOOL_WIDTH + 1;
    let (target, tag) = match view.width {
        Some(width) if width < NARROW => (
            notice::middle(&target, width.saturating_sub(prefix_chars).max(8)),
            None,
        ),
        Some(width) => {
            let room = width.saturating_sub(prefix_chars + tag.chars().count() + 2);
            let target = notice::middle(&target, room.max(8));
            let pad = room.max(8).saturating_sub(target.chars().count()) + 2;
            (format!("{target}{}", " ".repeat(pad)), Some(tag))
        }
        None => (format!("{target}  "), Some(tag)),
    };
    let tag = tag.map(|t| view.style.tint(mark, &t)).unwrap_or_default();
    let quiet = event.verdict == Verdict::Defer;
    let call = format!("{tool:<TOOL_WIDTH$} {target}");
    let line = format!(
        "{}  {host:<HOST_WIDTH$} {} {}{tag}",
        view.style.dim(&clock(event.ts_ms)),
        view.style.tint(mark, symbol),
        if quiet { view.style.dim(&call) } else { call },
    );
    let mut lines = vec![line.trim_end().to_owned()];
    if let Some(why) = held(event, view.policy) {
        let text = format!("↳ {}", notice::shown(&view.paths, &known, &why));
        lines.push(format!("{}{}", " ".repeat(INDENT), view.style.dim(&text)));
    }
    lines
}

/// The colour of a verdict and its symbol, the one every command shows
/// ([`crate::render::verdict_symbol`]).
fn mark(verdict: Verdict) -> (Mark, &'static str) {
    let colour = match verdict {
        Verdict::Allow => Mark::Ok,
        Verdict::Defer => Mark::Info,
        Verdict::Review => Mark::Attention,
        // `Deny`, and any verdict added to the core later.
        _ => Mark::Broken,
    };
    (colour, crate::render::verdict_symbol(verdict))
}

/// `allow · dev-shell`, `deny · secrets-paths`, `defer · agent asks`.
fn tag(event: &Event) -> String {
    let verdict = event.verdict.as_str();
    match (event.verdict, event.rules.first()) {
        (Verdict::Defer, _) => format!("{verdict} · agent asks"),
        (_, Some(rule)) => format!("{verdict} · {rule}"),
        (_, None) => verdict.to_owned(),
    }
}

/// What a deny or review stopped, in the rule's words: its title when the
/// person's policy gives it one, else the first reason; for a review, how to
/// approve it.
fn held(event: &Event, policy: Option<&Policy>) -> Option<String> {
    if !matches!(event.verdict, Verdict::Deny | Verdict::Review) {
        return None;
    }
    let title = event
        .rules
        .iter()
        .find_map(|id| policy?.own_group(id)?.title.clone())
        .or_else(|| event.reasons.first().cloned())?;
    Some(match event.verdict {
        Verdict::Review => format!("{title} · approve: openmoat allow --last"),
        _ => title,
    })
}
