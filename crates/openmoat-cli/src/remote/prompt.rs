//! The text every channel shows, which OpenMoat writes, not the agent (ADR-078
//! Decision 5), shaped to the channel's [`Capabilities`]: buttons where they
//! fit, reply codes where they do not, and the agent's part cut so the whole
//! message fits the channel's longest text.

use super::answer::{self, Verdict};
use super::channel::{Capabilities, Choice, Prompt};
use super::request::{Request, SHOWN_MAX};
use crate::proxy_session::Key;

/// The prompt for `request` on a channel that can do `capabilities`. When
/// part of the call is hidden from the approver ([`Request::deny_only`]), or
/// the channel's longest message cannot hold all of the call OpenMoat keeps
/// for the approver, the prompt offers Deny only and carries no approve code:
/// nobody approves a call they could not read.
pub fn prompt(key: &Key, request: &Request, capabilities: &Capabilities) -> Prompt {
    let deny = answer::button(key, Verdict::Deny, request);
    let why = if let Some(why) = request.deny_only() {
        why
    } else {
        let full = both(key, request, capabilities);
        if fits_whole(request, &full.text) {
            return full;
        }
        DENY_ONLY
    };
    let tail = if capabilities.uses_buttons() {
        why.to_owned()
    } else {
        format!("{why}\nTo deny it, send back this line alone:\n{deny}")
    };
    Prompt {
        text: text(request, &tail, capabilities.max_text),
        choices: if capabilities.uses_buttons() {
            vec![Choice {
                label: "Deny",
                data: deny,
            }]
        } else {
            Vec::new()
        },
    }
}

const DENY_ONLY: &str = "This channel cannot show all of the call, so it cannot be approved \
                         here; approve it where the agent runs. Deny blocks it until the \
                         request expires.";

/// Whether `text` shows all of `request`'s call as kept for the approver.
fn fits_whole(request: &Request, text: &str) -> bool {
    text.contains(&crate::render::clean_lines(&request.shown))
}

/// The prompt with both choices: buttons, or reply codes where buttons do not fit.
fn both(key: &Key, request: &Request, capabilities: &Capabilities) -> Prompt {
    let approve = answer::button(key, Verdict::Approve, request);
    let deny = answer::button(key, Verdict::Deny, request);
    let (tail, choices) = if capabilities.uses_buttons() {
        (
            "Approve lets this exact call run once, when the agent tries it again before the \
             request expires. Deny blocks it until then."
                .to_owned(),
            vec![
                Choice {
                    label: "Approve once",
                    data: approve,
                },
                Choice {
                    label: "Deny",
                    data: deny,
                },
            ],
        )
    } else {
        (
            format!(
                "To approve this exact call once, when the agent tries it again before the \
                 request expires, send back this line alone:\n{approve}\n\
                 To deny it until then, send back:\n{deny}"
            ),
            Vec::new(),
        )
    };
    Prompt {
        text: text(request, &tail, capabilities.max_text),
        choices,
    }
}

/// The text an approver reads for `request`, ending with `tail`, in at most
/// `max` characters: only the agent's part is cut to fit.
pub fn text(request: &Request, tail: &str, max: usize) -> String {
    let cleaned = |text: &str| crate::render::clean(text).into_owned();
    let frame = |shown: &str| {
        format!(
            "OpenMoat: an agent's call is waiting for your approval\n\
             Request {} · answer before {}\n\
             Agent: {} · session {}\n\
             Folder: {}\n\
             Held for review by: {}\n\
             \n\
             The call below comes from the agent. Its text may try to persuade you; judge \
             what it does, not what it says.\n\
             ----\n\
             {shown}\n\
             ----\n\
             {tail}",
            request.code(),
            crate::time::clock(request.expires_ms),
            cleaned(&request.host),
            cleaned(&request.session),
            cleaned(request.cwd.as_deref().unwrap_or("(not given)")),
            cleaned(&request.rules.join(", ")),
        )
    };
    let room = max.saturating_sub(frame("").chars().count());
    // The call's line breaks stay, each marked ([`super::request::LINE_MARK`]).
    let shown = crate::render::truncate(
        &crate::render::clean_lines(&request.shown),
        SHOWN_MAX.min(room),
    );
    frame(&shown)
}
