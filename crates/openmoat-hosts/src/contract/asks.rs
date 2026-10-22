//! What a host does with an `ask` (and a `defer`), and the one place an `ask`
//! or `defer` is turned into what the host can act on ([`answer`], [`decided`]).

use openmoat_core::{Decision, Verdict};

use super::HostSpec;
use crate::HookEvent;

/// How a person approves a call a host could not ask about. Every host that
/// receives an `ask` as a `deny` ends its reason with this.
const HOW_TO_APPROVE: &str = "run `openmoat` to approve it, or `openmoat allow --last` (this session) \
     or `openmoat allow --last --always`, then retry";

/// What a host does with an `ask` (and a `defer`, ADR-025) on a tool hook.
#[derive(Debug)]
#[non_exhaustive]
pub struct Asks {
    /// On [`HookEvent::PreToolUse`]: `None` when the host puts the question to a
    /// person, else why it cannot, which the `deny` it receives instead says.
    pub on_pre_tool_use: Option<&'static str>,
    /// The same for [`HookEvent::PreToolUseNoAsk`].
    pub on_no_ask: Option<&'static str>,
    /// Whether a `defer` on [`HookEvent::PreToolUseNoAsk`] is an `ask`: the
    /// host has no flow of its own there that decides.
    pub defer_is_ask_on_no_ask: bool,
    /// The verdict for a tool OpenMoat does not govern: `defer`, so the host
    /// decides it as if no hook had answered, or `allow` where the host's hooks
    /// have no "no decision" (Cursor).
    pub ungoverned: Verdict,
    /// Whether an `ask` for a tainted session's protected write tells the
    /// person that `openmoat allow --last` stops the asking in this session.
    pub allow_last_hint: bool,
    /// The values of the payload's permission mode in which no question
    /// reaches a person: a call in one is [`HookEvent::PreToolUseNoAsk`].
    pub prompt_free_modes: &'static [&'static str],
}

impl Asks {
    /// The value the asks of a host spec take for every field they do not
    /// name: the host asks on every tool hook, an ungoverned tool is a
    /// `defer`, no `allow --last` hint and no prompt-free modes.
    pub const BASE: Asks = Asks {
        on_pre_tool_use: None,
        on_no_ask: None,
        defer_is_ask_on_no_ask: false,
        ungoverned: Verdict::Defer,
        allow_last_hint: false,
        prompt_free_modes: &[],
    };
}

/// The decision to record for `event` on the host `spec` describes. A `defer`
/// needs a host flow that decides by itself; where there is none, OpenMoat
/// asks itself: the `ask` is recorded, and [`answer`] sends it as a deny that
/// says how to approve it.
pub(crate) fn decided(spec: &HostSpec, event: &HookEvent, mut decision: Decision) -> Decision {
    if spec.asks.defer_is_ask_on_no_ask
        && *event == HookEvent::PreToolUseNoAsk
        && decision.verdict == Verdict::Defer
    {
        decision.verdict = Verdict::Ask;
    }
    decision
}

/// The decision as the host `spec` describes has to receive it. Where the host
/// cannot ask, an `ask` reaches it as a `deny` that says how to approve it; the
/// audit log keeps the `ask`, which is what `moat allow --last` looks for.
pub(crate) fn answer(spec: &HostSpec, event: &HookEvent, decision: &Decision) -> Decision {
    let why = match event {
        HookEvent::PreToolUse => spec.asks.on_pre_tool_use,
        HookEvent::PreToolUseNoAsk => spec.asks.on_no_ask,
        HookEvent::ConfigChange { .. } => None,
    };
    let mut answer = decision.clone();
    if let Some(why) = why
        && decision.verdict == Verdict::Ask
    {
        answer.verdict = Verdict::Deny;
        answer.reasons.push(format!(
            "this needs your approval and {why}: {HOW_TO_APPROVE}"
        ));
    }
    answer
}
