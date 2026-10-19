//! What every host adapter declares: the facts about a host as data
//! ([`HostSpec`]), and the one place an `ask` or `defer` is turned into what
//! the host can act on ([`answer`], [`decided`]).

use openmoat_core::{Decision, Verdict};

use crate::{HookEvent, Host};

/// How a person approves a call a host could not ask about. Every host that
/// receives an `ask` as a `deny` ends its reason with this.
const HOW_TO_APPROVE: &str = "run `moat` to approve it, or `moat allow --last` (this session) \
     or `moat allow --last --always`, then retry";

/// The facts about one host. Code covers only what a fact cannot say.
#[derive(Debug)]
pub struct HostSpec {
    /// The identifier used on the command line and in the audit log.
    pub id: &'static str,
    /// The product name shown to people.
    pub display_name: &'static str,
    /// The host whose hook format this host sends, when it is another host's
    /// (`cn` sends Claude Code's).
    pub speaks: Option<Host>,
    /// What the host does with an `ask` on each kind of tool hook.
    pub asks: Asks,
}

/// What a host does with an `ask` (and a `defer`, ADR-025) on a tool hook.
#[derive(Debug)]
pub struct Asks {
    /// On [`HookEvent::PreToolUse`]: `None` when the host puts the question to a
    /// person, else why it cannot, which the `deny` it receives instead says.
    pub on_pre_tool_use: Option<&'static str>,
    /// The same for [`HookEvent::PreToolUseNoAsk`].
    pub on_no_ask: Option<&'static str>,
    /// Whether a `defer` on [`HookEvent::PreToolUseNoAsk`] is an `ask`: the
    /// host has no flow of its own there that decides.
    pub defer_is_ask_on_no_ask: bool,
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
