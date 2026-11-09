//! What a host does with a `review` (and a `defer`), and the one place a `review`
//! or `defer` is turned into what the host can act on ([`answer`], [`decided`]).

use openmoat_core::{Decision, Verdict};

use super::HostSpec;
use crate::HookEvent;

/// How a person approves a call a host could not prompt about. Every host that
/// receives a `review` as a `deny` ends its reason with this.
const HOW_TO_APPROVE: &str = "run `openmoat` to approve it, or `openmoat allow --last` (this session) \
     or `openmoat allow --last --always`, then retry";

/// What a host does with a `review` (and a `defer`, ADR-025) on a tool hook.
#[derive(Debug)]
#[non_exhaustive]
pub struct Reviews {
    /// On [`HookEvent::PreToolUse`]: `None` when the host puts the question to a
    /// person, else why it cannot, which the `deny` it receives instead says.
    pub on_pre_tool_use: Option<&'static str>,
    /// The same for [`HookEvent::PreToolUseNoPrompt`].
    pub on_no_prompt: Option<&'static str>,
    /// Whether a `defer` on [`HookEvent::PreToolUseNoPrompt`] is a `review`: the
    /// host has no flow of its own there that decides.
    pub defer_is_review_on_no_prompt: bool,
    /// The verdict for a tool OpenMoat does not govern: `defer`, so the host
    /// decides it as if no hook had answered, or `allow` where the host's hooks
    /// have no "no decision" (Cursor).
    pub ungoverned: Verdict,
    /// Whether a `review` for a tainted session's protected write tells the
    /// person that `openmoat allow --last` stops the reviews in this session.
    pub allow_last_hint: bool,
    /// The values of the payload's permission mode in which no question
    /// reaches a person: a call in one is [`HookEvent::PreToolUseNoPrompt`].
    pub prompt_free_modes: &'static [&'static str],
    /// How to tell, outside the payload, that the host would approve a
    /// `review` without a person seeing it; a call then is
    /// [`HookEvent::PreToolUseNoPrompt`]. `None` for a host whose payload says
    /// it, or whose reviews always reach a person.
    pub unseen: Option<Unseen>,
}

/// What the hook's process can see that makes a host approve a `review` unseen
/// ([`Reviews::unseen`]): the CLI checks it before answering a call.
#[derive(Debug)]
#[non_exhaustive]
pub struct Unseen {
    /// Variables of the hook's environment that do it when set to `1`,
    /// `true`, `yes` or `on`, in any case.
    pub env: &'static [&'static str],
    /// A file of the configuration directory to read for [`Self::config`] in
    /// place of the hook file (Antigravity CLI's `settings.json`, beside no
    /// hook); `None` reads the hook file. A file that is not there holds no
    /// such setting.
    pub file: Option<&'static str>,
    /// The setting of that file, parsed, that does it; `None`
    /// when no setting there does.
    pub config: fn(&serde_json::Value) -> Option<&'static str>,
}

impl Unseen {
    /// Whether `value`, a variable's, is one [`Self::env`] counts.
    #[must_use]
    pub fn truthy(value: &str) -> bool {
        ["1", "true", "yes", "on"]
            .iter()
            .any(|t| value.trim().eq_ignore_ascii_case(t))
    }
}

impl Reviews {
    /// The value the reviews of a host spec take for every field they do not
    /// name: the host prompts on every tool hook, an ungoverned tool is a
    /// `defer`, no `allow --last` hint, no prompt-free modes and nothing
    /// else that approves a review unseen.
    pub const BASE: Reviews = Reviews {
        on_pre_tool_use: None,
        on_no_prompt: None,
        defer_is_review_on_no_prompt: false,
        ungoverned: Verdict::Defer,
        allow_last_hint: false,
        prompt_free_modes: &[],
        unseen: None,
    };
}

/// The decision to record for `event` on the host `spec` describes. A `defer`
/// needs a host flow that decides by itself; where there is none, OpenMoat
/// holds the call for review itself: the `review` is recorded, and [`answer`]
/// sends it as a deny that says how to approve it.
pub(crate) fn decided(spec: &HostSpec, event: &HookEvent, mut decision: Decision) -> Decision {
    if spec.reviews.defer_is_review_on_no_prompt
        && *event == HookEvent::PreToolUseNoPrompt
        && decision.verdict == Verdict::Defer
    {
        decision.verdict = Verdict::Review;
    }
    decision
}

/// The decision as the host `spec` describes has to receive it. Where the host
/// cannot prompt, a `review` reaches it as a `deny` that says how to approve it; the
/// audit log keeps the `review`, which is what `moat allow --last` looks for.
pub(crate) fn answer(spec: &HostSpec, event: &HookEvent, decision: &Decision) -> Decision {
    let why = match event {
        HookEvent::PreToolUse => spec.reviews.on_pre_tool_use,
        HookEvent::PreToolUseNoPrompt => spec.reviews.on_no_prompt,
        HookEvent::ConfigChange { .. }
        | HookEvent::SessionStart { .. }
        | HookEvent::PostToolUse { .. } => None,
    };
    let mut answer = decision.clone();
    if let Some(why) = why
        && decision.verdict == Verdict::Review
    {
        answer.verdict = Verdict::Deny;
        // A block message says how to approve on its `next` line (ADR-059).
        match &mut answer.notice {
            Some(notice) => notice.unasked = Some(why.to_owned()),
            None => answer.reasons.push(format!(
                "this needs your approval and {why}: {HOW_TO_APPROVE}"
            )),
        }
    }
    answer
}
