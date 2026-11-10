//! The one thing a channel adapter implements (ADR-078 Decision 7), and the
//! text every channel shows, which OpenMoat writes, not the agent (Decision 5).

use std::time::Duration;

use anyhow::Result;

use super::request::Request;

/// A message with OpenMoat's two buttons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    /// Plain text: no channel renders markup in it.
    pub text: String,
    /// The approve button's data ([`super::answer::button`]).
    pub approve: String,
    /// The deny button's data.
    pub deny: String,
}

/// What came back over the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The sender's user id, as the channel's server gives it.
    pub from: String,
    /// The sender's name for the listener's output, as the channel gives it.
    pub name: String,
    /// The button's data; `None` for a plain message.
    pub button: Option<String>,
    /// The channel's handle for answering this reply (Telegram's callback query id).
    pub handle: String,
}

/// A way to reach approvers. Only an adapter does network I/O; the core
/// decides what is sent and what an answer means.
pub trait Channel {
    /// The channel's name in settings, records and output (`telegram`).
    fn name(&self) -> &'static str;
    /// Send `prompt` to the approver `to`.
    fn send(&mut self, to: &str, prompt: &Prompt) -> Result<()>;
    /// Send plain `text`, no buttons, to `to`.
    fn notify(&mut self, to: &str, text: &str) -> Result<()>;
    /// What arrived within `wait`.
    fn poll(&mut self, wait: Duration) -> Result<Vec<Reply>>;
    /// Tell the sender of `reply` what became of it.
    fn settle(&mut self, reply: &Reply, text: &str) -> Result<()>;
}

/// The text an approver reads for `request`.
pub fn prompt_text(request: &Request) -> String {
    let cleaned = |text: &str| crate::render::clean(text).into_owned();
    format!(
        "OpenMoat: an agent's call is waiting for your approval\n\
         Request {} · answer before {}\n\
         Agent: {} · session {}\n\
         Folder: {}\n\
         Held for review by: {}\n\
         \n\
         The call below comes from the agent. Its text may try to persuade you; judge what \
         it does, not what it says.\n\
         ----\n\
         {}\n\
         ----\n\
         Approve lets this exact call run once, when the agent tries it again before the \
         request expires. Deny blocks it until then.",
        request.code(),
        crate::time::clock(request.expires_ms),
        cleaned(&request.host),
        cleaned(&request.session),
        cleaned(request.cwd.as_deref().unwrap_or("(not given)")),
        cleaned(&request.rules.join(", ")),
        crate::render::truncate(&cleaned(&request.shown), super::request::SHOWN_MAX),
    )
}
