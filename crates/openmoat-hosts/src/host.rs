//! One module per host: its [`HostSpec`](crate::HostSpec) and the quirks a
//! fact cannot say. A host that sends a shared format reads it through
//! [`crate::wire`]; no host module imports another.

pub(crate) mod claude_code;
pub(crate) mod codex;
pub(crate) mod continue_cli;
pub(crate) mod cursor;
pub(crate) mod openclaw;
