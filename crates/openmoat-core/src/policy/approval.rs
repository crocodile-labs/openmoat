//! The `approval:` section: where a review is answered and how long the answer lasts.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalChannel {
    Terminal,
    Telegram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RememberScope {
    Once,
    Session,
    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    #[serde(default = "default_channel")]
    pub channel: ApprovalChannel,
    #[serde(default = "default_remember")]
    pub remember: RememberScope,
    #[serde(default = "default_timeout")]
    pub timeout_s: u32,
}

fn default_channel() -> ApprovalChannel {
    ApprovalChannel::Terminal
}
fn default_remember() -> RememberScope {
    RememberScope::Session
}
fn default_timeout() -> u32 {
    300
}

impl Default for Approval {
    fn default() -> Self {
        Self {
            channel: default_channel(),
            remember: default_remember(),
            timeout_s: default_timeout(),
        }
    }
}
