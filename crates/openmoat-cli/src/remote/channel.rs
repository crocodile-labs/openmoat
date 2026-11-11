//! The contract between the channel-neutral core and a channel (ADR-078,
//! "Channel architecture"): the [`Channel`] trait a channel implements, the
//! [`Spec`] that describes it (its [`Capabilities`], credential and user id
//! shapes, and how to open it), and the [`Registry`] that lists every channel.
//! The core never names a channel; it reads all it needs here.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Result, bail};
use zeroize::Zeroizing;

/// One secret value (a bot token, an app token), zeroed on drop.
pub type Credential = Zeroizing<String>;

/// A channel's secret fields ([`Field::secret`]) by key, kept owner-only in
/// `<channel>/credential`, never in a signed or readable settings file.
pub type Secrets = BTreeMap<String, Credential>;

/// A channel's other fields by key; signed with the approval key in the
/// channel's own settings.
pub type Options = BTreeMap<String, String>;

/// What a channel can do; the core shapes every message to fit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// A message can carry buttons, and the channel's server reports a press
    /// with the id of the account that pressed it.
    pub buttons: bool,
    /// The most bytes a button's data may hold. When OpenMoat's button data
    /// does not fit, the core falls back to reply codes, as without buttons.
    pub button_bytes: usize,
    /// The longest message text, in characters. At least [`MIN_TEXT`].
    pub max_text: usize,
}

impl Capabilities {
    /// Whether prompts carry buttons: the channel has them and
    /// [`super::answer::BUTTON_LEN`] bytes fit in one. Otherwise the approver
    /// sends the reply code back as a message.
    pub fn uses_buttons(&self) -> bool {
        self.buttons && self.button_bytes >= super::answer::BUTTON_LEN
    }
}

/// The shortest message text a channel may allow: room for OpenMoat's own
/// framing, both reply codes and enough of the call to judge it.
pub const MIN_TEXT: usize = 1024;

/// One value `connect` takes for a channel, declared as data so one generic
/// prompt, one store and one check serve every channel.
#[derive(Debug, Clone, Copy)]
pub struct Field {
    /// The key it is kept under: lowercase letters, digits and `_`.
    pub key: &'static str,
    /// What the person is asked at the terminal.
    pub ask: &'static str,
    /// A secret: asked at the terminal or read from a file, never taken as a
    /// command-line argument, stored owner-only in [`Secrets`], never shown.
    pub secret: bool,
    /// Whether a value is acceptable; checked at `connect` and every load.
    pub valid: fn(&str) -> bool,
}

/// Everything the core knows about one channel. A channel's folder defines
/// one `pub const SPEC: Spec` and the registry lists it.
pub struct Spec {
    /// The channel's name in commands, settings, records and approver ids:
    /// lowercase letters, digits and `-`.
    pub name: &'static str,
    /// The name people read (`connect`'s output, help).
    pub title: &'static str,
    pub capabilities: Capabilities,
    /// What `connect` takes, secret or not, in the order it asks.
    pub fields: &'static [Field],
    /// What a user id on this channel looks like, for errors.
    pub user_id: &'static str,
    /// Whether text is a user id on this channel (without the `name:` prefix).
    pub valid_user: fn(&str) -> bool,
    /// The channel, ready to use with its checked secrets and options. No
    /// network I/O happens before a method is called.
    pub open: fn(&Secrets, &Options) -> Result<Box<dyn Channel>>,
    /// What the person does after `connect`, given the channel's account name.
    pub next_steps: fn(&str) -> String,
    /// How to revoke the credential after `disconnect`.
    pub revoke: &'static str,
}

impl std::fmt::Debug for Spec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spec")
            .field("name", &self.name)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

/// One choice on a prompt: a button's label and its data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub label: &'static str,
    pub data: String,
}

/// A message to an approver, already shaped to the channel's capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    /// Plain text: no channel renders markup in it. Fits
    /// [`Capabilities::max_text`]; without buttons it ends with the reply codes.
    pub text: String,
    /// The buttons, approve first; empty when the channel takes reply codes.
    pub choices: Vec<Choice>,
}

/// What came back over the channel.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reply {
    /// The sender's user id on this channel, as the channel's server gives it;
    /// the core qualifies it with the channel's name ([`approver_id`]).
    pub from: String,
    /// The sender's name for the listener's output, as the channel gives it.
    pub name: String,
    /// A pressed button's data; `None` for a message.
    pub button: Option<String>,
    /// A message's text; `None` for a button press.
    pub text: Option<String>,
    /// The channel's handle for answering this reply (a callback id).
    pub handle: String,
}

/// A way to reach approvers. Only a channel does network I/O; the core
/// decides what is sent and what an answer means.
pub trait Channel {
    /// The account the credential belongs to (a bot's name), which also
    /// proves the credential works.
    fn account(&mut self) -> Result<String>;
    /// Send `prompt` to the user `to` (an id without the channel prefix).
    fn send(&mut self, to: &str, prompt: &Prompt) -> Result<()>;
    /// Send plain `text`, no buttons, to `to`.
    fn notify(&mut self, to: &str, text: &str) -> Result<()>;
    /// What arrived within `wait`.
    fn poll(&mut self, wait: Duration) -> Result<Vec<Reply>>;
    /// Tell the sender of `reply` what became of it.
    fn settle(&mut self, reply: &Reply, text: &str) -> Result<()>;
}

/// Names a channel folder may not take: the store's own folders.
const RESERVED: &[&str] = &["requests", "answers", "used"];

/// Every channel this build knows, in one list ([`super::channels::REGISTRY`]).
#[derive(Debug, Clone, Copy)]
pub struct Registry(pub &'static [&'static Spec]);

impl Registry {
    /// The channel called `name`; refused, for every name, when the list
    /// breaks a rule of [`Registry::check`].
    pub fn find(&self, name: &str) -> Result<&'static Spec> {
        self.check()?;
        match self.0.iter().find(|spec| spec.name == name) {
            Some(spec) => Ok(spec),
            None => bail!(
                "this release does not know the channel `{}`; it knows: {}",
                crate::render::clean(name),
                self.names().join(", ")
            ),
        }
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.0.iter().map(|spec| spec.name).collect()
    }

    /// Every rule a listed channel must meet: a plain unique name that is not
    /// one of the store's folders, and room for a prompt.
    pub fn check(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for spec in self.0 {
            let name = spec.name;
            if name.is_empty()
                || name.len() > 32
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || RESERVED.contains(&name)
            {
                bail!("`{name}` cannot name a channel");
            }
            if !seen.insert(name) {
                bail!("`{name}` is listed twice");
            }
            if spec.capabilities.max_text < MIN_TEXT {
                bail!("{name}: messages under {MIN_TEXT} characters cannot hold a prompt");
            }
            let keys: std::collections::BTreeSet<_> = spec.fields.iter().map(|f| f.key).collect();
            if keys.len() != spec.fields.len() {
                bail!("{name}: two fields share a key");
            }
            if let Some(field) = spec.fields.iter().find(|f| {
                f.key.is_empty()
                    || !f
                        .key
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            }) {
                bail!("{name}: `{}` cannot name a field", field.key);
            }
        }
        Ok(())
    }

    /// The qualified approver id `given` names: `name:id` for a listed
    /// channel, or a bare id on `connected`. Refused when it is not a user id
    /// of that channel, or names another channel than the connected one.
    pub fn approver(&self, connected: &'static Spec, given: &str) -> Result<String> {
        let (spec, local) = match given.split_once(':') {
            Some((prefix, local)) if self.0.iter().any(|s| s.name == prefix) => {
                (self.find(prefix)?, local)
            }
            _ => (connected, given),
        };
        if spec.name != connected.name {
            bail!(
                "`{}` is a {} id, but the connected channel is {}",
                crate::render::clean(given),
                spec.title,
                connected.title
            );
        }
        if !(spec.valid_user)(local) {
            bail!("`{}` is not {}", crate::render::clean(local), spec.user_id);
        }
        Ok(approver_id(spec.name, local))
    }
}

/// The approver id of user `local` on channel `name`: `name:local`. Every
/// allowlist entry and every answer carries this form, so ids of two
/// channels never collide.
pub fn approver_id(name: &str, local: &str) -> String {
    format!("{name}:{local}")
}

/// The channel's own part of an approver id (`123` of `<name>:123`), when
/// it belongs to channel `name`.
pub fn local_id<'a>(name: &str, approver: &'a str) -> Option<&'a str> {
    approver
        .strip_prefix(name)
        .and_then(|rest| rest.strip_prefix(':'))
}
