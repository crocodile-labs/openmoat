//! The Telegram channel (ADR-078): a bot the person made, reached with the
//! Bot API's long polling (`getUpdates`), so nothing listens on this machine.
//!
//! Facts used, from <https://core.telegram.org/bots/api>: requests are
//! `https://api.telegram.org/bot<token>/METHOD`; every answer is a JSON object
//! with `ok`, then `result` or `description`; a button's `callback_data` is
//! 1–64 bytes; message text is at most 4096 characters; `getUpdates` does not
//! work while a webhook is set.

#[cfg(test)]
mod tests;

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::remote::channel::{
    Capabilities, Channel, Credential, Field, Options, Prompt, Reply, Secrets, Spec,
};
use crate::remote::https;

/// The channel, as the registry lists it.
pub const SPEC: Spec = Spec {
    name: "telegram",
    title: "Telegram",
    capabilities: Capabilities {
        buttons: true,
        button_bytes: 64,
        max_text: MAX_TEXT,
        // `getUpdates`' `timeout`: the server answers as soon as an update
        // arrives, so answers are seen at once and an idle listener asks
        // about 144 times an hour.
        poll_wait: Duration::from_secs(25),
    },
    fields: &[Field {
        key: TOKEN,
        ask: "Paste the bot's token from @BotFather, then Enter: ",
        secret: true,
        valid: valid_token,
    }],
    user_id: "a Telegram user id (a number)",
    valid_user,
    open,
    next_steps,
    revoke: "revoke the bot's token with @BotFather if it may have been seen",
};

/// The one secret: the bot's token.
const TOKEN: &str = "token";
const API_HOST: &str = "api.telegram.org";
/// What a request may take beyond the long poll it asks for.
const SLACK: Duration = Duration::from_secs(15);
/// Telegram's longest message text.
const MAX_TEXT: usize = 4096;

fn open(secrets: &Secrets, _: &Options) -> Result<Box<dyn Channel>> {
    let token = secrets.get(TOKEN).context("the bot's token is missing")?;
    Ok(Box::new(Telegram::new(Https::new(token.clone())?)))
}

fn next_steps(bot: &str) -> String {
    format!(
        "  1. send /start to {bot} from your own Telegram account\n  2. run `openmoat \
         approvals listen` in a terminal of your own; it prints your user id when you \
         message the bot\n  3. `openmoat approvals allow <your user id>`, then `openmoat \
         approvals test`"
    )
}

/// One Bot API call: the method, its JSON body and how long to wait; the
/// parsed answer. The real one is HTTPS; tests give a fake.
pub trait Api: Send {
    fn call(&mut self, method: &str, body: &Value, timeout: Duration) -> Result<Value>;
}

/// The Bot API over HTTPS, with the token held zeroed-on-drop.
pub struct Https {
    token: Credential,
    client: https::Client,
}

impl Https {
    pub fn new(token: Credential) -> Result<Self> {
        Ok(Self {
            token,
            client: https::Client::new(API_HOST)?,
        })
    }
}

impl Api for Https {
    fn call(&mut self, method: &str, body: &Value, timeout: Duration) -> Result<Value> {
        let path = Zeroizing::new(format!("/bot{}/{method}", self.token.as_str()));
        let body = serde_json::to_vec(body).context("encoding a Telegram request")?;
        let raw = self.client.post(&path, &body, timeout)?;
        serde_json::from_slice(&raw).with_context(|| format!("Telegram's answer to {method}"))
    }
}

/// Whether `token` has the shape of a bot token, `<digits>:<secret>`.
pub fn valid_token(token: &str) -> bool {
    let Some((bot, secret)) = token.split_once(':') else {
        return false;
    };
    !bot.is_empty()
        && bot.len() <= 20
        && bot.bytes().all(|b| b.is_ascii_digit())
        && (30..=80).contains(&secret.len())
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Whether `id` is a Telegram user id (a positive integer).
pub fn valid_user(id: &str) -> bool {
    !id.is_empty() && id.len() <= 20 && id.bytes().all(|b| b.is_ascii_digit()) && id != "0"
}

/// `answer`'s `result`, or an error with Telegram's description.
fn result(method: &str, answer: &Value) -> Result<Value> {
    if answer.get("ok").and_then(Value::as_bool) == Some(true) {
        return Ok(answer.get("result").cloned().unwrap_or(Value::Null));
    }
    let why = answer
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("no reason given");
    bail!(
        "Telegram refused {method}: {}",
        crate::render::clean(&crate::render::truncate(why, 200))
    )
}

pub struct Telegram<A: Api> {
    api: A,
    /// One more than the last update id handled: where `getUpdates` asks from.
    offset: i64,
    /// One more than the last update id the last poll returned.
    next: i64,
}

impl<A: Api> Telegram<A> {
    pub fn new(api: A) -> Self {
        Self {
            api,
            offset: 0,
            next: 0,
        }
    }

    fn call(&mut self, method: &str, body: &Value, timeout: Duration) -> Result<Value> {
        let answer = self.api.call(method, body, timeout)?;
        result(method, &answer)
    }

    fn message(to: &str, text: &str) -> Result<Value> {
        let chat: i64 = to.parse().context("a Telegram user id is a number")?;
        Ok(json!({
            "chat_id": chat,
            "text": crate::render::truncate(text, MAX_TEXT),
            "link_preview_options": { "is_disabled": true },
        }))
    }
}

/// The user id and a name to show of `from`, a Telegram `User`; `None` for a bot.
fn sender(from: &Value) -> Option<(String, String)> {
    if from.get("is_bot").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    let id = from.get("id").and_then(Value::as_i64)?;
    let name = from
        .get("username")
        .and_then(Value::as_str)
        .map(|u| format!("@{u}"))
        .or_else(|| {
            from.get("first_name")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default();
    Some((id.to_string(), name))
}

/// The replies in a `getUpdates` result, and the next offset.
pub fn replies(updates: &Value, offset: i64) -> (Vec<Reply>, i64) {
    let mut next = offset;
    let mut out = Vec::new();
    for update in updates.as_array().map(Vec::as_slice).unwrap_or_default() {
        if let Some(id) = update.get("update_id").and_then(Value::as_i64) {
            next = next.max(id.saturating_add(1));
        }
        if let Some(query) = update.get("callback_query") {
            let (Some((from, name)), Some(handle)) = (
                query.get("from").and_then(sender),
                query.get("id").and_then(Value::as_str),
            ) else {
                continue;
            };
            out.push(Reply {
                from,
                name,
                button: Some(
                    query
                        .get("data")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                ),
                text: None,
                handle: handle.to_owned(),
            });
        } else if let Some(message) = update.get("message")
            && let Some((from, name)) = message.get("from").and_then(sender)
        {
            out.push(Reply {
                from,
                name,
                button: None,
                text: Some(
                    message
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                ),
                handle: String::new(),
            });
        }
    }
    (out, next)
}

impl<A: Api> Channel for Telegram<A> {
    /// The bot's `@username`.
    fn account(&mut self) -> Result<String> {
        let me = self.call("getMe", &json!({}), SLACK)?;
        let name = me.get("username").and_then(Value::as_str).unwrap_or("");
        Ok(format!("@{}", crate::render::clean(name)))
    }

    fn send(&mut self, to: &str, prompt: &Prompt) -> Result<()> {
        let mut body = Self::message(to, &prompt.text)?;
        if !prompt.choices.is_empty() {
            let row: Vec<Value> = prompt
                .choices
                .iter()
                .map(|c| json!({ "text": c.label, "callback_data": c.data }))
                .collect();
            body["reply_markup"] = json!({ "inline_keyboard": [row] });
        }
        self.call("sendMessage", &body, SLACK).map(drop)
    }

    fn notify(&mut self, to: &str, text: &str) -> Result<()> {
        self.call("sendMessage", &Self::message(to, text)?, SLACK)
            .map(drop)
    }

    fn poll(&mut self, wait: Duration) -> Result<Vec<Reply>> {
        let body = json!({
            "offset": self.offset,
            "timeout": wait.as_secs(),
            "allowed_updates": ["message", "callback_query"],
        });
        let updates = self.call("getUpdates", &body, wait + SLACK)?;
        let (out, next) = replies(&updates, self.offset);
        self.next = next;
        Ok(out)
    }

    /// The next `getUpdates` asks from past these, which confirms them to
    /// Telegram; until then they are fetched again.
    fn handled(&mut self) {
        self.offset = self.next;
    }

    fn settle(&mut self, reply: &Reply, text: &str) -> Result<()> {
        if !reply.handle.is_empty() {
            let body = json!({ "callback_query_id": reply.handle, "text": text });
            self.call("answerCallbackQuery", &body, SLACK)?;
        }
        self.notify(&reply.from, text)
    }
}
