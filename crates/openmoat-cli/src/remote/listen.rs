//! The loop behind `openmoat approvals listen`, channel-neutral (ADR-078):
//! send each waiting request to every approver, turn each button press from
//! an approver into a signed answer, and record and clear what expired.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::Result;
use openmoat_core::Verdict;

use super::answer::{self, Answer};
use super::channel::{Channel, Prompt, Reply, prompt_text};
use super::request::Request;
use super::settings::Settings;
use super::store::Store;
use super::{APPROVED_ROW_RULE, DENIED_RULE, EXPIRED_RULE, REFUSED_RULE};
use crate::proxy_session::Key;

/// One audit row the listener writes, in the request's host and session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub host: String,
    pub session: String,
    pub cwd: Option<String>,
    pub rule: &'static str,
    pub verdict: Verdict,
    pub reason: String,
}

/// Where the listener's rows go: the audit log, or a test's list.
pub trait Records {
    /// Write `row`; an error stops the answer it belongs to.
    fn record(&mut self, row: Row) -> Result<()>;
}

pub struct Listener<'a> {
    store: &'a Store,
    key: &'a Key,
    settings: Settings,
    /// Requests already sent in this run.
    sent: HashSet<String>,
    /// What happened, one line each, for the person's terminal.
    pub log: Vec<String>,
}

fn row(request: &Request, rule: &'static str, verdict: Verdict, reason: String) -> Row {
    Row {
        host: request.host.clone(),
        session: request.session.clone(),
        cwd: request.cwd.clone(),
        rule,
        verdict,
        reason,
    }
}

impl<'a> Listener<'a> {
    /// Use `settings` from the next round on: the approvers a person changed
    /// while the listener runs.
    pub fn update(&mut self, settings: Settings) {
        self.settings = settings;
    }

    pub fn new(store: &'a Store, key: &'a Key, settings: Settings) -> Self {
        Self {
            store,
            key,
            settings,
            sent: HashSet::new(),
            log: Vec::new(),
        }
    }

    /// One round: send what is new, expire what is old, then wait up to
    /// `wait` for replies and answer them. `now` reads the clock.
    pub fn step(
        &mut self,
        channel: &mut dyn Channel,
        records: &mut dyn Records,
        wait: Duration,
        now: &dyn Fn() -> i64,
    ) -> Result<()> {
        self.sweep(channel, records, now())?;
        for reply in channel.poll(wait)? {
            self.reply(channel, records, &reply, now())?;
        }
        Ok(())
    }

    fn sweep(
        &mut self,
        channel: &mut dyn Channel,
        records: &mut dyn Records,
        now_ms: i64,
    ) -> Result<()> {
        self.store.sweep_used(now_ms);
        for found in self.store.requests()? {
            let request = match found {
                Ok(request) if request.verified(self.key) => request,
                Ok(request) => {
                    records.record(row(
                        &request,
                        REFUSED_RULE,
                        Verdict::Deny,
                        "a request on file was not signed with this machine's approval key; \
                         removed unsent"
                            .to_owned(),
                    ))?;
                    self.log
                        .push(format!("removed request {}: bad signature", request.code()));
                    self.store.forget(&request.id);
                    continue;
                }
                Err(id) => {
                    self.log.push(format!("removed unreadable request {id}"));
                    self.store.forget(&id);
                    continue;
                }
            };
            if request.expired(now_ms) {
                self.expire(channel, records, &request)?;
            } else if !self.sent.contains(&request.id) {
                self.send(channel, &request);
            }
        }
        Ok(())
    }

    fn send(&mut self, channel: &mut dyn Channel, request: &Request) {
        let prompt = Prompt {
            text: prompt_text(request),
            approve: answer::button(self.key, answer::Verdict::Approve, request),
            deny: answer::button(self.key, answer::Verdict::Deny, request),
        };
        let mut reached = 0;
        for approver in &self.settings.approvers {
            match channel.send(approver, &prompt) {
                Ok(()) => reached += 1,
                Err(error) => self.log.push(format!(
                    "could not send request {} to {approver}: {error:#}",
                    request.code()
                )),
            }
        }
        // Sent again next round when nobody could be reached.
        if reached > 0 {
            self.sent.insert(request.id.clone());
            self.log.push(format!(
                "sent request {} ({} in {}) to {reached} approver(s)",
                request.code(),
                crate::render::clean(&request.tool),
                request.host
            ));
        }
    }

    fn expire(
        &mut self,
        channel: &mut dyn Channel,
        records: &mut dyn Records,
        request: &Request,
    ) -> Result<()> {
        if self.store.answer(&request.id).is_none() {
            records.record(row(
                request,
                EXPIRED_RULE,
                Verdict::Deny,
                format!(
                    "request {} got no answer before it expired; the call stays held for review",
                    request.code()
                ),
            ))?;
            if self.sent.contains(&request.id) {
                for approver in &self.settings.approvers {
                    let _ = channel.notify(
                        approver,
                        &format!(
                            "OpenMoat: request {} expired unanswered; nothing ran",
                            request.code()
                        ),
                    );
                }
            }
            self.log
                .push(format!("request {} expired unanswered", request.code()));
        }
        self.sent.remove(&request.id);
        self.store.forget(&request.id);
        Ok(())
    }

    fn reply(
        &mut self,
        channel: &mut dyn Channel,
        records: &mut dyn Records,
        reply: &Reply,
        now_ms: i64,
    ) -> Result<()> {
        let from = crate::render::clean(&reply.from).into_owned();
        let name = crate::render::clean(&reply.name).into_owned();
        let Some(data) = &reply.button else {
            if self.settings.approver(&reply.from) {
                self.log
                    .push(format!("message from approver {name} ({from})"));
            } else {
                self.log.push(format!(
                    "message from {name} ({from}), who is not an approver; `openmoat approvals \
                     allow {from}` would make them one"
                ));
            }
            return Ok(());
        };
        let Some((verdict, id, tag)) = answer::parse_button(data) else {
            let _ = channel.settle(reply, "not an OpenMoat button");
            return Ok(());
        };
        let Some(request) = self.store.request(id).filter(|r| r.verified(self.key)) else {
            let _ = channel.settle(reply, "this request is no longer waiting");
            return Ok(());
        };
        let refuse = |why: &str| {
            row(
                &request,
                REFUSED_RULE,
                Verdict::Deny,
                format!("an answer to request {} was refused: {why}", request.code()),
            )
        };
        if !self.settings.approver(&reply.from) {
            records.record(refuse(&format!("{from} is not an approver")))?;
            self.log.push(format!(
                "refused an answer from {name} ({from}), who is not an approver"
            ));
            let _ = channel.settle(reply, "You are not an approver for this machine.");
            return Ok(());
        }
        if !answer::button_holds(self.key, verdict, &request, tag) {
            records.record(refuse("its button was not one OpenMoat sent"))?;
            let _ = channel.settle(reply, "This button is not valid.");
            return Ok(());
        }
        if request.expired(now_ms) {
            records.record(refuse("it came after the request expired"))?;
            let _ = channel.settle(reply, "Too late: this request has expired.");
            return Ok(());
        }
        if self.store.answer(id).is_some() || self.store.used(id) {
            let _ = channel.settle(reply, "This request was already answered.");
            return Ok(());
        }
        let answer = Answer::signed(
            self.key,
            &request,
            (verdict, &reply.from, channel.name()),
            now_ms,
        )?;
        let (rule, core) = match verdict {
            answer::Verdict::Approve => (APPROVED_ROW_RULE, Verdict::Allow),
            answer::Verdict::Deny => (DENIED_RULE, Verdict::Deny),
        };
        if !self.store.put_answer(&answer)? {
            let _ = channel.settle(reply, "This request was already answered.");
            return Ok(());
        }
        // An answer that cannot be recorded does not stand.
        let recorded = records.record(row(
            &request,
            rule,
            core,
            format!(
                "request {} {} by {from} on {}",
                request.code(),
                verdict.word(),
                channel.name()
            ),
        ));
        if let Err(error) = recorded {
            self.store.forget_answer(id);
            let _ = channel.settle(reply, "Not recorded, so not applied; try again.");
            return Err(error);
        }
        self.log.push(format!(
            "request {} {} by {name} ({from})",
            request.code(),
            verdict.word()
        ));
        let text = match verdict {
            answer::Verdict::Approve => {
                "Approved: the call runs once when the agent tries it again before the request \
                 expires."
            }
            answer::Verdict::Deny => "Denied: the call stays blocked until the request expires.",
        };
        let _ = channel.settle(reply, text);
        Ok(())
    }
}
