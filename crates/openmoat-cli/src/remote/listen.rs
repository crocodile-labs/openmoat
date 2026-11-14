//! The loop behind `openmoat approvals listen`, channel-neutral (ADR-078):
//! send each waiting request to every approver, turn each button press from
//! an approver into a signed answer, and record and clear what expired.
//! [`run`] runs the two halves, sending and answering, on their own threads.

pub mod run;

use std::collections::HashSet;

use anyhow::Result;
use openmoat_core::Verdict;

use super::answer::{self, Answer};
use super::channel::{Channel, Reply, Spec, approver_id, local_id};
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
    /// The connected channel's spec: its name qualifies every sender, its
    /// capabilities shape every prompt.
    spec: &'a Spec,
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

    pub fn new(store: &'a Store, key: &'a Key, spec: &'a Spec, settings: Settings) -> Self {
        Self {
            store,
            key,
            spec,
            settings,
            sent: HashSet::new(),
            log: Vec::new(),
        }
    }

    /// The connected channel's spec.
    pub fn spec(&self) -> &'a Spec {
        self.spec
    }

    /// One round, as the two halves of `listen` take turns in tests: send
    /// what is new and expire what is old ([`Self::send_round`]), then wait
    /// up to `wait` for replies and answer them ([`Self::answer`]), then
    /// beat. `now` reads the clock.
    #[cfg(test)]
    pub fn step(
        &mut self,
        channel: &mut dyn Channel,
        records: &mut dyn Records,
        wait: std::time::Duration,
        now: &dyn Fn() -> i64,
    ) -> Result<()> {
        self.send_round(channel, records, now)?;
        let replies = channel.poll(wait)?;
        self.answer(channel, records, &replies, now)?;
        self.beat(now());
        Ok(())
    }

    /// Refused once another channel is connected than the one listened on.
    fn check_channel(&self) -> Result<()> {
        if self.settings.channel != self.spec.name {
            anyhow::bail!(
                "the connected channel is now {}, not {}",
                crate::render::clean(&self.settings.channel),
                self.spec.name
            );
        }
        Ok(())
    }

    /// Send every request not sent yet, expire what is old and tell the
    /// approvers of approvals refused after all: the local half of `listen`.
    pub fn send_round(
        &mut self,
        channel: &mut dyn Channel,
        records: &mut dyn Records,
        now: &dyn Fn() -> i64,
    ) -> Result<()> {
        self.check_channel()?;
        self.sweep(channel, records, now())
    }

    /// Answer `replies`, one poll's: the channel half of `listen`. Every one
    /// is handled (one that fails is logged, and the next is still
    /// answered); only then does the channel move past them, so none is
    /// dropped unread.
    pub fn answer(
        &mut self,
        channel: &mut dyn Channel,
        records: &mut dyn Records,
        replies: &[Reply],
        now: &dyn Fn() -> i64,
    ) -> Result<()> {
        self.check_channel()?;
        for reply in replies {
            if let Err(error) = self.reply(channel, records, reply, now()) {
                self.log.push(format!(
                    "a reply from {} could not be handled: {error:#}",
                    crate::render::clean(&reply.from)
                ));
            }
        }
        channel.handled();
        Ok(())
    }

    /// The beat that lets a guard wait for an answer (ADR-093). One not
    /// written only means the guard does not wait, as with no listener.
    pub fn beat(&self, now_ms: i64) {
        let _ = super::live::beat(self.store, self.key, self.spec.name, now_ms);
    }

    fn sweep(
        &mut self,
        channel: &mut dyn Channel,
        records: &mut dyn Records,
        now_ms: i64,
    ) -> Result<()> {
        self.store.sweep_used(now_ms);
        self.tell_refused(channel, records);
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

    /// Tell the approvers of every approval the guard used for a call it then
    /// refused ([`super::refused`]), and record it; each note once.
    fn tell_refused(&mut self, channel: &mut dyn Channel, records: &mut dyn Records) {
        for (id, note) in self.store.refused() {
            self.store.forget_refused(&id);
            let Some(note) = note.filter(|n| n.verified(self.key)) else {
                self.log
                    .push(format!("removed refusal note {id}: bad signature"));
                continue;
            };
            let what = format!(
                "request {} was approved, but the call was refused: {}",
                note.request.code(),
                note.reason
            );
            let row = row(&note.request, REFUSED_RULE, Verdict::Deny, what.clone());
            if let Err(error) = records.record(row) {
                self.log
                    .push(format!("could not record that {what}: {error:#}"));
            }
            for approver in self.locals() {
                let _ = channel.notify(&approver, &format!("OpenMoat: {what}. Nothing ran."));
            }
            self.log.push(what);
        }
    }

    /// The approvers of this channel, by their id on it.
    fn locals(&self) -> Vec<String> {
        self.settings
            .approvers
            .iter()
            .filter_map(|a| local_id(self.spec.name, a))
            .map(str::to_owned)
            .collect()
    }

    fn send(&mut self, channel: &mut dyn Channel, request: &Request) {
        let prompt = super::prompt::prompt(self.key, request, &self.spec.capabilities);
        let mut reached = 0;
        for approver in self.locals() {
            match channel.send(&approver, &prompt) {
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
                for approver in self.locals() {
                    let _ = channel.notify(
                        &approver,
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
        // Qualified here, with the registered name: a channel cannot give an
        // id of another channel.
        let who = approver_id(self.spec.name, &reply.from);
        let from = crate::render::clean(&who).into_owned();
        let name = crate::render::clean(&reply.name).into_owned();
        // Where prompts carry buttons only a press answers; elsewhere the
        // reply code sent back as a message does, verified the same way.
        let data = if self.spec.capabilities.uses_buttons() {
            reply.button.as_deref()
        } else {
            reply
                .text
                .as_deref()
                .map(str::trim)
                .filter(|t| answer::parse_button(t).is_some())
        };
        let Some(data) = data else {
            if self.settings.approver(&who) {
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
        if !self.settings.approver(&who) {
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
        let answer = Answer::signed(self.key, &request, (verdict, &who, self.spec.name), now_ms)?;
        let (rule, core) = match verdict {
            answer::Verdict::Approve => (APPROVED_ROW_RULE, Verdict::Allow),
            answer::Verdict::Deny => (DENIED_RULE, Verdict::Deny),
        };
        // An answer that cannot be recorded does not stand, and no guard
        // sees it before its row is written: a guard waiting for it would
        // otherwise run the call while the row may still fail.
        let recorded = self.store.put_answer_once_recorded(&answer, || {
            records.record(row(
                &request,
                rule,
                core,
                format!(
                    "request {} {} by {from} on {}",
                    request.code(),
                    verdict.word(),
                    self.spec.name
                ),
            ))
        });
        match recorded {
            Ok(true) => {}
            Ok(false) => {
                self.log.push(format!(
                    "request {} was answered meanwhile by another listener; this answer was \
                     recorded but not applied",
                    request.code()
                ));
                let _ = channel.settle(reply, "This request was already answered.");
                return Ok(());
            }
            Err(error) => {
                let _ = channel.settle(reply, "Not recorded, so not applied; try again.");
                return Err(error);
            }
        }
        self.log.push(format!(
            "request {} {} by {name} ({from})",
            request.code(),
            verdict.word()
        ));
        let text = match verdict {
            answer::Verdict::Approve => {
                "Approved: the call runs once, now if the agent is still waiting for the answer, \
                 or when it tries the call again before the request expires."
            }
            answer::Verdict::Deny => "Denied: the call stays blocked until the request expires.",
        };
        let _ = channel.settle(reply, text);
        Ok(())
    }
}
