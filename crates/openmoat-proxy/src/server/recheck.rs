//! Session taint, when a connection opens and again while it is open.
//!
//! A connection is decided with its session's taint when it opens. The
//! session can read secret material later, while a tunnel opened before stays
//! open (a tunnel may carry many requests). So the relay asks again every
//! [`Limits::taint_recheck`](super::Limits::taint_recheck), with the taint
//! looked up at most that long ago, and a connection the taint now refuses is
//! recorded and closed.

use std::time::Duration;

use openmoat_core::{Decision, Verdict};

use super::{Proxy, Turn};
use crate::decide;
use crate::request::Request;
use crate::session::RULE_SESSION;

impl Proxy<'_> {
    /// The refusal the connection's session taint calls for, if any. A
    /// session whose history cannot be read is refused (fail closed). With
    /// `max_age`, a taint looked up that recently is used again.
    pub(super) fn tainted(
        &self,
        turn: Turn<'_>,
        request: &Request,
        max_age: Option<Duration>,
    ) -> Option<Decision> {
        let (Some(sessions), Some(session)) = (self.sessions, turn.session) else {
            return None;
        };
        let taint = match max_age {
            Some(age) => sessions.taint_within(session, age),
            None => sessions.taint(session),
        };
        match taint {
            Ok(taint) => decide::tainted(self.policy, request.host(), request.port(), &taint),
            Err(why) => Some(Decision::single(
                Verdict::Deny,
                RULE_SESSION,
                format!("the session's history cannot be read, so its taint is unknown: {why}"),
            )),
        }
    }

    /// Whether an open connection may stay open under its session's taint as
    /// it is now. When it may not, the refusal is recorded (the allow row is
    /// already there) and the caller closes the connection, recorded or not.
    pub(super) fn still_untainted(&self, turn: Turn<'_>, request: &Request) -> bool {
        let Some(mut refusal) = self.tainted(turn, request, Some(self.limits.taint_recheck)) else {
            return true;
        };
        refusal.reasons.push(
            "the connection was opened before the session's taint grew; it is closed".to_owned(),
        );
        self.record(turn, Some(request), &refusal);
        false
    }
}
