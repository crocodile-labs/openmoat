//! A call under `moat run`: decided by the run's process outside the sandbox,
//! its answer printed as it came.

use std::io::{self, Write as _};
use std::time::Instant;

use anyhow::Result;
use openmoat_hosts::{HookEvent, Host};

use super::{GATE, deadline, entry, kernel_error, read_stdin, respond};
use crate::exit::Code;
use crate::guard_relay;
use crate::hangs::{self, Phase};

/// Under `moat run`: the call goes to the run's process outside the sandbox,
/// and its answer is printed as it came. Whatever fails denies here, in the
/// format the payload's hook expects; nothing is recorded from in here.
pub(super) fn relayed(
    installed_for: Host,
    endpoint: Result<guard_relay::Endpoint>,
    started: Instant,
) -> Code {
    hangs::enter(Phase::Stdin);
    let payload = match read_stdin(installed_for) {
        Ok(payload) => payload,
        Err(error) => {
            return respond(installed_for, &HookEvent::default(), &kernel_error(&error));
        }
    };
    let caller_set = entry::caller_set();
    let host = installed_for.sender(&payload, caller_set);
    let event = host.event_of_as(&payload, entry::event());
    deadline::saw(host, &event);
    let budget = deadline::of(installed_for).saturating_sub(started.elapsed());
    hangs::enter(Phase::Relay);
    let sent = (caller_set, entry::event());
    match endpoint.and_then(|e| e.decide(installed_for, &payload, sent, budget)) {
        Ok(reply) => {
            hangs::enter(Phase::Answer);
            relay_once(&reply)
        }
        Err(error) => {
            let error = error.context("`openmoat run` did not decide this call");
            respond(host, &event, &kernel_error(&error))
        }
    }
}

/// Print `reply` as the guard outside the sandbox wrote it, unless the
/// deadline's deny came first.
fn relay_once(reply: &guard_relay::Reply) -> Code {
    GATE.once(|| write_reply(reply)).unwrap_or(Code::Deny)
}

fn write_reply(reply: &guard_relay::Reply) -> Code {
    let mut stdout = io::stdout().lock();
    let written = stdout
        .write_all(&reply.stdout)
        .and_then(|()| stdout.flush());
    let _ = io::stderr().lock().write_all(&reply.stderr);
    if let Err(error) = written {
        eprintln!("moat: could not write the hook response: {error}");
        return Code::Deny;
    }
    if reply.code == 0 {
        Code::Ok
    } else {
        Code::Deny
    }
}
