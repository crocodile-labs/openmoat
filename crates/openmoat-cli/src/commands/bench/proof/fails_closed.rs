//! Whether a failed hook blocks the call. OpenMoat's side is exercised: a
//! payload `openmoat guard` cannot read must come back as a deny the host
//! reads as one (ADR-004, ADR-015). The host's side, what it does when the
//! hook crashes or times out, needs the real host: the report lists what
//! each host's documentation says and marks it not tested.

use openmoat_hosts::Host;

use super::super::Call;
use super::super::Target;
use super::super::hook::{self, Scratch};
use super::super::hosts::{self, Answer};
use super::status::Evidence;

/// The id the report names to reproduce the guard's check.
pub const PROBE: &str = "hook-malformed-payload";

/// A payload cut off half way, as a host that crashed while writing it sends.
const MALFORMED: &str = "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":";

/// What the guard's row checks.
pub const GUARD_CHECK: &str =
    "`openmoat guard` answers a payload it cannot read with a deny the host reads as deny";

/// What the hosts' row checks.
pub const HOST_CHECK: &str = "the host blocks the call when its hook crashes or times out";

/// The guard's answer to [`MALFORMED`] on each of `hosts`, as the host reads it.
pub fn guard(target: &Target, scratch: &Scratch, hosts: &[Host]) -> Vec<Evidence> {
    let call = Call::Shell("true".to_owned());
    hosts
        .iter()
        .map(|&host| {
            let reply = hook::send(&mut target.command(scratch, host), MALFORMED);
            match hosts::classify(host, &call, &reply) {
                Answer::Deny => Evidence::Held,
                other => Evidence::Broken(format!(
                    "{}: a payload the guard cannot read is read as {} ({})",
                    host.id(),
                    other.word(),
                    reply.cause()
                )),
            }
        })
        .collect()
}

/// The hosts' own handling of a failed hook: documented, not measured here.
pub fn hosts(hosts: &[Host]) -> Vec<Evidence> {
    hosts
        .iter()
        .map(|&host| {
            Evidence::Unexercised(format!(
                "{}: needs the real host; THREAT_MODEL.md §5 says: {}",
                host.id(),
                hosts::failure(host)
            ))
        })
        .collect()
}
