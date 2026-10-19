//! How each host sends one tool call and reads the hook's reply. The host
//! adapters (`openmoat_hosts::bench`) know each host; this module only maps
//! the hook process's end to what they read.

use openmoat_core::Verdict;
use openmoat_hosts::Host;
use openmoat_hosts::bench::Exit;
pub use openmoat_hosts::bench::{Answer, Place};

use super::Call;
use super::hook::Reply;

/// The answer a host must end up with for `verdict` on `call` ([`Host::seen`]).
pub fn seen(host: Host, call: &Call, verdict: Verdict) -> Answer {
    host.seen(call, verdict)
}

/// Read the hook's reply the way `host` does. A hook that timed out or could
/// not start is a failure on every host.
pub fn classify(host: Host, call: &Call, reply: &Reply) -> Answer {
    let Reply::Exited {
        code,
        stdout,
        stderr,
    } = reply
    else {
        return Answer::Error;
    };
    host.read_reply(
        call,
        &Exit {
            code: *code,
            stdout,
            stderr,
        },
    )
}

/// What `host` does when its hook is missing, crashes or times out.
pub fn failure(host: Host) -> &'static str {
    host.spec().on_hook_failure
}

/// The hook payload for `call`, or `None` when this host has no tool for it.
pub fn payload(host: Host, call: &Call, at: &Place<'_>) -> Option<String> {
    host.bench_payload(call, at)
}
