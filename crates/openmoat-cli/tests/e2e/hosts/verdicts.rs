//! Every host's verdict shapes: what reaches the host for a secret read, an
//! allowed call, a tool OpenMoat does not govern, arguments that cannot be
//! checked and an ask, in the host's own reply format.

use openmoat_core::Verdict;
use openmoat_hosts::Host;

use super::{assert_reason, dir_of, guard, row, verdict};
use crate::common::{DENY, OK, Sandbox, stdout, text};

#[test]
fn a_secret_read_is_denied_in_the_hosts_format() {
    for host in Host::ALL {
        let row = row(host.id());
        let Some(read) = row.secret_read else {
            continue;
        };
        let sb = Sandbox::installed(&[&dir_of(host)]);
        let out = guard(&row, &sb, &read(&sb));
        assert_eq!(out.status.code(), Some(DENY), "{}: {}", row.id, text(&out));
        assert_eq!(verdict(&row, &out), "deny", "{}: {}", row.id, text(&out));
        assert_reason(&row, &out, "secrets-paths", "secret read");
    }
}

#[test]
fn a_benign_call_is_allowed() {
    for host in Host::ALL {
        let row = row(host.id());
        let Some(benign) = row.benign else { continue };
        let sb = Sandbox::installed(&[&dir_of(host)]);
        let out = guard(&row, &sb, &benign(&sb));
        assert_eq!(out.status.code(), Some(OK), "{}: {}", row.id, text(&out));
        assert_eq!(verdict(&row, &out), "allow", "{}: {}", row.id, text(&out));
    }
}

/// A tool OpenMoat does not govern is left to the host (`Asks::ungoverned`):
/// no output where the host's hooks have a "no decision", else an `allow`
/// that names the rule.
#[test]
fn an_ungoverned_tool_is_left_to_the_host() {
    for host in Host::ALL {
        let row = row(host.id());
        if row.ungoverned.is_empty() {
            continue;
        }
        let sb = Sandbox::installed(&[&dir_of(host)]);
        let ungoverned = host.spec().asks.ungoverned;
        for payload in row.ungoverned {
            let out = guard(&row, &sb, &payload(&sb));
            assert_eq!(out.status.code(), Some(OK), "{}: {}", row.id, text(&out));
            if ungoverned == Verdict::Defer {
                assert_eq!(stdout(&out).trim(), "", "{}: defer prints nothing", row.id);
            } else {
                assert_eq!(ungoverned, Verdict::Allow, "{}", row.id);
                assert_eq!(verdict(&row, &out), "allow", "{}: {}", row.id, text(&out));
                assert_reason(&row, &out, "ungoverned", "ungoverned tool");
            }
        }
    }
}

/// Arguments the hook cannot check are denied, whatever the tool's name.
#[test]
fn arguments_that_cannot_be_checked_are_denied() {
    for host in Host::ALL {
        let row = row(host.id());
        let Some((payload, says)) = row.malformed else {
            continue;
        };
        let sb = Sandbox::installed(&[&dir_of(host)]);
        let out = guard(&row, &sb, &payload(&sb));
        assert_eq!(out.status.code(), Some(DENY), "{}: {}", row.id, text(&out));
        assert_eq!(verdict(&row, &out), "deny", "{}: {}", row.id, text(&out));
        if let Some(says) = says {
            assert_reason(&row, &out, says, "malformed arguments");
        }
    }
}

/// Where the host puts a question to the person (`Asks::on_pre_tool_use`), an
/// `ask` reaches it as one; where it cannot, as a deny that says how to approve.
#[test]
fn an_ask_reaches_the_host_as_its_spec_says() {
    for host in Host::ALL {
        let row = row(host.id());
        let Some(ask) = row.ask else { continue };
        let sb = Sandbox::installed_asking(&[&dir_of(host)]);
        let out = guard(&row, &sb, &ask(&sb));
        if host.spec().asks.on_pre_tool_use.is_none() {
            assert_eq!(out.status.code(), Some(OK), "{}: {}", row.id, text(&out));
            assert_eq!(verdict(&row, &out), "ask", "{}: {}", row.id, text(&out));
        } else {
            assert_eq!(out.status.code(), Some(DENY), "{}: {}", row.id, text(&out));
            assert_eq!(verdict(&row, &out), "deny", "{}: {}", row.id, text(&out));
            assert_reason(&row, &out, "openmoat allow --last", "ask");
        }
    }
}
