//! The proxy's answer to a tool's local helper (ADR-118), on the proxy's port.
//!
//! `openmoat credential`, started by git or the AWS CLI inside the sandbox,
//! connects to the port the agent's proxy variables name and sends one line:
//!
//! ```text
//! MOAT-HELPER/1 <tool> <secret-id> <host or -> <base64 of session:token>
//! ```
//!
//! with the session credential from those variables, so only the session's
//! processes can ask. The answer is one line, `OK <user or -> <value>` or
//! `NO <reason>`. The broker decides ([`Broker::hand_out`]); the decision is
//! recorded before the value is sent, and a row that cannot be written
//! sends nothing.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::time::Instant;

use openmoat_core::rule_id::{PROXY_HELPER, PROXY_SESSION};
use openmoat_core::{Decision, Verdict};
use zeroize::Zeroizing;

use super::Proxy;
use crate::audit::Connection;
use crate::broker::Broker;

/// What a helper's request starts with; no HTTP method does.
pub const HELPER_PREFIX: &[u8] = b"MOAT-HELPER/1 ";

/// The longest request line read.
const MAX_LINE: usize = 4096;

/// The request line a helper sends: `tool` asks for secret `id` for `host`
/// (`None` for a helper that names no host), with the session's proxy
/// credential `basic` (base64 of `session:token`).
#[must_use]
pub fn helper_request(tool: &str, id: &str, host: Option<&str>, basic: &str) -> Zeroizing<Vec<u8>> {
    let line = format!(
        "{}{tool} {id} {} {basic}\n",
        String::from_utf8_lossy(HELPER_PREFIX),
        host.unwrap_or("-")
    );
    Zeroizing::new(line.into_bytes())
}

/// The fields of one request line.
struct Asked<'a> {
    tool: &'a str,
    id: &'a str,
    host: Option<&'a str>,
    basic: &'a str,
}

fn parse(line: &str) -> Option<Asked<'_>> {
    let rest = line.strip_prefix(std::str::from_utf8(HELPER_PREFIX).ok()?)?;
    let mut words = rest.trim_end_matches(['\r', '\n']).split(' ');
    let asked = Asked {
        tool: words.next().filter(|w| !w.is_empty())?,
        id: words.next().filter(|w| !w.is_empty())?,
        host: words.next().filter(|w| *w != "-"),
        basic: words.next().filter(|w| !w.is_empty())?,
    };
    words.next().is_none().then_some(asked)
}

/// The line the helper sent, up to its newline; `None` for one too long,
/// cut short or not UTF-8.
fn read_line(client: &TcpStream) -> Option<Zeroizing<String>> {
    let mut line = Zeroizing::new(Vec::with_capacity(256));
    let mut byte = [0u8; 1];
    let mut reader = client;
    while line.len() < MAX_LINE {
        match reader.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => {
                return String::from_utf8(line.to_vec()).ok().map(Zeroizing::new);
            }
            Ok(1) => line.push(byte[0]),
            _ => return None,
        }
    }
    None
}

impl Proxy<'_> {
    /// Answer one helper connection.
    pub(super) fn helper(&self, client: &TcpStream, started: Instant) {
        let deny = |rule: &str, why: String| Decision::single(Verdict::Deny, rule, why);
        let Some(line) = read_line(client) else {
            let decision = deny(
                PROXY_HELPER,
                "a helper request that could not be read".into(),
            );
            self.helper_row(None, None, &decision, started);
            answer(client, None, &decision);
            return;
        };
        let Some(asked) = parse(&line) else {
            let decision = deny(
                PROXY_HELPER,
                "a helper request that is not well formed".into(),
            );
            self.helper_row(None, None, &decision, started);
            answer(client, None, &decision);
            return;
        };
        // Only the session's own processes, which hold its proxy credential.
        let session = self
            .sessions
            .map(|sessions| sessions.admit(&[format!("Basic {}", asked.basic)]));
        let session = match session {
            Some(Ok(admitted)) => admitted.session,
            Some(Err(error)) => {
                let decision = deny(PROXY_SESSION, format!("helper request refused: {error}"));
                self.helper_row(None, asked.host, &decision, started);
                answer(client, None, &decision);
                return;
            }
            None => {
                let decision = deny(
                    PROXY_HELPER,
                    "this proxy serves no sessions, so it hands nothing to helpers".into(),
                );
                self.helper_row(None, asked.host, &decision, started);
                answer(client, None, &decision);
                return;
            }
        };
        let broker: &Broker = self.broker;
        match broker.hand_out(asked.tool, asked.id, asked.host) {
            Ok(out) => {
                if self.helper_row(Some(&session), Some(out.host), &out.decision, started) {
                    answer(client, Some((out.username, &out.value)), &out.decision);
                } else {
                    let decision = deny(PROXY_HELPER, "the audit log is unavailable".into());
                    answer(client, None, &decision);
                }
            }
            Err(decision) => {
                self.helper_row(Some(&session), asked.host, &decision, started);
                answer(client, None, &decision);
            }
        }
    }

    fn helper_row(
        &self,
        session: Option<&str>,
        host: Option<&str>,
        decision: &Decision,
        started: Instant,
    ) -> bool {
        self.write_row(&Connection {
            session,
            method: Some("HELPER"),
            destination: host.map(|h| (h, 443)),
            terminated: false,
            decision,
            latency_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        })
    }
}

/// Write the answer: `OK <user or -> <value>` when `given`, else `NO <reason>`.
fn answer(mut client: &TcpStream, given: Option<(Option<&str>, &str)>, decision: &Decision) {
    let line = if let Some((user, value)) = given {
        Zeroizing::new(format!("OK {} {value}\n", user.unwrap_or("-")))
    } else {
        let why = decision.reasons.first().map_or("refused", String::as_str);
        Zeroizing::new(format!("NO {}\n", why.replace(['\r', '\n'], " ")))
    };
    // Nothing more to do for a helper that went away: the row is written.
    let _ = client
        .write_all(line.as_bytes())
        .and_then(|()| client.flush());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_line_round_trips() {
        let line = helper_request("git", "gh-git", Some("github.com"), "c2VzczpzZWNyZXQ=");
        let text = String::from_utf8(line.to_vec()).unwrap();
        assert_eq!(
            text,
            "MOAT-HELPER/1 git gh-git github.com c2VzczpzZWNyZXQ=\n"
        );
        let asked = parse(&text).unwrap();
        assert_eq!(
            (asked.tool, asked.id, asked.host),
            ("git", "gh-git", Some("github.com"))
        );
        assert_eq!(asked.basic, "c2VzczpzZWNyZXQ=");
        let aws = String::from_utf8(helper_request("aws", "s3", None, "eA==").to_vec()).unwrap();
        assert_eq!(parse(&aws).unwrap().host, None);
    }

    #[test]
    fn a_malformed_line_is_not_read() {
        for bad in [
            "GET / HTTP/1.1\n",
            "MOAT-HELPER/1 git\n",
            "MOAT-HELPER/1 git id host\n",
            "MOAT-HELPER/1 git id host cred extra\n",
            "MOAT-HELPER/1  id host cred\n",
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
    }
}
