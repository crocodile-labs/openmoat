//! The unlisted setting of ADR-062 step 0, the proof of concept of request
//! rules: temporary, not a feature, and not policy schema.
//!
//! `OPENMOAT_ADR062_POC=1` in the environment of `openmoat run` (and of
//! `openmoat proxy ca init`, so that the CA covers the host) adds one fixed
//! rule: `api.github.com` is terminated like the host of a `tls: terminate`
//! secret (ADR-043), and a `POST /gists` to it, or to a path under it, is
//! refused by the proxy with rule `proxy-request-rule` and an audit row,
//! before anything is sent. Every other request to the host passes as it was.
//! The setting only narrows: the host must still be allowed by the policy,
//! and without a pinned CA that covers it `openmoat run` does not start.
//! `scripts/ci/adr062-poc.py` measures it; ADR-062 step 1 onwards replaces it
//! with the `requests:` policy section.

use std::ffi::OsStr;

use anyhow::{Context as _, Result};
use openmoat_proxy::Requests;

/// The variable that turns the proof of concept on, with the value `1`.
pub const ENV: &str = "OPENMOAT_ADR062_POC";

/// The one host the proof of concept terminates.
const HOST: &str = "api.github.com";

/// What it refuses there: creating a gist, and anything posted under one
/// (a comment, a fork), in any letter case, with or without a trailing slash.
const DENY: &[&str] = &["POST /gists", "POST /gists/**"];

/// Whether the setting is on in this process's environment.
pub fn enabled() -> bool {
    is_on(std::env::var_os(ENV).as_deref())
}

fn is_on(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
}

/// The hosts the setting terminates: none when it is off.
pub fn hosts() -> Vec<String> {
    hosts_for(enabled())
}

fn hosts_for(on: bool) -> Vec<String> {
    if on {
        vec![HOST.to_owned()]
    } else {
        Vec::new()
    }
}

/// The request rules `openmoat run`'s proxy holds: none when it is off.
pub fn requests() -> Result<Requests> {
    requests_for(enabled())
}

fn requests_for(on: bool) -> Result<Requests> {
    if !on {
        return Ok(Requests::default());
    }
    Requests::default()
        .deny(HOST, DENY)
        .context("the ADR-062 proof-of-concept rule")
}

/// Said before the agent starts while the setting is on.
pub fn notice() -> Option<String> {
    enabled().then(|| {
        format!(
            "moat run: {ENV}=1: HTTPS to {HOST} is terminated and {} refused there; a temporary \
             proof of concept (ADR-062 step 0), not a feature",
            DENY.join(" and ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_value_1_turns_it_on() {
        assert!(is_on(Some(OsStr::new("1"))));
        for value in [None, Some(""), Some("0"), Some("true"), Some("1 ")] {
            assert!(!is_on(value.map(OsStr::new)), "{value:?}");
        }
    }

    #[test]
    fn off_it_adds_no_host_and_no_rule() {
        assert_eq!(hosts_for(false), Vec::<String>::new());
        assert_eq!(requests_for(false).unwrap().hosts().count(), 0);
    }

    #[test]
    fn on_it_terminates_the_one_host_its_rule_names() {
        assert_eq!(hosts_for(true), [HOST]);
        let rules: Vec<String> = requests_for(true)
            .unwrap()
            .hosts()
            .map(str::to_owned)
            .collect();
        assert_eq!(rules, hosts_for(true));
    }
}
