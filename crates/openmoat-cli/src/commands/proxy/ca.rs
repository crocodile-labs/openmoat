//! `openmoat proxy ca init`: make the certificate authority `openmoat run`'s
//! proxy terminates TLS with, for the secrets that say `tls: terminate`
//! (ADR-043).
//!
//! Person-only, like the other commands that change what OpenMoat trusts: it
//! refuses without a terminal or with an agent among its parents, and over a
//! policy lock that shows drift. It shows what the CA covers and asks before
//! it writes; then it pins both files. Running it again makes a new CA, which
//! is how the CA is rotated and how it comes to cover new hosts.

use std::io::Write as _;

use anyhow::{Result, bail};
use openmoat_core::Policy;

use crate::exit::Code;
use crate::home::{Home, write_private};
use crate::integrity::{self, HookPins};
use crate::proxy_ca::{self, cert_path, key_path, terminated_hosts, valid_until};
use crate::render::Deferred;

pub fn init() -> Result<Code> {
    crate::terminal::refuse_agent("openmoat proxy ca init")?;
    if !crate::terminal::interactive() {
        bail!(
            "`openmoat proxy ca init` must be run by a person in a terminal, not from a hook or \
             script: the CA decides which HTTPS the proxy may read"
        );
    }
    let home = Home::locate()?;
    home.require_exists()?;
    integrity::refuse_drift(&home, "make the proxy CA")?;
    let policy = home.load_policy()?;
    let mut out = Deferred::default();
    make(&home, &policy, &mut out)?;
    out.finish()?;
    Ok(Code::Ok)
}

/// Say what a CA for `policy`'s terminated hosts would cover, ask, then write
/// and pin it. `false` when the person said no. The caller has made sure a
/// person runs it.
pub(in crate::commands) fn make(home: &Home, policy: &Policy, out: &mut Deferred) -> Result<bool> {
    let hosts = terminated_hosts(policy);
    if hosts.is_empty() {
        bail!(
            "no brokered secret says `tls: terminate`, so there is nothing for a CA to cover; \
             `openmoat secret add <id> --tls-terminate` adds one"
        );
    }
    let (cert, key) = (cert_path(home), key_path(home));
    writeln!(
        out,
        "The proxy CA lets `openmoat run` read HTTPS to {} and put brokered secrets in it.",
        hosts.join(", ")
    )?;
    writeln!(
        out,
        "  It can sign for those hosts and names under them only, for {} days.",
        openmoat_proxy::CA_VALID_DAYS
    )?;
    writeln!(
        out,
        "  Only the commands `openmoat run` starts trust it; no trust store on this machine changes."
    )?;
    writeln!(
        out,
        "  Its key goes to {} (owner-only), which no OpenMoat sandbox lets the agent read,\n  \
         and both files are pinned in the policy lock.",
        key.display()
    )?;
    let old = std::fs::read_to_string(&cert).ok();
    if let Some(until) = old.as_deref().and_then(valid_until) {
        writeln!(
            out,
            "  It replaces the CA valid until {until}; an `openmoat run` already running keeps that one."
        )?;
    }
    if !super::super::edit::confirm(out, "Make it? [y/N] ")? {
        writeln!(out, "no CA was made")?;
        return Ok(false);
    }
    let ca = openmoat_proxy::new_ca(&hosts)?;
    write_private(&key, ca.key_pem.as_bytes())?;
    write_private(
        &cert,
        proxy_ca::cert_text(&ca, &hosts, crate::time::now_ms()).as_bytes(),
    )?;
    let lock = integrity::repin_with(
        home,
        &crate::install::hook_binary()?,
        HookPins::Keep,
        &proxy_ca::files(home),
        &[],
    )?;
    writeln!(
        out,
        "✔ proxy CA made for {} ({}); the policy lock pins {} files",
        hosts.join(", "),
        cert.display(),
        lock.entries.len()
    )?;
    writeln!(out, "  start a new `openmoat run` to use it")?;
    Ok(true)
}
