//! The certificate authority `openmoat run`'s proxy terminates TLS with, for
//! secrets that say `tls: terminate` (ADR-043).
//!
//! - It lives in OpenMoat's state directory, `proxy-ca/`: `ca.pem` (the
//!   certificate, which clients in the run trust) and `key.pem` (the key,
//!   owner-only). No sandbox OpenMoat writes lets the agent read that
//!   directory, and the default policy's `kernel-self` denies reading it.
//! - Only `openmoat proxy ca init`, a person at a terminal, writes the files,
//!   and pins both in the policy lock. Other re-pins keep the pins and never
//!   add them, as for the signing files (`integrity::signing_files`).
//! - `openmoat run` uses the CA only while both files are pinned and intact,
//!   and only when it signs leaves that verify today for every terminated host.

mod trust;

use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use openmoat_core::Policy;
use openmoat_proxy::{CA_VALID_DAYS, CaFiles, Roots, Tls};
use zeroize::Zeroizing;

pub use self::trust::Trust;
use crate::home::Home;
use crate::integrity::Lock;

/// Days before the CA expires that `openmoat run` starts saying so.
const EXPIRY_NOTICE_DAYS: i64 = 30;
const MS_PER_DAY: i64 = 86_400_000;

/// The CA's certificate.
pub fn cert_path(home: &Home) -> PathBuf {
    home.root().join("proxy-ca").join("ca.pem")
}

/// The CA's private key.
pub fn key_path(home: &Home) -> PathBuf {
    home.root().join("proxy-ca").join("key.pem")
}

/// The files `openmoat proxy ca init` pins.
pub fn files(home: &Home) -> Vec<PathBuf> {
    vec![cert_path(home), key_path(home)]
}

/// The hosts of `policy`'s secrets that say `tls: terminate`, sorted, once each.
pub fn terminated_hosts(policy: &Policy) -> Vec<String> {
    let mut hosts: Vec<String> = policy
        .secrets
        .iter()
        .filter(|s| s.terminates())
        .map(|s| s.host.clone())
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// `YYYY-MM-DD` of `ts_ms`, in UTC.
fn date(ts_ms: i64) -> String {
    crate::time::rfc3339(ts_ms)[..10].to_owned()
}

/// The text of `ca.pem`: what it is, for a person who opens it, then the
/// certificate. PEM readers skip text outside the block (RFC 7468 §2).
pub fn cert_text(ca: &CaFiles, hosts: &[String], now_ms: i64) -> String {
    format!(
        "# OpenMoat proxy CA, made by `openmoat proxy ca init` on {}\n\
         # valid until {}, and only for: {}\n\
         # trusted only by the commands `openmoat run` starts (ADR-043)\n{}",
        date(now_ms),
        date(now_ms + CA_VALID_DAYS * MS_PER_DAY),
        hosts.join(", "),
        ca.cert_pem
    )
}

/// The `valid until` date `cert_text` wrote, if the file has one.
pub fn valid_until(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|l| l.strip_prefix("# valid until "))
        .and_then(|rest| rest.get(..10))
}

/// The run's termination: the proxy's [`Tls`], and the certificate the
/// agent's clients trust.
pub struct Loaded {
    pub tls: Tls,
    pub cert_pem: String,
    /// Said on standard error before the agent starts: the CA expires soon.
    pub notice: Option<String>,
}

/// The CA for `policy`'s terminated hosts; `None` when no secret says
/// `tls: terminate`. Refused unless both files are pinned (the caller has
/// checked the lock for drift) and the CA covers every terminated host today.
pub fn load(home: &Home, policy: &Policy) -> Result<Option<Loaded>> {
    let hosts = terminated_hosts(policy);
    if hosts.is_empty() {
        return Ok(None);
    }
    let again = "run `openmoat proxy ca init` in a terminal";
    let lock = Lock::load(&home.lock_path())?;
    if !files(home).iter().all(|f| lock.pins(f) && f.is_file()) {
        bail!(
            "{} {} `tls: terminate`, but there is no pinned proxy CA yet: {again}",
            hosts.join(", "),
            if hosts.len() == 1 { "says" } else { "say" }
        );
    }
    let cert = std::fs::read_to_string(cert_path(home))
        .with_context(|| format!("reading {}", cert_path(home).display()))?;
    let key = Zeroizing::new(
        std::fs::read_to_string(key_path(home))
            .with_context(|| format!("reading {}", key_path(home).display()))?,
    );
    let tls = Tls::new(&cert, &key, &Roots::System, &hosts)
        .with_context(|| format!("the proxy CA cannot be used; {again}"))?;
    let now = crate::time::now_ms();
    let notice = valid_until(&cert)
        .filter(|until| *until <= date(now + EXPIRY_NOTICE_DAYS * MS_PER_DAY).as_str())
        .map(|until| {
            format!("moat run: the proxy CA expires on {until}; {again} to make a new one")
        });
    Ok(Some(Loaded {
        tls,
        cert_pem: cert,
        notice,
    }))
}

#[cfg(test)]
mod tests;
