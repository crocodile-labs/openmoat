//! Reading the values of the policy's brokered secrets for `moat proxy`
//! (ADR-020).
//!
//! A value goes straight into a zeroed-on-drop buffer and from there into the
//! proxy's [`Broker`]. Errors name the secret and where it was looked for,
//! never what was read.

mod command;
mod keychain;
mod program;
mod refresh;
#[cfg(all(test, unix))]
mod stand;

use anyhow::{Context as _, Result, bail};
use openmoat_audit::KnownSecrets;
use openmoat_core::{Policy, Secret, SecretSource};
use openmoat_proxy::Broker;
use zeroize::Zeroizing;

pub use refresh::{Masks, Refresher};

/// A broker holding the value of every secret of `policy`, and what renews
/// those from `command` sources (ADR-087), which also holds every value for
/// the audit log to mask. `home` is the user's home directory in slash form,
/// for `~/` sources. Any secret that cannot be read stops the proxy from
/// starting.
pub fn broker(policy: &Policy, home: &str) -> Result<(Broker, Refresher)> {
    let mut held = Vec::with_capacity(policy.secrets.len());
    let mut fixed = Vec::new();
    let mut started = Vec::new();
    for secret in &policy.secrets {
        let reading = || format!("reading secret `{}`", secret.id);
        let value = match &secret.source {
            SecretSource::Command(source) => {
                let program = command::Program::prepare(&secret.id, source, policy, home)
                    .with_context(reading)?;
                let answer = program.fetch().with_context(reading)?;
                let until = std::time::Instant::now() + answer.lifetime;
                started.push((program, until, answer.value.clone()));
                answer.value
            }
            other => {
                let value = read(other, home).with_context(reading)?;
                fixed.push(value.clone());
                value
            }
        };
        held.push((secret.clone(), value));
    }
    let broker = Broker::new(held)?;
    let mut programs = Vec::with_capacity(started.len());
    for (program, until, value) in started {
        let rotation = broker
            .rotation(program.id())
            .context("a brokered secret went missing")?;
        // Counted from when the program answered, not from now.
        rotation.renew(
            value.clone(),
            until.saturating_duration_since(std::time::Instant::now()),
        )?;
        programs.push((program, rotation, value));
    }
    Ok((broker, Refresher::new(programs, fixed)))
}

/// The values of `secrets` that `moat guard` masks in the audit log: those with
/// a file or environment source that this process can read. A keychain read
/// would start a program on every tool call, and a `command` source runs in
/// `openmoat proxy` only; a secret that cannot be read is skipped, since the
/// proxy, which needs it, refuses to start without it.
pub fn known(secrets: &[Secret], home: &str) -> Result<KnownSecrets> {
    let values = known_values(secrets, home);
    Ok(KnownSecrets::new(values.iter().map(|v| v.as_str()))?)
}

/// The values [`known`] masks, for a caller that masks more besides (audit
/// delivery, ADR-081).
pub fn known_values(secrets: &[Secret], home: &str) -> Vec<Zeroizing<String>> {
    secrets
        .iter()
        .filter(|s| !matches!(s.source, SecretSource::Keychain { .. }) && !s.source.proxy_only())
        .filter_map(|s| read(&s.source, home).ok())
        .collect()
}

/// The value at `source`, without its trailing newline; also the keys and
/// tokens audit delivery sends with (ADR-081). A `command` source is refused:
/// only `openmoat proxy` runs it ([`broker`]).
pub fn read(source: &SecretSource, home: &str) -> Result<Zeroizing<String>> {
    let mut value = match source {
        SecretSource::File(path) => {
            let path = match path.strip_prefix("~/") {
                Some(rest) => format!("{home}/{rest}"),
                None => path.clone(),
            };
            Zeroizing::new(std::fs::read_to_string(&path).with_context(|| path.clone())?)
        }
        // `VarError::NotUnicode` would print the value, so it is not passed on.
        SecretSource::Env(name) => Zeroizing::new(
            std::env::var(name)
                .ok()
                .with_context(|| format!("environment variable {name} is not set or not UTF-8"))?,
        ),
        SecretSource::Keychain { service, account } => keychain::read(service, account)?,
        SecretSource::Command(source) => bail!(
            "`command` source {} is run by `openmoat proxy` only",
            source.program()
        ),
    };
    let end = value.trim_end_matches(['\r', '\n']).len();
    value.truncate(end);
    Ok(value)
}

#[cfg(test)]
mod tests;
