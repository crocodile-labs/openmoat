//! Reading the values of the policy's brokered secrets for `moat proxy`
//! (ADR-020).
//!
//! A value goes straight into a zeroed-on-drop buffer and from there into the
//! proxy's [`Broker`]. Errors name the secret and where it was looked for,
//! never what was read.

mod keychain;

use anyhow::{Context as _, Result};
use openmoat_audit::KnownSecrets;
use openmoat_core::{Secret, SecretSource};
use openmoat_proxy::Broker;
use zeroize::Zeroizing;

/// A broker holding the value of every secret in `secrets`, and the same values
/// for the audit log to mask. `home` is the user's home directory in slash
/// form, for `~/` file sources. Any secret that cannot be read stops the proxy
/// from starting.
pub fn broker(secrets: &[Secret], home: &str) -> Result<(Broker, KnownSecrets)> {
    let mut held = Vec::with_capacity(secrets.len());
    for secret in secrets {
        let value = read(&secret.source, home)
            .with_context(|| format!("reading secret `{}`", secret.id))?;
        held.push((secret.clone(), value));
    }
    let known = KnownSecrets::new(held.iter().map(|(_, value)| value.as_str()))?;
    Ok((Broker::new(held)?, known))
}

/// The values of `secrets` that `moat guard` masks in the audit log: those with
/// a file or environment source that this process can read. A keychain read
/// would start a program on every tool call; a secret that cannot be read is
/// skipped, since the proxy, which needs it, refuses to start without it.
pub fn known(secrets: &[Secret], home: &str) -> Result<KnownSecrets> {
    let values: Vec<Zeroizing<String>> = secrets
        .iter()
        .filter(|s| !matches!(s.source, SecretSource::Keychain { .. }))
        .filter_map(|s| read(&s.source, home).ok())
        .collect();
    Ok(KnownSecrets::new(values.iter().map(|v| v.as_str()))?)
}

fn read(source: &SecretSource, home: &str) -> Result<Zeroizing<String>> {
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
    };
    let end = value.trim_end_matches(['\r', '\n']).len();
    value.truncate(end);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use openmoat_core::Policy;

    use super::*;

    /// Generated for the test; no real secret is used.
    const VALUE: &str = "fake-file-secret-5d0c1b";

    fn policy(source: &str) -> Policy {
        Policy::parse(&format!(
            "version: 1\nsecrets:\n  - id: t\n    host: a.test\n    header: X-Key\n    \
             source: {source}\n"
        ))
        .unwrap()
    }

    #[test]
    fn a_home_file_is_read_without_its_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".config")).unwrap();
        std::fs::write(dir.path().join(".config/t"), format!("{VALUE}\r\n")).unwrap();
        let home = dir.path().to_str().unwrap().replace('\\', "/");
        let p = policy("{ file: ~/.config/t }");
        // Kept, the `\r\n` would have been refused as control characters.
        let (b, known) = broker(&p.secrets, &home).unwrap();
        assert!(b.leak("b.test", VALUE.as_bytes()).is_some());
        assert_eq!(known.redact(&format!("x{VALUE}x")), "x[redacted]x");
        // The guard reads it too, and skips what it cannot read.
        let known = super::known(&p.secrets, &home).unwrap();
        assert_eq!(known.redact(VALUE), "[redacted]");
        let missing = super::known(&policy("{ file: ~/nope }").secrets, &home).unwrap();
        assert_eq!(missing.redact(VALUE), VALUE);
    }

    #[test]
    fn a_missing_or_unusable_source_names_the_secret_not_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_str().unwrap().replace('\\', "/");
        let missing = broker(&policy("{ file: ~/nope }").secrets, &home).unwrap_err();
        assert!(
            format!("{missing:#}").contains("reading secret `t`"),
            "{missing:#}"
        );
        std::fs::write(dir.path().join("bad"), "a\0b").unwrap();
        let bad = broker(&policy("{ file: ~/bad }").secrets, &home).unwrap_err();
        assert!(format!("{bad:#}").contains("control character"), "{bad:#}");
        assert!(!format!("{bad:#}").contains("a\0b"));
        let env = broker(&policy("{ env: MOAT_TEST_UNSET_9F3A }").secrets, &home).unwrap_err();
        assert!(
            format!("{env:#}").contains("MOAT_TEST_UNSET_9F3A is not set"),
            "{env:#}"
        );
    }
}
