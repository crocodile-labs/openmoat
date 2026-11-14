//! Connecting, opening and disconnecting a channel, for any channel the
//! registry lists: what `openmoat approvals connect`, `test`, `listen` and
//! `disconnect` do once a person is at the terminal. Nothing here names a
//! channel; each step asks the channel's [`Spec`].

use anyhow::{Context as _, Result, bail};

use super::channel::{Channel, Options, Registry, Secrets, Spec};
use super::settings::{ChannelSettings, Settings};
use super::store::Store;
use crate::proxy_session::Key;

/// Refused unless `values` holds exactly `spec`'s fields of the kind
/// `secret`, each one valid. Errors never show a value.
pub fn check_fields<V: AsRef<str>>(
    spec: &Spec,
    secret: bool,
    values: &std::collections::BTreeMap<String, V>,
) -> Result<()> {
    for field in spec.fields.iter().filter(|f| f.secret == secret) {
        match values.get(field.key) {
            Some(value) if (field.valid)(value.as_ref()) => {}
            Some(_) => bail!("that is not a valid {} for {}", field.key, spec.title),
            None => bail!("{} needs {}", spec.title, field.key),
        }
    }
    if let Some(extra) = values.keys().find(|k| {
        !spec
            .fields
            .iter()
            .any(|f| f.secret == secret && f.key == k.as_str())
    }) {
        bail!(
            "{} has no {} `{}`",
            spec.title,
            if secret { "secret" } else { "setting" },
            crate::render::clean(extra)
        );
    }
    Ok(())
}

/// Connect `spec` with `secrets` and `options`, requests waiting
/// `expiry_s`: check every field and then the secrets with the channel's
/// server, and only then save them, the channel's signed settings and the
/// settings that make it the connected channel. The account's name.
pub fn connect(
    store: &Store,
    spec: &'static Spec,
    secrets: &Secrets,
    options: Options,
    expiry_s: u64,
) -> Result<String> {
    check_fields(spec, true, secrets).context("nothing was saved")?;
    check_fields(spec, false, &options).context("nothing was saved")?;
    let mut settings = Settings::new(spec.name, expiry_s)?;
    let account = (spec.open)(secrets, &options)?.account().with_context(|| {
        format!(
            "checking the credentials with {}; nothing was saved",
            spec.title
        )
    })?;
    let key = Key::load_or_create_at(&store.key_path())?;
    let files = store.channel(spec);
    files.put_secrets(secrets)?;
    ChannelSettings::new(spec.name, account.clone(), options).save(&files.settings_path(), &key)?;
    // Approvers, and the hook's wait, stay when the same channel is connected again.
    if let Ok(old) = Settings::load(&store.settings_path(), &key)
        && old.channel == settings.channel
    {
        settings.approvers = old.approvers;
        settings.wait_s = old.wait_s;
    }
    settings.save(&store.settings_path(), &key)?;
    Ok(account)
}

/// The connected channel's spec, from `registry`.
pub fn spec(registry: &Registry, settings: &Settings) -> Result<&'static Spec> {
    registry.find(&settings.channel)
}

/// The connected channel, opened with its credential and signed settings.
pub fn open(
    store: &Store,
    registry: &Registry,
    key: &Key,
    settings: &Settings,
) -> Result<(&'static Spec, Box<dyn Channel>)> {
    let spec = spec(registry, settings)?;
    let files = store.channel(spec);
    let secrets = files.read_secrets(spec)?;
    let own = ChannelSettings::load(&files.settings_path(), key, spec.name)?;
    check_fields(spec, false, &own.options)?;
    Ok((spec, (spec.open)(&secrets, &own.options)?))
}

/// The connected channel's account name, when its settings read.
pub fn account(
    store: &Store,
    registry: &Registry,
    key: &Key,
    settings: &Settings,
) -> Option<String> {
    let spec = spec(registry, settings).ok()?;
    let files = store.channel(spec);
    ChannelSettings::load(&files.settings_path(), key, spec.name)
        .ok()
        .map(|own| own.account)
}

/// What is wrong with the connected channel's credential file, if anything.
pub fn credential_problem(store: &Store, spec: &Spec) -> Option<String> {
    let path = store.channel(spec).credential_path();
    if path.exists() {
        crate::key_file::problem(&path)
    } else {
        Some(format!("{} is missing", path.display()))
    }
}

/// Remove the settings, every listed channel's folder and the waiting
/// requests and answers; the spec of the channel that was connected, and
/// whether anything was removed.
pub fn disconnect(store: &Store, registry: &Registry) -> Result<(Option<&'static Spec>, bool)> {
    let path = store.settings_path();
    // Which channel it was, signed or not: only to name how to revoke it.
    let was = std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Settings>(&text).ok())
        .and_then(|settings| registry.find(&settings.channel).ok());
    let mut removed = match std::fs::remove_file(&path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
    };
    for spec in registry.0 {
        removed |= store.channel(spec).remove()?;
    }
    for dir in ["requests", "answers"] {
        let _ = std::fs::remove_dir_all(store.dir().join(dir));
    }
    Ok((was, removed))
}
