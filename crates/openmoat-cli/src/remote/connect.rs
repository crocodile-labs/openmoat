//! Connecting, opening and disconnecting a channel, for any channel the
//! registry lists: what `openmoat approvals connect`, `test`, `listen` and
//! `disconnect` do once a person is at the terminal. Nothing here names a
//! channel; each step asks the channel's [`Spec`].

use anyhow::{Context as _, Result, bail};

use super::channel::{Channel, Credential, Options, Registry, Spec};
use super::settings::{ChannelSettings, Settings};
use super::store::Store;
use crate::proxy_session::Key;

/// Refused unless `options` answers exactly `spec`'s questions, each validly.
pub fn check_options(spec: &Spec, options: &Options) -> Result<()> {
    for question in spec.questions {
        match options.get(question.key) {
            Some(answer) if (question.valid)(answer) => {}
            Some(_) => bail!("that is not a valid {} for {}", question.key, spec.title),
            None => bail!("{} needs {}", spec.title, question.key),
        }
    }
    if let Some(extra) = options
        .keys()
        .find(|k| !spec.questions.iter().any(|q| q.key == k.as_str()))
    {
        bail!(
            "{} has no setting `{}`",
            spec.title,
            crate::render::clean(extra)
        );
    }
    Ok(())
}

/// Connect `spec` with `credential` and `options`, requests waiting
/// `expiry_s`: check the credential's shape and then with the channel's
/// server, and only then save it, the channel's signed settings and the
/// settings that make it the connected channel. The account's name.
pub fn connect(
    store: &Store,
    spec: &'static Spec,
    credential: &Credential,
    options: Options,
    expiry_s: u64,
) -> Result<String> {
    if !(spec.valid_credential)(credential) {
        bail!("that is not a {} credential; nothing was saved", spec.title);
    }
    check_options(spec, &options)?;
    let mut settings = Settings::new(spec.name, expiry_s)?;
    let account = (spec.open)(credential.clone(), &options)?
        .account()
        .with_context(|| {
            format!(
                "checking the credential with {}; nothing was saved",
                spec.title
            )
        })?;
    let key = Key::load_or_create_at(&store.key_path())?;
    let files = store.channel(spec);
    files.put_credential(credential)?;
    ChannelSettings::new(spec.name, account.clone(), options).save(&files.settings_path(), &key)?;
    // Approvers stay when the same channel is connected again.
    if let Ok(old) = Settings::load(&store.settings_path(), &key)
        && old.channel == settings.channel
    {
        settings.approvers = old.approvers;
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
    let credential = files.read_credential(spec)?;
    let own = ChannelSettings::load(&files.settings_path(), key, spec.name)?;
    check_options(spec, &own.options)?;
    Ok((spec, (spec.open)(credential, &own.options)?))
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
