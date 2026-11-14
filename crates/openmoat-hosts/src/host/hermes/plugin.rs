//! Hermes Agent's plugin (ADR-099): a Python plugin, `plugin.yaml` and
//! `__init__.py` whose `register(ctx)` adds a `pre_tool_call` callback
//! (`ctx.register_hook`), which returns `{"action": "block", "message"}` to
//! veto a call or `{"action": "approve"}` for Hermes's approval prompt (the
//! plugins guide). Hermes's human-reviewed Plugin Catalog takes a
//! `plugin-catalog/<name>.yaml` pinned to a full commit (the catalog
//! submission page and `plugin-catalog/README.md`); the folder holds that
//! entry with the commit left for the person who submits it.

use serde_json::Value;

use crate::Host;
use crate::contract::{Meta, Paths, PluginFile, PluginSpec, StandAside};
use crate::wire::plugin_package::{
    INSTALL_DIRS, LOCK_FILE, LOCK_UNUSABLE, NOT_INSTALLED, PLUGIN_FLAG, PROGRAM,
};

/// The Hermes release OpenMoat's hook was last checked against (`HOST.md`).
const CHECKED: &str = "0.22.5";

static SOURCE: &str = include_str!("integration/plugin.py");

pub(super) static SPEC: PluginSpec = PluginSpec {
    channel: "Hermes Agent Plugin Catalog",
    install: "hermes plugins install openmoat && hermes plugins enable openmoat",
    publish: &[
        "Test it: `hermes plugins validate plugins/hermes --install-deps`, then copy the \
         folder into a throwaway Hermes home's plugins and enable it.",
        "Copy `plugins/hermes/plugin-catalog-entry.yaml` to `plugin-catalog/openmoat.yaml` in \
         a fork of `NousResearch/hermes-agent`, set `sha` to the full 40-character commit of \
         `crocodile-labs/openmoat` that holds this release's `plugins/hermes`, and open a pull \
         request; CI validates it and maintainers review it. Bump `sha` and `version` on \
         every release.",
    ],
    sources: &[
        "https://hermes-agent.nousresearch.com/docs/developer-guide/plugins",
        "https://hermes-agent.nousresearch.com/docs/developer-guide/plugins/catalog-submission",
        "https://github.com/NousResearch/hermes-agent/blob/main/plugin-catalog/README.md",
    ],
    // No answer from the callback lets the call run; a block vetoes it.
    stand_aside: StandAside::NoDecision,
    deny_exit: 2,
    // Plugins live in the home's `plugins/`, all of which `kernel-self`
    // already names from this host's own paths.
    installed: Paths::new("", &[]),
    marketplace: None,
    files,
};

/// `text` as a quoted scalar YAML and Python both read as written.
fn quoted(text: &str) -> String {
    Value::from(text).to_string()
}

fn files(host: Host, meta: &Meta) -> Vec<PluginFile> {
    let event = host
        .spec()
        .install
        .as_ref()
        .and_then(|install| install.hooks.first())
        .map_or(super::EVENT, |hook| hook.event);
    let dirs = Value::from(INSTALL_DIRS.to_vec()).to_string();
    let source = SOURCE
        .replacen("__HOST__", &quoted(host.id()), 1)
        .replacen("__EVENT__", &quoted(event), 1)
        .replacen("__FLAG__", &quoted(PLUGIN_FLAG), 1)
        .replacen("__PROGRAM__", &quoted(PROGRAM), 1)
        .replacen("__NOT_INSTALLED__", &quoted(NOT_INSTALLED), 1)
        .replacen("__INSTALL_DIRS__", &dirs, 1)
        .replacen("__LOCK_FILE__", &quoted(LOCK_FILE), 1)
        .replacen("__LOCK_UNUSABLE__", &quoted(LOCK_UNUSABLE), 1);
    let manifest = format!(
        "name: {name}\nversion: {version}\ndescription: {description}\nauthor: {author}\n\
         provides_hooks:\n  - {event}\nrequires_hermes: {requires}\n",
        name = meta.name,
        version = quoted(meta.version),
        description = quoted(meta.description),
        author = quoted(meta.author),
        requires = quoted(&format!(">={CHECKED}")),
    );
    let entry = format!(
        "# The Plugin Catalog entry, as `plugin-catalog/openmoat.yaml` of\n\
         # NousResearch/hermes-agent. Set `sha` to the full commit of {repository}\n\
         # that holds this folder before opening the pull request.\n\
         name: {name}\nrepo: {repository}\nsha: \"<40-character commit>\"\nsubdir: plugins/{id}\n\
         description: {description}\nmaintainer: {author}\ntier: community\n\
         requires_hermes: {requires}\ndocs_url: {docs}\nversion: {version}\ntitle: {title}\n\
         capabilities:\n  provides_tools: []\n  provides_hooks: [{event}]\n  \
         provides_middleware: []\n  requires_env: []\n",
        name = meta.name,
        repository = meta.repository,
        id = host.id(),
        description = quoted(meta.description),
        author = quoted(meta.author),
        requires = quoted(&format!(">={CHECKED}")),
        docs = quoted(meta.homepage),
        version = quoted(meta.version),
        title = quoted(meta.display_name),
    );
    vec![
        PluginFile::data("plugin.yaml", manifest),
        PluginFile::data("__init__.py", source),
        PluginFile::data("plugin-catalog-entry.yaml", entry),
    ]
}
