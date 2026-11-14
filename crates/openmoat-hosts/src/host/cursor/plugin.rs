//! Cursor's plugin (ADR-095): `.cursor-plugin/plugin.json` and
//! `hooks/hooks.json`, the parser's default hooks location, in the layout of
//! `~/.cursor/hooks.json` (`version: 1`, a `hooks` map of entries with
//! `command`, `timeout` and `failClosed`). A plugin's hooks run from its
//! install directory, which `CURSOR_PLUGIN_ROOT` names, so the hook file names
//! the guard script by a relative path. A multi-plugin repository lists its
//! plugins in `.cursor-plugin/marketplace.json` (the plugins reference).

use serde_json::json;

use crate::Host;
use crate::contract::{Marketplace, Meta, PluginFile, PluginSpec, StandAside};
use crate::wire::plugin_package::{hook_plugin, json_file};

/// The guard script, and how the hook file names it from the install directory.
const SCRIPT: &str = "hooks/openmoat-guard";
const COMMAND: &str = "./hooks/openmoat-guard";

pub(super) static SPEC: PluginSpec = PluginSpec {
    channel: "Cursor Marketplace",
    install: "Cursor: Customize, find OpenMoat in the Marketplace, Install",
    publish: &[
        "Publish the `plugins/` folder as the repository `crocodile-labs/openmoat-plugins` \
         (the step the Claude Code plugin takes); its `.cursor-plugin/marketplace.json` lists \
         `cursor/`.",
        "Test it: copy `plugins/cursor` to `~/.cursor/plugins/local/openmoat` on a test \
         account, then Developer: Reload Window.",
        "Submit it at https://cursor.com/marketplace/publish; Cursor reviews it and every \
         update before listing.",
    ],
    sources: &[
        "https://cursor.com/docs/plugins",
        "https://cursor.com/docs/reference/plugins",
        "https://cursor.com/docs/agent/hooks",
    ],
    // Cursor's hooks have no "no decision"; it runs every matching hook and
    // takes deny over ask over allow, whatever their source, so `allow`
    // leaves `openmoat init`'s answer as it is.
    stand_aside: StandAside::Allow,
    marketplace: Some(Marketplace {
        file: ".cursor-plugin/marketplace.json",
        source_prefix: "",
    }),
    files,
};

fn files(host: Host, meta: &Meta) -> Vec<PluginFile> {
    let manifest = json!({
        "name": meta.name,
        "description": meta.description,
        "version": meta.version,
        "author": { "name": meta.author },
        "homepage": meta.homepage,
        "repository": meta.repository,
        "license": meta.license,
        "keywords": ["security", "hooks", "policy"],
    });
    let mut files = vec![PluginFile::data(
        ".cursor-plugin/plugin.json",
        json_file(&manifest),
    )];
    files.extend(hook_plugin(host, "hooks/hooks.json", SCRIPT, COMMAND, &[]));
    files
}
