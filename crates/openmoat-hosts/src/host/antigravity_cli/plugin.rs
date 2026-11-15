//! Antigravity CLI's plugin (ADR-099): `plugin.json` and `<plugin-root>/hooks.json`
//! (a `hooks/hooks.json` is not loaded from a native plugin), the layout of
//! `~/.gemini/config/hooks.json` that `openmoat init` writes: one named group
//! with `enabled` and a `PreToolUse` list. Command hooks run with the plugin's
//! root as their working directory, so the guard script is named by a
//! relative path (the build-plugins guide). `agy plugin install <github-url>`
//! installs a repository's root.

use serde_json::json;

use crate::Host;
use crate::contract::{Meta, Paths, PluginFile, PluginSpec, StandAside};
use crate::wire::plugin_package::{hook_plugin, json_file};

/// The guard script, and how the hook file names it from the plugin's root.
const SCRIPT: &str = "openmoat-guard";
const COMMAND: &str = "./openmoat-guard";

pub(super) static SPEC: PluginSpec = PluginSpec {
    channel: "Antigravity CLI plugins",
    install: "agy plugin install https://github.com/crocodile-labs/openmoat-antigravity",
    publish: &[
        "Create the public repository `crocodile-labs/openmoat-antigravity` whose root is \
         `plugins/antigravity-cli`, and push it on every release.",
        "Test it with `agy plugin install ./plugins/antigravity-cli` in a throwaway home: \
         Antigravity CLI is a preview host (no hook fired in the 2026-11-10 real run), so check \
         that the plugin's hook fires before saying it protects anything.",
        "For the curated marketplace, fill in Antigravity's interest form \
         (https://antigravity.google/docs/marketplace.md).",
    ],
    sources: &[
        "https://antigravity.google/docs/plugins.md",
        "https://antigravity.google/docs/build-plugins.md",
        "https://antigravity.google/docs/hooks.md",
    ],
    // `allow` defers to the next hook or the default policy, the answer the
    // guard gives a `defer`.
    stand_aside: StandAside::NoDecision,
    // `~/.gemini/config/plugins/<plugin_name>/` (the plugins page), all of
    // which `kernel-self` already names from this host's own paths.
    installed: Paths::new("", &[]),
    marketplace: None,
    files,
};

fn files(host: Host, meta: &Meta) -> Vec<PluginFile> {
    let manifest = json!({
        "name": meta.name,
        "displayName": meta.display_name,
        "version": meta.version,
        "description": meta.description,
    });
    let mut files = vec![PluginFile::data("plugin.json", json_file(&manifest))];
    files.extend(hook_plugin(host, "hooks.json", SCRIPT, COMMAND, &[]));
    files
}
