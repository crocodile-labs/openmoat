//! Claude Code's plugin (ADR-099): `.claude-plugin/plugin.json` and
//! `hooks/hooks.json`, whose shape is the `hooks` of `settings.json` under a
//! top-level `hooks` key, so it holds the entries `openmoat init` writes.
//! Hook commands may name `${CLAUDE_PLUGIN_ROOT}`, the plugin's installed
//! copy, anywhere in `command` and `args` (the plugin manifest reference,
//! "Environment variables"). A marketplace is a repository with
//! `.claude-plugin/marketplace.json` listing each plugin by a `source` path
//! from its root (the marketplace page).

use serde_json::json;

use crate::Host;
use crate::contract::{Marketplace, Meta, Paths, PluginFile, PluginSpec, StandAside};
use crate::wire::plugin_package::{hook_plugin, json_file};

/// The guard script, and how the hook file names it.
const SCRIPT: &str = "hooks/openmoat-guard";
const COMMAND: &str = "${CLAUDE_PLUGIN_ROOT}/hooks/openmoat-guard";

pub(super) static SPEC: PluginSpec = PluginSpec {
    channel: "Claude Code plugin marketplace",
    install: "claude plugin marketplace add crocodile-labs/openmoat-plugins && claude plugin \
              install openmoat@crocodile-labs",
    publish: &[
        "Create the repository `crocodile-labs/openmoat-plugins` whose root is this `plugins/` \
         folder (`git subtree split --prefix plugins` on a release commit), and push it; \
         repeat on every release, since the plugin's `version` keeps people on the release \
         it names.",
        "Check it: `claude plugin validate ./plugins` and `claude plugin validate \
         ./plugins/claude-code`, then `claude plugin marketplace add ./plugins` and `claude \
         plugin install openmoat@crocodile-labs` with `CLAUDE_CONFIG_DIR` set to a throwaway \
         directory.",
        "Optionally submit it to Anthropic's directory \
         (https://code.claude.com/docs/en/plugins/publish).",
    ],
    sources: &[
        "https://code.claude.com/docs/en/plugins-reference",
        "https://code.claude.com/docs/en/plugin-marketplaces",
        "https://code.claude.com/docs/en/hooks",
    ],
    // Claude Code runs every matching hook; a deny wins over ask and allow,
    // and no output is no opinion.
    stand_aside: StandAside::NoDecision,
    // Exit 2 blocks the call ("Exit code 2 behavior", the hooks reference).
    deny_exit: 2,
    // The plugins root keeps a marketplace plugin's copy in
    // `cache/<marketplace>/<plugin>/<version>/` and a GitHub marketplace's
    // clone in `marketplaces/<name>/` (the plugin loading reference, "Find
    // plugins on disk"); `enabledPlugins` is in the settings files `kernel-self`
    // already names. `CLAUDE_CODE_PLUGIN_CACHE_DIR` moves the root.
    installed: Paths::new(
        "Claude Code: OpenMoat's plugin as its marketplace installs it, and that\n\
         marketplace's clone",
        &[
            "~/.claude/plugins/cache/crocodile-labs/openmoat",
            "~/.claude/plugins/cache/crocodile-labs/openmoat/**",
            "~/.claude/plugins/marketplaces/crocodile-labs",
            "~/.claude/plugins/marketplaces/crocodile-labs/**",
        ],
    ),
    marketplace: Some(Marketplace {
        file: ".claude-plugin/marketplace.json",
        source_prefix: "./",
    }),
    files,
};

fn files(host: Host, meta: &Meta) -> Vec<PluginFile> {
    let manifest = json!({
        "name": meta.name,
        "displayName": meta.display_name,
        "version": meta.version,
        "description": meta.description,
        "author": { "name": meta.author },
        "homepage": meta.homepage,
        "repository": meta.repository,
        "license": meta.license,
        "keywords": ["security", "hooks", "policy", "sandbox"],
    });
    let mut files = vec![PluginFile::data(
        ".claude-plugin/plugin.json",
        json_file(&manifest),
    )];
    files.extend(hook_plugin(host, "hooks/hooks.json", SCRIPT, COMMAND, &[]));
    files
}
