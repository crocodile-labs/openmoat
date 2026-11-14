//! Gemini CLI's extension (ADR-099): `gemini-extension.json` at the root,
//! and the hooks in `hooks/hooks.json`, not in the manifest; `${extensionPath}`
//! is the extension's absolute directory in both files (the extension
//! reference). The entries are the ones `openmoat init` writes into
//! `settings.json`, under the same top-level `hooks` key. The gallery lists a
//! public repository with `gemini-extension.json` at its root and the topic
//! `gemini-cli-extension` (the releasing page).

use serde_json::json;

use crate::Host;
use crate::contract::{Meta, Paths, PluginFile, PluginSpec, StandAside};
use crate::wire::plugin_package::{hook_plugin, json_file};

/// The guard script, and how the hook file names it.
const SCRIPT: &str = "hooks/openmoat-guard";
const COMMAND: &str = "${extensionPath}/hooks/openmoat-guard";

pub(super) static SPEC: PluginSpec = PluginSpec {
    channel: "Gemini CLI extensions gallery",
    install: "gemini extensions install https://github.com/crocodile-labs/openmoat-gemini",
    publish: &[
        "Create the public repository `crocodile-labs/openmoat-gemini` whose root is \
         `plugins/gemini-cli` (the manifest must be at the root), and push it on every release.",
        "Test it: `gemini extensions link plugins/gemini-cli` with `GEMINI_CLI_HOME` set to a \
         throwaway directory, in a trusted folder (untrusted folders run no hooks).",
        "Add the GitHub topic `gemini-cli-extension` to the repository; the gallery crawls \
         daily.",
    ],
    sources: &[
        "https://geminicli.com/docs/extensions/reference/",
        "https://geminicli.com/docs/extensions/releasing/",
        "https://geminicli.com/docs/hooks/",
    ],
    // No output from a `BeforeTool` hook is no decision.
    stand_aside: StandAside::NoDecision,
    // Exit 2 is a "System Block" (the hooks page).
    deny_exit: 2,
    // Extensions load from `<home>/.gemini/extensions`, each in a folder named
    // as the extension (the extension reference).
    installed: Paths::new(
        "Gemini CLI: OpenMoat's extension",
        &["~/.gemini/extensions/openmoat", "~/.gemini/extensions/openmoat/**"],
    ),
    marketplace: None,
    files,
};

fn files(host: Host, meta: &Meta) -> Vec<PluginFile> {
    let manifest = json!({
        "name": meta.name,
        "version": meta.version,
        "description": meta.description,
    });
    let mut files = vec![PluginFile::data(
        "gemini-extension.json",
        json_file(&manifest),
    )];
    files.extend(hook_plugin(host, "hooks/hooks.json", SCRIPT, COMMAND, &[]));
    files
}
