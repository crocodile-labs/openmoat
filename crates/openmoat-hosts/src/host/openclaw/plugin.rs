//! OpenClaw's package (ADR-099): a native plugin as `ClawHub` publishes it, an
//! npm-style folder with `openclaw.plugin.json` (`id` and `configSchema`
//! required) and a `package.json` whose `openclaw` block names the entry
//! (`extensions`) and the compatibility `ClawHub` requires
//! (`compat.pluginApi`, `build.openclawVersion`). The plugin is the one
//! `openmoat init` writes, finding `openmoat` on the search path, under an id
//! of its own: with `init`'s copy loaded too, both register, and this one
//! gives no decision while that one decides.

use serde_json::json;

use crate::Host;
use crate::contract::{Meta, Paths, PluginFile, PluginSpec, StandAside};
use crate::wire::plugin_package::{json_file, package_json, packaged};

const FILE: &str = "openmoat.mjs";

/// The package's plugin id, not [`super::PLUGIN_ID`], `init`'s copy's.
pub(crate) const PACKAGE_ID: &str = "openmoat-clawhub";

/// The OpenClaw release OpenMoat's plugin was last checked against
/// (`fixtures/README.md`, and `checked` in `scripts/ci/latest-agents/agents.json`).
const CHECKED: &str = "2026.10.5";

pub(super) static SPEC: PluginSpec = PluginSpec {
    channel: "ClawHub",
    install: "openclaw plugins install clawhub:@openmoat/openclaw",
    publish: &[
        "Test it with `openclaw plugins install ./plugins/openclaw` with `OPENCLAW_STATE_DIR` \
         set to a throwaway directory, then restart the Gateway.",
        "`clawhub package publish ./plugins/openclaw --dry-run`, then without `--dry-run`, \
         signed in as Crocodile Labs; ClawHub scans each release before it is listed. \
         Check first that ClawHub's plugin publishing works in the current OpenClaw \
         release (2026.11.2-11.3 release notes report it incomplete).",
        "Raise `compat` and `build` in `package.json` (from the OpenClaw release the weekly \
         check last passed) when OpenMoat's plugin is checked against a newer one.",
    ],
    sources: &[
        "https://docs.openclaw.ai/tools/clawhub",
        "https://docs.openclaw.ai/plugins/manifest",
        "https://docs.openclaw.ai/plugins/building-plugins",
    ],
    // A handler that returns nothing makes no decision; a block is final.
    stand_aside: StandAside::NoDecision,
    deny_exit: 2,
    // `openclaw plugins install` puts a plugin "into the active OpenClaw
    // workspace" (the ClawHub page) without naming the folder; the package's
    // folder is covered below the state directory and in any npm folder.
    // `plugins.entries.<id>.enabled` is in `openclaw.json`, which `kernel-self`
    // already names.
    installed: Paths::new(
        "OpenClaw: OpenMoat's ClawHub package, below its state directory or in an npm\n\
         folder",
        &[
            "~/.openclaw/**/openmoat-clawhub",
            "~/.openclaw/**/openmoat-clawhub/**",
            "**/node_modules/@openmoat/openclaw",
            "**/node_modules/@openmoat/openclaw/**",
        ],
    ),
    marketplace: None,
    files,
};

fn files(host: Host, meta: &Meta) -> Vec<PluginFile> {
    let entry = format!("./{FILE}");
    let manifest = json!({
        "id": PACKAGE_ID,
        "name": meta.display_name,
        "description": meta.description,
        "version": meta.version,
        "configSchema": { "type": "object", "additionalProperties": false },
    });
    let ours = format!("id: \"{}\",", super::PLUGIN_ID);
    let plugin = packaged(&super::PLUGIN).replacen(&ours, &format!("id: \"{PACKAGE_ID}\","), 1);
    vec![
        package_json(
            meta,
            "@openmoat/openclaw",
            host.id(),
            &[FILE, "openclaw.plugin.json", "README.md"],
            &["openclaw", "openclaw-plugin", "security", "policy"],
            json!({
                "openclaw": {
                    "extensions": [entry],
                    "compat": { "pluginApi": format!(">={CHECKED}"), "minGatewayVersion": CHECKED },
                    "build": { "openclawVersion": CHECKED },
                },
            }),
        ),
        PluginFile::data("openclaw.plugin.json", json_file(&manifest)),
        PluginFile::data(FILE, plugin),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_package_has_an_id_of_its_own() {
        let files = super::files(crate::Host::OpenClaw, &crate::plugin::META);
        let plugin = files.iter().find(|f| f.path == super::FILE).unwrap();
        assert_eq!(plugin.text.matches(super::PACKAGE_ID).count(), 1);
        assert!(!plugin.text.contains(r#"id: "openmoat","#));
    }
}
