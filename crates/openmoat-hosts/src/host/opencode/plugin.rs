//! OpenCode's package (ADR-095): an npm package an `opencode.json`'s
//! `plugins` list names, which OpenCode installs at start; its default export
//! is the plugin, as a local plugin's is (the plugins and build-plugins
//! pages). The plugin is the one `openmoat init` writes, for OpenCode 1 and 2,
//! finding `openmoat` on the search path instead of the path and state
//! directory `init` fills in.

use serde_json::json;

use crate::Host;
use crate::contract::{Meta, PluginFile, PluginSpec, StandAside};
use crate::wire::plugin_package::{package_json, packaged};

const FILE: &str = "openmoat.js";

pub(super) static SPEC: PluginSpec = PluginSpec {
    channel: "OpenCode plugins (npm)",
    install: "opencode plugin add @openmoat/opencode",
    publish: &[
        "Test it with OpenCode 1 and 2, each with `OPENCODE_CONFIG_DIR` set to a throwaway \
         directory whose `opencode.json` lists the folder's path in `plugins` (OpenCode 2 \
         loads a configured local directory).",
        "From `plugins/opencode`, `npm publish --access public` as a member of the `@openmoat` \
         npm organisation, on every release.",
        "Open a pull request adding it to OpenCode's ecosystem page \
         (https://opencode.ai/docs/ecosystem/).",
    ],
    sources: &[
        "https://opencode.ai/docs/plugins/",
        "https://opencode.ai/docs/build/plugins",
    ],
    // A hook that neither throws nor rejects lets the call run.
    stand_aside: StandAside::NoDecision,
    marketplace: None,
    files,
};

fn files(host: Host, meta: &Meta) -> Vec<PluginFile> {
    let entry = format!("./{FILE}");
    vec![
        package_json(
            meta,
            "@openmoat/opencode",
            host.id(),
            &[FILE, "README.md"],
            &["opencode", "opencode-plugin", "security", "policy"],
            json!({ "main": entry, "exports": { ".": entry } }),
        ),
        PluginFile::data(FILE, plugin()),
    ]
}

/// `init`'s plugin as the package ships it, under an id of its own: with
/// `init`'s copy loaded too, both register, and this one gives no decision
/// while that one decides.
fn plugin() -> String {
    packaged(&super::PLUGIN).replacen(
        r#"export default { id: "openmoat", server, setup };"#,
        &format!(r#"export default {{ id: "{PACKAGE_ID}", server, setup }};"#),
        1,
    )
}

/// The package's plugin id, not `init`'s copy's `openmoat`.
const PACKAGE_ID: &str = "openmoat-npm";

#[cfg(test)]
mod tests {
    #[test]
    fn the_package_has_an_id_of_its_own() {
        let text = super::plugin();
        assert!(text.contains(r#"id: "openmoat-npm""#));
        assert!(!text.contains(r#"id: "openmoat","#));
    }
}
