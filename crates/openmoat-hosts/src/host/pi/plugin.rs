//! pi's package (ADR-095): an npm package whose `package.json` names its
//! extensions under `pi.extensions` and carries the `pi-package` keyword for
//! the pi.dev gallery (`docs/packages.md`). The extension is the one `openmoat
//! init` writes, finding `openmoat` on the search path instead of the path and
//! state directory `init` fills in.

use serde_json::json;

use crate::Host;
use crate::contract::{Meta, PluginFile, PluginSpec, StandAside};
use crate::wire::plugin_package::{package_json, packaged};

const FILE: &str = "openmoat.js";

pub(super) static SPEC: PluginSpec = PluginSpec {
    channel: "pi packages (npm, pi.dev gallery)",
    install: "pi install npm:@openmoat/pi",
    publish: &[
        "Test it with `pi install ./plugins/pi` with `PI_CODING_AGENT_DIR` set to a throwaway \
         directory.",
        "From `plugins/pi`, `npm publish --access public` as a member of the `@openmoat` npm \
         organisation (the one that publishes `@openmoat/sdk`), on every release.",
        "The `pi-package` keyword lists it in the pi.dev gallery; nothing else to submit.",
    ],
    sources: &[
        "https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/packages.md",
        "https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md",
    ],
    // A handler that returns nothing does not block; the first block wins.
    stand_aside: StandAside::NoDecision,
    marketplace: None,
    files,
};

fn files(host: Host, meta: &Meta) -> Vec<PluginFile> {
    vec![
        package_json(
            meta,
            "@openmoat/pi",
            host.id(),
            &[FILE, "README.md"],
            &["pi-package", "security", "policy", "ai-agents"],
            json!({ "pi": { "extensions": [format!("./{FILE}")] } }),
        ),
        PluginFile::data(FILE, packaged(&super::EXTENSION)),
    ]
}
