//! The repository's `plugins/` folder, generated from the host specs
//! ([`crate::HostSpec::plugin`], ADR-099): one folder per host whose channel
//! takes a package, the marketplace files that list them, and a README.
//!
//! `cargo test -p openmoat-hosts --test plugins` fails when the folder differs
//! from [`files`]; `OPENMOAT_TEST_UPDATE_PLUGINS=1` rewrites it.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Value, json};

use crate::Host;
use crate::contract::{Meta, Plugin, PluginFile, PluginSpec};
use crate::wire::plugin_package::{NOT_INSTALLED, PLUGIN_FLAG, json_file};

pub use crate::wire::plugin_package::PROGRAM;

/// What every package says of itself.
pub const META: Meta = Meta {
    version: env!("CARGO_PKG_VERSION"),
    name: "openmoat",
    display_name: "OpenMoat",
    description: "Checks each tool call your coding agent makes against OpenMoat's policy before \
                  it runs. Needs the openmoat program: brew install crocodile-labs/tap/openmoat, \
                  then openmoat init.",
    author: "Crocodile Labs",
    repository: "https://github.com/crocodile-labs/openmoat",
    homepage: "https://github.com/crocodile-labs/openmoat/blob/main/docs/INSTALL.md",
    license: "MIT OR Apache-2.0",
};

/// The name of the marketplace the `plugins/` folder is, once published.
pub const MARKETPLACE: &str = "crocodile-labs";

/// The package of `host`, if its channel takes one.
#[must_use]
pub fn spec(host: Host) -> Option<&'static PluginSpec> {
    match host.spec().plugin {
        Plugin::Package(spec) => Some(spec),
        Plugin::None { .. } => None,
    }
}

/// Every file of the `plugins/` folder, relative to it, sorted by path.
#[must_use]
pub fn files() -> Vec<PluginFile> {
    let mut out = Vec::new();
    let mut marketplaces: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for host in Host::ALL {
        let Some(spec) = spec(host) else { continue };
        let readme = PluginFile::data("README.md", package_readme(host, spec));
        for file in (spec.files)(host, &META).into_iter().chain([readme]) {
            out.push(PluginFile {
                path: format!("{}/{}", host.id(), file.path),
                ..file
            });
        }
        if let Some(market) = spec.marketplace {
            marketplaces.entry(market.file).or_default().push(json!({
                "name": META.name,
                "source": format!("{}{}", market.source_prefix, host.id()),
                "description": META.description,
            }));
        }
    }
    for (file, plugins) in marketplaces {
        let doc = json!({
            "name": MARKETPLACE,
            "owner": { "name": META.author },
            "plugins": plugins,
        });
        out.push(PluginFile::data(file, json_file(&doc)));
    }
    out.push(PluginFile::data("README.md", readme()));
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Which `openmoat` a package runs, as the READMEs say it.
const WHICH: &str = "the one the policy lock pins (`binary` in `~/.moat/policy.lock`, the \
     absolute path `openmoat init` recorded); with no lock yet, one in `~/.cargo/bin` or \
     Homebrew's folder, then the search path (the guard then denies every call until `openmoat \
     init` writes the lock).";

/// What a package alone does not do that `openmoat init`'s hook does, as the
/// READMEs say it (ADR-099).
const ALONE: &str = "the package is outside the policy lock: the agent may update it, and you or \
     a project's settings may turn it off, without OpenMoat seeing it. It decides only with the \
     default state directory, `~/.moat` (a `MOAT_HOME` naming another is denied), and finds the \
     lock there from the agent's `HOME`. Its guard script is POSIX `sh`, so native Windows needs \
     `openmoat init`. `openmoat init`'s hook names its binary and state directory itself and is \
     pinned by the lock, so keep it as the setup to rely on.";

/// A package's own `README.md`: what it does and how to install it.
fn package_readme(host: Host, spec: &PluginSpec) -> String {
    format!(
        "# {display} for {name} (preview)\n\n\
         Checks each tool call {name} makes against OpenMoat's policy before it runs. Generated \
         from OpenMoat's host specs; see [the plugins README]({repo}/blob/main/plugins/README.md) \
         and [ADR-099]({repo}/blob/main/docs/adr/ADR-099-plugin-packages.md).\n\n\
         ## Install\n\n\
         1. Install OpenMoat and set it up once: `brew install crocodile-labs/tap/openmoat`, \
         then `openmoat init` in your own terminal (other ways: {homepage}).\n\
         2. Install this package ({channel}): `{install}`\n\n\
         ## What it does\n\n\
         It holds no binary and downloads nothing. For each call it runs `{PROGRAM} guard \
         --host {id} {PLUGIN_FLAG}`: {WHICH} Without `{PROGRAM}`, or when it gives no answer, \
         the call is blocked; without the policy lock `openmoat init` writes, every call is \
         denied. Where `openmoat init`'s own hook for {name} is installed too, this package \
         gives no decision, so each call is decided once. `openmoat doctor` shows when it \
         last ran.\n\n\
         ## With this package alone\n\n\
         {ALONE}\n",
        display = META.display_name,
        name = host.display_name(),
        repo = META.repository,
        homepage = META.homepage,
        channel = spec.channel,
        install = spec.install,
        id = host.id(),
    )
}

/// `plugins/README.md`: what each folder is, how a person installs it, and
/// what is left to publish it.
fn readme() -> String {
    let mut text = format!(
        "# OpenMoat in each agent's own plugin channel (preview)\n\n\
         Generated from the host specs (`crates/openmoat-hosts/src/host/<module>/plugin.rs`) by \
         `OPENMOAT_TEST_UPDATE_PLUGINS=1 cargo test -p openmoat-hosts --test plugins`; do not \
         edit. Design: [ADR-099](../docs/adr/ADR-099-plugin-packages.md); install steps: \
         [docs/INSTALL.md](../docs/INSTALL.md#install-from-an-agents-plugin-channel-preview).\n\n\
         Each folder is a thin package for one agent's channel. It holds no binary and \
         downloads nothing: it runs `{PROGRAM} guard --host <id> {PLUGIN_FLAG}`, the command \
         `openmoat init` writes plus the flag. {WHICH} When there is no `{PROGRAM}`, or it \
         gives no answer, the call is blocked with: \"{NOT_INSTALLED}\". Without a policy lock \
         the guard denies every call and names `openmoat init`, which stays the source of the \
         policy and its lock. Where `openmoat init`'s own hook for the agent is installed and \
         pinned, the package gives no decision, so each call is decided once; `openmoat \
         doctor` reports what the package did last.\n\n\
         **With a package alone**, without `openmoat init`'s hook: {ALONE}\n\n\
         None of these is listed in its channel yet: each is a preview until it is.\n\n\
         | Agent | Folder | Channel | Install, once published | Format sources |\n\
         |---|---|---|---|---|\n"
    );
    for host in Host::ALL {
        let name = host.display_name();
        match host.spec().plugin {
            Plugin::Package(spec) => {
                let sources: Vec<String> = spec
                    .sources
                    .iter()
                    .enumerate()
                    .map(|(at, url)| format!("[{}]({url})", at + 1))
                    .collect();
                let _ = writeln!(
                    text,
                    "| {name} | [`{id}/`]({id}/) | {} | `{}` | {} |",
                    spec.channel,
                    spec.install,
                    sources.join(" "),
                    id = host.id(),
                );
            }
            Plugin::None { why } => {
                let _ = writeln!(text, "| {name} | none | none: {why} | `openmoat init` | |");
            }
        }
    }
    text.push_str("\n## Publishing\n\nNothing here is published by CI. For each package:\n");
    for host in Host::ALL {
        let Some(spec) = spec(host) else { continue };
        let _ = write!(text, "\n### {}\n\n", host.display_name());
        for (at, step) in spec.publish.iter().enumerate() {
            let _ = writeln!(text, "{}. {step}", at + 1);
        }
    }
    text
}
