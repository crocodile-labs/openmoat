//! The agent tables of `README.md` ("Agents") and `docs/FEATURES.md` ("Each
//! agent"), built from the host specs alone, so the page that says which
//! feature works with which agent cannot claim more than the specs do. The
//! evidence behind each claim, OS by OS, is `docs/PROTECTION.md`'s.

use openmoat_hosts::{Host, HostSpec, Managed, McpSyntax, Plugin};

use crate::cfg::Os;
use crate::matrix::{anchor, runs};
use crate::{check, hosts};

/// What a cell says when the feature does not apply to the agent.
const NONE: &str = "—";

/// `README.md` "Agents": one short row per agent, its protection, the command
/// that sets up only it, and where its per-OS facts are.
pub fn readme_table() -> Vec<String> {
    let mut lines = vec![
        "| Agent | Protection | Set up only this agent | Per OS |".to_owned(),
        "|---|---|---|---|".to_owned(),
    ];
    for host in hosts() {
        let spec = host.spec();
        let setup = match spec.install {
            Some(_) => format!("`openmoat init --hosts {}`", spec.id),
            None => "none".to_owned(),
        };
        lines.push(format!(
            "| {} | {} | {setup} | [details](docs/PROTECTION.md#{}) |",
            spec.display_name,
            spec.docs.protection,
            anchor(spec.display_name)
        ));
    }
    lines
}

/// `docs/FEATURES.md` "How each agent is hooked": the events and files, what
/// checks its calls, and its `--hosts` id (none for an agent with no hook to
/// install).
pub fn hooked_table() -> Vec<String> {
    let mut lines = vec![
        "| Agent | How OpenMoat is hooked | Protection | `openmoat init --hosts` |".to_owned(),
        "|---|---|---|---|".to_owned(),
    ];
    for host in hosts() {
        let spec = host.spec();
        let id = match spec.install {
            Some(_) => format!("`{}`", spec.id),
            None => "none".to_owned(),
        };
        lines.push(format!(
            "| {} | {} | {} | {id} |",
            spec.display_name, spec.docs.hooked_by, spec.docs.protection
        ));
    }
    lines
}

/// The agent's own OS sandbox: the file `openmoat init` writes, and whether
/// it is written on native Windows.
fn own_sandbox(spec: &HostSpec) -> String {
    match &spec.sandbox {
        None => NONE.to_owned(),
        Some(s) if s.unavailable_on_windows.is_some() => {
            format!("`{}`, not on native Windows", s.file)
        }
        Some(s) => format!("`{}`", s.file),
    }
}

/// The systems `openmoat run` starts the agent on, where OpenMoat knows how.
fn run(spec: &HostSpec) -> String {
    let oses: Vec<&str> = [Os::Mac, Os::Linux, Os::Windows]
        .into_iter()
        .filter(|os| runs(spec, *os).is_ok())
        .map(|os| match os {
            Os::Linux => "Linux",
            Os::Mac => "macOS 13+",
            Os::Windows => "Windows",
        })
        .collect();
    if oses.is_empty() {
        NONE.to_owned()
    } else {
        oses.join(", ")
    }
}

/// What a `review` on a tool call becomes in the agent.
fn review(spec: &HostSpec) -> String {
    if spec.install.is_none() {
        return NONE.to_owned();
    }
    match spec.reviews.on_pre_tool_use {
        None => "the agent's own prompt".to_owned(),
        Some(_) => "a deny you approve with `openmoat allow --last`".to_owned(),
    }
}

/// What OpenMoat does with the agent's MCP servers.
fn mcp(spec: &HostSpec) -> String {
    match &spec.mcp {
        None => NONE.to_owned(),
        Some(m) if m.user_reader.syntax() == McpSyntax::Yaml => "pinned".to_owned(),
        Some(_) => "pinned; stdio servers can be wrapped".to_owned(),
    }
}

/// Whether `openmoat init --managed` writes a hook a project cannot turn off.
fn managed(spec: &HostSpec) -> String {
    match &spec.hook_off.managed {
        Managed::Written(hooks) if hooks.root_owned => {
            "`openmoat init --managed` prints the root command".to_owned()
        }
        Managed::Written(_) => "`openmoat init --managed`".to_owned(),
        Managed::Manual { .. } => "an administrator writes it".to_owned(),
        Managed::None { .. } => NONE.to_owned(),
    }
}

/// The agent's own plugin channel, where OpenMoat has a package for it.
fn plugin(spec: &HostSpec) -> String {
    match spec.plugin {
        Plugin::Package(p) => p.channel.to_owned(),
        Plugin::None { .. } => NONE.to_owned(),
    }
}

/// What the agent does with a call when OpenMoat's hook fails, in a few words
/// (`docs/LIMITS.md` "If the hook fails" has every case and source).
fn hook_failure(spec: &HostSpec) -> String {
    if spec.install.is_none() {
        return NONE.to_owned();
    }
    let facts = &spec.hook_failure;
    let open = facts.open_cases(true);
    if !open.is_empty() {
        return format!("runs it when the hook {}", open.join("; or "));
    }
    match facts.flag_since() {
        Some((major, minor, patch)) => {
            format!("blocks it from {major}.{minor}.{patch}; earlier versions run it")
        }
        None => "blocks it".to_owned(),
    }
}

/// `docs/FEATURES.md` "Each agent": which features apply to each agent.
pub fn features_table() -> Vec<String> {
    let mut lines = vec![
        "| Agent | Protection | Own OS sandbox (`openmoat init`) | `openmoat run` | A `review` \
         becomes | MCP servers | Hook a project cannot turn off | Plugin package (preview) | \
         When the hook fails, the agent |"
            .to_owned(),
        "|---|---|---|---|---|---|---|---|---|".to_owned(),
    ];
    for host in hosts() {
        let spec = host.spec();
        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            spec.display_name,
            spec.docs.protection,
            own_sandbox(spec),
            run(spec),
            review(spec),
            mcp(spec),
            managed(spec),
            plugin(spec),
            hook_failure(spec)
        ));
    }
    lines
}

#[test]
fn readme_lists_each_agent_and_its_protection() {
    check("README.md", &[("hosts-agents", readme_table())]);
}

#[test]
fn features_lists_each_agent_and_what_applies_to_it() {
    check(
        "docs/FEATURES.md",
        &[
            ("features-hooked", hooked_table()),
            ("features-agents", features_table()),
        ],
    );
}

/// Every agent the registry knows has a row in both tables, so a new host
/// cannot be left out of the page that says what works with it.
#[test]
fn every_agent_has_a_row() {
    for table in [readme_table(), hooked_table(), features_table()] {
        for host in Host::EVERY {
            let name = host.display_name();
            assert!(
                table.iter().any(|l| l.starts_with(&format!("| {name} |"))),
                "{name} has no row"
            );
        }
    }
}
