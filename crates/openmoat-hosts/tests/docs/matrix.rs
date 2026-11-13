//! `docs/PROTECTION.md`: one row per agent and OS of what protects its calls,
//! built from the host specs and from the evidence behind each claim
//! (ADR-079 decision 5): the end-to-end tests marked `// protection:`
//! ([`crate::marks`]) and the weekly `latest agents` job's records
//! ([`crate::weekly`]). A claim with no evidence says `no evidence yet` in the
//! table; the summary calls it `preview`.

use std::fmt::Write as _;

use openmoat_hosts::{FailureOutcome, Host, HostSpec, McpSyntax, RunFacts, RunWrite};

use crate::cfg::Os;
use crate::marks::{Claim, Mark};
use crate::weekly::Record;

/// What the summary says of one claim on one OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Claimed, with evidence.
    Shown,
    /// Claimed, with no evidence yet.
    Preview,
    /// Not claimed.
    Absent,
}

/// The evidence the matrix is built from.
pub struct Evidence<'a> {
    pub marks: &'a [Mark],
    pub records: &'a [Record],
}

impl Evidence<'_> {
    /// The marked tests of `claim` for `host` on `os`.
    pub fn tests(&self, claim: Claim, host: Host, os: Os) -> Vec<&str> {
        self.marks
            .iter()
            .filter(|m| m.claim == claim && m.hosts.contains(&host) && m.oses.contains(&os))
            .map(|m| m.test.as_str())
            .collect()
    }

    /// The weekly job's records of `host`.
    pub fn records_of(&self, host: Host) -> Vec<&Record> {
        self.records
            .iter()
            .filter(|r| r.host == host.id())
            .collect()
    }

    /// The weekly job's records that prove `claim` for `host` on `os`. For
    /// the hook, every record of the host must prove it there: an agent run
    /// in two versions (OpenCode 1 and 2) is shown protected only when both
    /// are.
    pub fn weekly(&self, claim: Claim, host: Host, os: Os) -> Vec<&Record> {
        let records = self.records_of(host);
        let proves = |r: &&Record| r.proves.contains(&claim) && r.oses.contains(&os);
        if claim == Claim::Hook && !records.iter().all(proves) {
            return Vec::new();
        }
        records.into_iter().filter(proves).collect()
    }

    /// Whether anything backs `claim` for `host` on `os`.
    pub fn has(&self, claim: Claim, host: Host, os: Os) -> bool {
        !self.tests(claim, host, os).is_empty() || !self.weekly(claim, host, os).is_empty()
    }
}

/// One cell: its text in the table, and the level the summary shows.
pub struct Cell {
    pub text: String,
    pub level: Level,
}

/// `text` with `; no evidence yet` when `evidenced` is false.
fn claimed(text: String, evidenced: bool) -> Cell {
    if evidenced {
        Cell {
            text,
            level: Level::Shown,
        }
    } else {
        Cell {
            text: format!("{text}; no evidence yet"),
            level: Level::Preview,
        }
    }
}

fn absent(text: impl Into<String>) -> Cell {
    Cell {
        text: text.into(),
        level: Level::Absent,
    }
}

fn code_list(items: impl IntoIterator<Item = String>) -> String {
    items
        .into_iter()
        .map(|i| format!("`{i}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether OpenMoat's hook decides the agent's calls.
pub fn hook(host: Host, os: Os, ev: &Evidence<'_>) -> Cell {
    if host.spec().install.is_none() {
        return absent("none: OpenMoat installs no hook for it");
    }
    if ev.has(Claim::Hook, host, os) {
        Cell {
            text: "protected".to_owned(),
            level: Level::Shown,
        }
    } else {
        claimed("installed by `openmoat init`".to_owned(), false)
    }
}

/// What the agent does with a call when the hook fails (ADR-079 decision 1).
pub fn hook_failure(host: Host, os: Os, ev: &Evidence<'_>) -> Cell {
    let spec = host.spec();
    if spec.install.is_none() {
        return absent("—");
    }
    let facts = &spec.hook_failure;
    let limit = facts
        .timeout_s
        .map_or_else(String::new, |s| format!(" (after {s} s)"));
    // An outcome that differs by case names the cases itself.
    let fails = match facts.fails {
        FailureOutcome::BlocksWhenMissing => facts.fails.words(),
        other => format!("cannot start, crashes or exits non-zero: {}", other.words()),
    };
    claimed(
        format!("{fails}; times out{limit}: {}", facts.times_out.words()),
        ev.has(Claim::HookFailure, host, os),
    )
}

/// The agent's own OS sandbox, as `openmoat init` writes it.
pub fn sandbox(host: Host, os: Os, ev: &Evidence<'_>) -> Cell {
    match &host.spec().sandbox {
        None => absent("none"),
        Some(s) if os == Os::Windows && s.unavailable_on_windows.is_some() => absent(format!(
            "none: {}",
            s.unavailable_on_windows.unwrap_or_default()
        )),
        Some(s) => claimed(
            format!("`{}`, written by `openmoat init`", s.file),
            ev.has(Claim::Sandbox, host, os),
        ),
    }
}

/// Whether `openmoat run` can start the agent on `os`.
fn runs(spec: &HostSpec, os: Os) -> Result<(), String> {
    if os == Os::Windows {
        return Err(
            "`openmoat run` refuses on Windows, where OpenMoat generates no OS sandbox".into(),
        );
    }
    match spec.run {
        RunFacts::Unknown { why } if spec.sandbox.is_none() => Err(why.to_owned()),
        _ => Ok(()),
    }
}

/// The command `openmoat status` offers on `os`, for an agent whose run facts
/// are known.
fn command(spec: &HostSpec, os: Os) -> Option<String> {
    let RunFacts::Known {
        program,
        args,
        writes,
    } = spec.run
    else {
        return None;
    };
    let mut line = String::from("openmoat run");
    if os == Os::Linux {
        line.push_str(" --isolate");
    }
    for write in writes {
        let path = match write {
            RunWrite::ConfigDir => format!("~/{}", spec.install.as_ref()?.dir_name),
            RunWrite::Home(path) => format!("~/{path}"),
            RunWrite::Cache(name) if os == Os::Mac => format!("~/Library/Caches/{name}"),
            RunWrite::Cache(name) => format!("~/.cache/{name}"),
        };
        let _ = write!(line, " --write {path}");
    }
    let _ = write!(line, " -- {program}");
    for arg in args {
        let _ = write!(line, " {arg}");
    }
    Some(line)
}

/// The tier `openmoat run` starts the agent in on `os`.
pub fn run(host: Host, os: Os, ev: &Evidence<'_>) -> Cell {
    let spec = host.spec();
    if let Err(why) = runs(spec, os) {
        return absent(format!("none: {why}"));
    }
    let tier = if os == Os::Linux {
        "Isolated (Lightweight where bubblewrap cannot run)"
    } else {
        "Lightweight (macOS 13 or later)"
    };
    let text = match command(spec, os) {
        Some(command) => format!("{tier}: `{command}`"),
        None => tier.to_owned(),
    };
    claimed(text, ev.has(Claim::Run, host, os))
}

/// The agent's MCP servers: what OpenMoat wraps, and what starts before any
/// check.
pub fn mcp(host: Host, os: Os, ev: &Evidence<'_>) -> Cell {
    let Some(m) = &host.spec().mcp else {
        return absent("OpenMoat reads none of its MCP servers");
    };
    let mut text = if m.user_reader.syntax() == McpSyntax::Yaml {
        "pinned by `openmoat init`, which names its stdio servers and does not rewrite its file"
            .to_owned()
    } else {
        format!(
            "pinned by `openmoat init`, which offers to wrap its stdio servers: a wrapped one is \
             checked before it starts, {}",
            if os == Os::Windows {
                "with your permissions"
            } else {
                "in the OS sandbox"
            }
        )
    };
    if !m.project_files.is_empty() {
        let files = code_list(m.project_files.iter().map(|(f, _)| (*f).to_owned()));
        let _ = write!(
            text,
            "; a project's ({files}) are held until accepted, never wrapped"
        );
    }
    text.push_str("; a server not wrapped runs its command before any check");
    if m.auto_start.is_some() {
        text.push_str(", and settings can start a project's without asking");
    }
    claimed(text, ev.has(Claim::Mcp, host, os))
}

/// What a command the agent runs can read inside `openmoat run`.
pub fn credentials(host: Host, os: Os, ev: &Evidence<'_>) -> Cell {
    let spec = host.spec();
    if runs(spec, os).is_err() {
        return absent("— (no `openmoat run`)");
    }
    let globs: Vec<String> = spec
        .protect
        .credentials
        .iter()
        .flat_map(|p| p.globs.iter().map(|g| (*g).to_owned()))
        .collect();
    let login = if globs.is_empty() {
        "its own login files".to_owned()
    } else {
        format!("its own login ({})", code_list(globs))
    };
    let names: Vec<String> = spec
        .run_env
        .iter()
        .map(|n| (*n).to_owned())
        .chain(spec.install.as_ref().map(|i| i.dir_variable.to_owned()))
        .collect();
    let allowlist = if names.is_empty() {
        "the base list".to_owned()
    } else {
        format!("the base list and {}", code_list(names))
    };
    claimed(
        format!(
            "{login}, not another agent's; every inherited variable but a brokered secret, or \
             under `require.run: full-boundary` only {allowlist}"
        ),
        ev.has(Claim::Credentials, host, os),
    )
}

/// The table: one row per agent and OS.
pub fn table(hosts: &[Host], ev: &Evidence<'_>) -> Vec<String> {
    let mut lines = vec![
        "| Agent | OS | Hook | When the hook fails | Own sandbox | `openmoat run` | MCP servers | \
         Credentials a command can read in a run | Evidence |"
            .to_owned(),
        "|---|---|---|---|---|---|---|---|---|".to_owned(),
    ];
    for &host in hosts {
        let name = host.display_name();
        for os in Os::EVERY {
            lines.push(format!(
                "| {name} | {os} | {} | {} | {} | {} | {} | {} | [evidence](#{}) |",
                hook(host, os, ev).text,
                hook_failure(host, os, ev).text,
                sandbox(host, os, ev).text,
                run(host, os, ev).text,
                mcp(host, os, ev).text,
                credentials(host, os, ev).text,
                anchor(name)
            ));
        }
    }
    lines
}

/// A heading's anchor as GitHub and Starlight make it.
pub fn anchor(heading: &str) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect()
}

/// A cell of the summary: `label: word`.
fn word(label: &str, cell: &Cell, shown: &str, none: &str) -> String {
    let said = match cell.level {
        Level::Shown => shown.to_owned(),
        Level::Preview => "preview".to_owned(),
        Level::Absent => none.to_owned(),
    };
    format!("{label}: {said}")
}

/// The summary: per agent, what each OS gives it, in words a person reads.
pub fn summary(hosts: &[Host], ev: &Evidence<'_>) -> Vec<String> {
    let mut lines = vec![
        "| Agent | Linux | macOS | Windows |".to_owned(),
        "|---|---|---|---|".to_owned(),
    ];
    for &host in hosts {
        let cells: Vec<String> = Os::EVERY
            .into_iter()
            .map(|os| {
                let tier = match (run(host, os, ev).level, os) {
                    (Level::Absent, _) => "none".to_owned(),
                    (level, Os::Linux) => tier_word("Isolated", level),
                    (level, _) => tier_word("Lightweight", level),
                };
                [
                    word("hook", &hook(host, os, ev), "protected", "none"),
                    word("own sandbox", &sandbox(host, os, ev), "yes", "none"),
                    format!("`openmoat run`: {tier}"),
                ]
                .join("<br>")
            })
            .collect();
        lines.push(format!(
            "| {} | {} |",
            host.display_name(),
            cells.join(" | ")
        ));
    }
    lines
}

fn tier_word(tier: &str, level: Level) -> String {
    if level == Level::Shown {
        tier.to_owned()
    } else {
        format!("{tier} (preview)")
    }
}

/// The evidence behind each claim, per agent: the tests, the weekly job and
/// the fixtures, OS by OS.
pub fn evidence(hosts: &[Host], ev: &Evidence<'_>) -> Vec<String> {
    let mut lines = Vec::new();
    for &host in hosts {
        let spec = host.spec();
        lines.push(format!("### {}", host.display_name()));
        lines.push(String::new());
        for claim in Claim::EVERY {
            if !applies(claim, host) {
                continue;
            }
            let per_os: Vec<String> = Os::EVERY
                .into_iter()
                .filter(|os| claim_on(claim, host, *os, ev))
                .map(|os| format!("{os}: {}", sources(claim, host, os, ev)))
                .collect();
            if !per_os.is_empty() {
                lines.push(format!("- **{}**: {}.", claim.id(), per_os.join("; ")));
            }
        }
        let fixtures: Vec<String> = ev
            .records_of(host)
            .iter()
            .filter_map(|r| r.fixture.as_ref())
            .map(|f| format!("crates/openmoat-hosts/src/host/{f}"))
            .collect();
        if !fixtures.is_empty() {
            lines.push(format!(
                "- **fixtures** the weekly job sends `openmoat guard` in the agent's format: {}.",
                code_list(fixtures)
            ));
        }
        if spec.install.is_some() {
            let sources: Vec<String> = spec
                .hook_failure
                .sources
                .iter()
                .enumerate()
                .map(|(i, url)| format!("[{}]({url})", i + 1))
                .collect();
            lines.push(format!(
                "- **hook-failure facts** come from: {}.",
                sources.join(" ")
            ));
        }
        for record in ev.records_of(host) {
            if let Some(why) = &record.why {
                lines.push(format!(
                    "- The weekly job's `{}` run proves no hook call: {why}.",
                    record.agent
                ));
            }
        }
        lines.push(String::new());
    }
    lines.pop();
    lines
}

/// Whether `claim` is a claim the agent's specs make at all.
fn applies(claim: Claim, host: Host) -> bool {
    let spec = host.spec();
    match claim {
        Claim::Hook | Claim::HookFailure => spec.install.is_some(),
        Claim::Payloads => true,
        Claim::Sandbox => spec.sandbox.is_some(),
        Claim::Mcp => spec.mcp.is_some(),
        Claim::Run | Claim::Credentials => Os::EVERY.into_iter().any(|os| runs(spec, os).is_ok()),
    }
}

/// Whether `claim` is made for `host` on `os`.
fn claim_on(claim: Claim, host: Host, os: Os, ev: &Evidence<'_>) -> bool {
    let level = match claim {
        Claim::Hook => hook(host, os, ev).level,
        Claim::HookFailure => hook_failure(host, os, ev).level,
        Claim::Sandbox => sandbox(host, os, ev).level,
        Claim::Run => run(host, os, ev).level,
        Claim::Mcp => mcp(host, os, ev).level,
        Claim::Credentials => credentials(host, os, ev).level,
        Claim::Payloads => Level::Shown,
    };
    level != Level::Absent
}

/// The tests and weekly records behind `claim` for `host` on `os`, or `no
/// evidence yet`.
fn sources(claim: Claim, host: Host, os: Os, ev: &Evidence<'_>) -> String {
    let mut parts: Vec<String> = ev
        .tests(claim, host, os)
        .into_iter()
        .map(|t| format!("`{t}`"))
        .collect();
    let weekly = ev.weekly(claim, host, os);
    if !weekly.is_empty() {
        parts.push(format!(
            "the weekly `latest agents` job ({})",
            code_list(weekly.iter().map(|r| r.agent.clone()))
        ));
    }
    if parts.is_empty() {
        "no evidence yet".to_owned()
    } else {
        parts.join(", ")
    }
}
