//! Cursor backend: `sandbox.json` in Cursor's user directory (ADR-018).
//!
//! Key names are those of Cursor 3.23's `sandbox.json` reference
//! (<https://cursor.com/docs/reference/sandbox>) and Run Modes page
//! (<https://cursor.com/docs/agent/security/run-modes>). Cursor sandboxes the
//! terminal commands its agent runs; file tools stay with the hook. What the
//! generator relies on, as documented (not yet checked against a Cursor build):
//! - `type: "workspace_readwrite"` lets commands read and write the workspace and
//!   the temp directory; `additionalReadwritePaths` adds paths;
//! - `readBoundary: "workspace"` limits sandboxed reads to the workspace,
//!   `additionalReadPaths` and the system paths tools need (libraries,
//!   toolchains, certificate stores), and of `~/.ssh` only `known_hosts`;
//! - no key denies a path, so nothing can be closed inside a granted one: a
//!   grant with a denied path below it is left out, and what the policy denies
//!   inside the workspace stays open to sandboxed commands;
//! - `networkPolicy` allows only the listed domains when `default` is `deny`,
//!   `deny` wins over `allow`, and private and metadata addresses are blocked;
//! - a project's own `.cursor/sandbox.json` replaces `readBoundary` and
//!   `additionalReadPaths` and adds to the paths and network allowlist.

mod settings;

use anyhow::Result;
use openmoat_core::ir::{Access, Effect, Enforcement};
use openmoat_core::{AtomicAction, Kind};
use serde_json::{Map, Value, json};

pub use settings::{apply, in_sync, remove, weaknesses};

use super::Report;
use super::patterns::{
    Spot, domain, git_exclusion, is_below, literal_tree, push_unique, split, spot,
};

/// What OpenMoat writes into `sandbox.json`.
#[derive(Debug, Clone, PartialEq)]
pub struct Generated {
    /// The top-level keys OpenMoat owns; `networkPolicy` is owned key by key,
    /// so other keys in it survive.
    pub settings: Map<String, Value>,
    /// Losses and allowances of this backend.
    pub report: Report,
}

/// Generate `sandbox.json` for `ir`, lowered by [`super::lower_for_hosts`].
/// `proxy_port` cannot be honoured: Cursor has no proxy setting.
pub fn generate(ir: &Enforcement, proxy_port: Option<u16>) -> Result<Generated> {
    let mut report = Report::default();
    let checker = ir.checker()?;
    let open = |atom: AtomicAction| checker.check_os(&atom) == Some(Effect::Allow);
    let readable = |path: &str| {
        open(AtomicAction::FsRead {
            path: path.to_owned(),
        })
    };
    let writable = |path: &str| {
        readable(path)
            && open(AtomicAction::FsWrite {
                path: path.to_owned(),
            })
    };
    let mut reads = Grants::new(&ir.fs.read, Kind::FsRead, &mut report);
    reads.allow_rules(&ir.fs.read, &readable, &mut report);
    for allowance in ir.allowances.iter().filter(|a| a.kind == Kind::FsRead) {
        for root in allowance.patterns.iter().filter(|p| !p.ends_with("/**")) {
            reads.grant(root, &allowance.rule, &readable, &mut report);
        }
        report.allowances.push(allowance.clone());
    }
    let mut writes = Grants::new(&ir.fs.write, Kind::FsWrite, &mut report);
    writes.allow_rules(&ir.fs.write, &writable, &mut report);
    reads.report_open(&mut report);
    writes.report_open(&mut report);
    let mut settings = Map::new();
    settings.insert("type".into(), json!("workspace_readwrite"));
    settings.insert("readBoundary".into(), json!("workspace"));
    settings.insert("additionalReadPaths".into(), json!(reads.granted));
    settings.insert("additionalReadwritePaths".into(), json!(writes.granted));
    settings.insert("networkPolicy".into(), network(&ir.egress.net, &mut report));
    report_host_gaps(ir, proxy_port, &mut report);
    Ok(Generated { settings, report })
}

/// The paths granted for one access, and the denied patterns Cursor cannot
/// close where it grants (the workspace, and every granted path).
struct Grants {
    kind: Kind,
    granted: Vec<String>,
    /// Absolute denied patterns: a grant above one is left out.
    denied: Vec<String>,
    /// Denied patterns that point into the workspace or anywhere, which stay open.
    open: Vec<String>,
}

impl Grants {
    fn new(access: &Access, kind: Kind, report: &mut Report) -> Self {
        let mut grants = Self {
            kind,
            granted: Vec::new(),
            denied: Vec::new(),
            open: Vec::new(),
        };
        for rule in &access.deny {
            for pattern in split(&rule.patterns).0 {
                grants.close(pattern);
            }
        }
        if access.default == Effect::Allow {
            let message = match kind {
                Kind::FsRead => {
                    "Cursor's read boundary is the workspace: sandboxed commands read only it, \
                     the read allowlist and system paths"
                }
                _ => {
                    "Cursor allows writes only in the workspace, the temp directory and listed paths"
                }
            };
            report.loss(kind, "default", message.into());
        }
        grants
    }

    fn close(&mut self, pattern: &str) {
        match spot(pattern) {
            // a `.git` in a granted directory: like the workspace's, Cursor keeps
            // its hooks and config unwritable, and denying it would refuse the grant
            Spot::Absolute(path) if git_exclusion(pattern) => {
                push_unique(&mut self.open, path.to_owned());
            }
            Spot::Absolute(path) => push_unique(&mut self.denied, path.to_owned()),
            Spot::Project(rest) => push_unique(&mut self.open, format!("${{project}}/{rest}")),
            Spot::Anywhere(_) => push_unique(&mut self.open, pattern.to_owned()),
        }
    }

    /// Allow rules: the project is Cursor's workspace, a literal path is
    /// granted, and an exception becomes a denied pattern.
    fn allow_rules(
        &mut self,
        access: &Access,
        allowed: &dyn Fn(&str) -> bool,
        report: &mut Report,
    ) {
        for rule in &access.allow {
            let (positive, excluded) = split(&rule.patterns);
            for pattern in excluded {
                self.close(pattern);
            }
            for pattern in positive {
                match spot(pattern) {
                    Spot::Project(_) => {}
                    Spot::Absolute(path) if literal_tree(path).is_some() => {
                        self.grant(
                            literal_tree(path).unwrap_or(path),
                            &rule.id,
                            allowed,
                            report,
                        );
                    }
                    _ => report.loss(
                        self.kind,
                        &rule.id,
                        format!("`{pattern}` cannot be granted as a path, so it stays denied"),
                    ),
                }
            }
        }
    }

    /// Grant `path` unless the IR denies it or a denied path lies below it.
    fn grant(
        &mut self,
        path: &str,
        rule: &str,
        allowed: &dyn Fn(&str) -> bool,
        report: &mut Report,
    ) {
        if !allowed(path) {
            report.loss(
                self.kind,
                rule,
                format!("`{path}` is inside a denied path, so it is not granted"),
            );
        } else if let Some(below) = self.denied.iter().find(|d| is_below(d, path)) {
            report.loss(
                self.kind,
                rule,
                format!(
                    "`{path}` holds a denied path (`{below}`), and sandbox.json cannot close a \
                     path inside one it grants, so it is not granted"
                ),
            );
        } else {
            push_unique(&mut self.granted, path.to_owned());
        }
    }

    fn report_open(&self, report: &mut Report) {
        if self.open.is_empty() {
            return;
        }
        let (rule, verb, cursor_own) = match self.kind {
            Kind::FsRead => ("cursor.reads-in-workspace", "read", ""),
            _ => (
                "cursor.writes-in-workspace",
                "write",
                "; Cursor itself keeps `.cursor/*.json`, `.claude/**/*.json`, `.vscode`, \
                 `.git/hooks`, `.git/config` and `.git/info/attributes` unwritable",
            ),
        };
        report.allowance(
            self.kind,
            rule,
            self.open.clone(),
            &format!(
                "sandbox.json cannot deny a path, so sandboxed commands may {verb} these in the \
                 workspace and every granted path: {}{cursor_own}; the hook still decides \
                 Cursor's file tools",
                self.open.join(", ")
            ),
        );
    }
}

/// `networkPolicy`: Cursor gates only sandboxed commands, so the `net` rules
/// apply. Hosts that are not domain names (`169.254.*`) stay unlisted, so denied.
fn network(net: &Access, report: &mut Report) -> Value {
    let mut allowed = Vec::new();
    let mut denied = Vec::new();
    if net.default == Effect::Allow {
        let message = "sandbox.json is written to deny unlisted hosts: sandboxed commands reach \
                       only listed hosts";
        report.loss(Kind::Net, "default.net", message.into());
    }
    for rule in &net.deny {
        let (positive, _) = split(&rule.patterns);
        for pattern in positive.into_iter().filter(|p| domain(p)) {
            push_unique(&mut denied, pattern.to_owned());
        }
    }
    for rule in &net.allow {
        let (positive, excluded) = split(&rule.patterns);
        if !excluded.iter().all(|p| domain(p)) {
            let message =
                "an exception is not a domain name, so the whole rule is left out: denied";
            report.loss(Kind::Net, &rule.id, message.into());
            continue;
        }
        for pattern in excluded {
            push_unique(&mut denied, pattern.to_owned());
        }
        for pattern in positive {
            if domain(pattern) {
                push_unique(&mut allowed, pattern.to_owned());
            } else {
                report.loss(
                    Kind::Net,
                    &rule.id,
                    format!("`{pattern}` is not a domain name, so it stays denied"),
                );
            }
        }
    }
    json!({ "default": "deny", "allow": allowed, "deny": denied })
}

/// What Cursor does outside `sandbox.json`, which no key can change.
fn report_host_gaps(ir: &Enforcement, proxy_port: Option<u16>, report: &mut Report) {
    if ir.fs.read.default == Effect::Deny {
        report.loss(
            Kind::FsRead,
            "default",
            "Cursor's file tools ask before reading outside the workspace and the read \
             allowlist (readBoundary), where the hook may allow"
                .into(),
        );
    }
    let gaps: [(Kind, &str, &str); 5] = [
        (
            Kind::FsRead,
            "cursor.system-paths",
            "Cursor keeps the system paths tools need readable (system libraries, toolchains, \
             certificate stores), `~/.ssh/known_hosts`, its own project folder under \
             `~/.cursor/projects` and its skills, rules and plugins folders",
        ),
        (
            Kind::FsWrite,
            "cursor.workspace",
            "sandboxed commands may read and write the workspace Cursor opened and the temp \
             directory; OpenMoat's project is the git root, so a workspace opened above a \
             project grants more than the hook allows",
        ),
        (
            Kind::Net,
            "cursor.network-defaults",
            "Cursor's Network access setting decides whether sandbox.json applies: its default, \
             \"sandbox.json + Defaults\", adds Cursor's package-manager domains, and \"Allow All\" \
             ignores sandbox.json; choose \"sandbox.json Only\" in Cursor's settings",
        ),
        (
            Kind::FsRead,
            "cursor.project-file",
            "a project's own `.cursor/sandbox.json` replaces the read boundary and read \
             allowlist and adds paths and hosts; Cursor keeps sandboxed commands from writing \
             it, but a cloned repository can ship one",
        ),
        (
            Kind::Shell,
            "cursor.unsandboxed",
            "Cursor runs a command outside its sandbox when its Auto-review classifier approves \
             it (a command that cannot use the sandbox, or a rerun after a sandbox error), in \
             Run Everything mode, in Allowlist mode with sandboxing off, and in the CLI unless \
             it starts with `--sandbox enabled`; on Linux without Landlock v3 it asks instead",
        ),
    ];
    for (kind, rule, message) in gaps {
        report.allowance(kind, rule, Vec::new(), message);
    }
    if let Some(port) = proxy_port {
        report.allowance(
            Kind::Net,
            "cursor.proxy",
            Vec::new(),
            &format!(
                "sandbox.json has no proxy setting, so Cursor's own allowlist decides and its \
                 traffic does not reach `moat proxy` on 127.0.0.1:{port}: no address checks, \
                 audit log or brokered secrets for it"
            ),
        );
    }
}

#[cfg(test)]
mod tests;
