//! Lightweight tier on Linux: the Landlock rules for one session (ADR-018).
//!
//! Landlock only grants: a rule allows reads or writes below a directory or on
//! a file, and nothing inside a granted tree can be denied again. So, unlike
//! Seatbelt, this backend is wider than the IR in listed places:
//! - a grant inside a denied path is not made, so the deny wins;
//! - a deny rule or `!` exception inside a granted tree (`**/.env` in the
//!   project, `~/.cargo/credentials.toml` in a read root) is not enforced, and
//!   is listed as an allowance; the hook still decides those accesses;
//! - a glob cannot be granted, so it stays denied (a loss);
//! - TCP connections are restricted by port only (ABI 4): the proxy's port is
//!   reachable on any host, unless `moat run` also gives the agent a network
//!   namespace (`commands/run/linux/netns.rs`), which drops this allowance;
//! - Landlock does not restrict UDP or connecting to Unix sockets: `moat run`'s
//!   seccomp filter (`super::seccomp`) closes them, so they are not listed.

use openmoat_core::ir::{Access, Checker, Effect, Enforcement};
use openmoat_core::{AtomicAction, Kind};
use serde::{Deserialize, Serialize};

use super::patterns::{Spot, literal_tree, push_unique, split, spot};
use super::{Grants, Report};

/// What every process reads and writes besides the policy's paths.
const PLATFORM_READ: [&str; 6] = [
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/pts",
];
const PLATFORM_WRITE: [&str; 4] = ["/dev/null", "/dev/zero", "/dev/tty", "/dev/pts"];

/// The paths and port the agent's processes may use; everything else is denied.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rules {
    /// Read and execute below these.
    pub read: Vec<String>,
    /// Read, write, create and remove below these.
    pub write: Vec<String>,
    /// The only TCP port connections may go to.
    pub connect_port: Option<u16>,
}

/// Generated rules.
#[derive(Debug, Clone)]
pub struct Generated {
    /// The rules `moat run` applies.
    pub rules: Rules,
    /// Losses and allowances of this backend.
    pub report: Report,
}

/// Generate the rules for `ir`, lowered for one session's project.
pub fn generate(ir: &Enforcement, grants: &Grants) -> anyhow::Result<Generated> {
    let checker = ir.checker()?;
    let mut g = Generated {
        rules: Rules {
            connect_port: grants.proxy_port,
            ..Rules::default()
        },
        report: Report::default(),
    };
    let own = |list: &[&str]| list.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
    let (read, write) = (Kind::FsRead, Kind::FsWrite);
    g.grant(
        read,
        "landlock.platform",
        own(&PLATFORM_READ),
        "every process reads these",
    );
    g.grant(
        write,
        "landlock.platform",
        own(&PLATFORM_WRITE),
        "the devices every process writes",
    );
    let program = grants.program.iter().cloned().collect();
    g.grant(
        read,
        "landlock.program",
        program,
        "the program `openmoat run` starts",
    );
    g.allows(&ir.fs.read, read, &checker);
    for allowance in &ir.allowances {
        let roots = allowance.patterns.iter().filter_map(|p| literal_tree(p));
        for root in roots.map(str::to_owned).collect::<Vec<_>>() {
            g.add(read, &allowance.rule, root, &checker);
        }
        g.report.allowances.push(allowance.clone());
    }
    g.allows(&ir.fs.write, write, &checker);
    let tmp = grants.tmpdir.iter().cloned().collect();
    g.grant(
        write,
        "landlock.tmpdir",
        tmp,
        "commands may read and write the temp directory",
    );
    let message = "`openmoat run --write`: commands may read and write these";
    g.grant(write, "landlock.write", grants.writes.clone(), message);
    g.unenforced(&ir.fs.read, read);
    g.unenforced(&ir.fs.write, write);
    if grants.proxy_port.is_some() {
        let message = "Landlock allows TCP connections by port only: the proxy's port is \
                       reachable on any host";
        g.report
            .allowance(Kind::Net, "landlock.tcp-port", Vec::new(), message);
    }
    g.report.proxy_only(&ir.egress.net);
    Ok(g)
}

impl Generated {
    /// Grant `paths` (fixed by the platform or the session) and list them.
    fn grant(&mut self, kind: Kind, id: &str, paths: Vec<String>, why: &str) {
        if paths.is_empty() {
            return;
        }
        for path in &paths {
            push_unique(self.list(kind), path.clone());
            if kind == Kind::FsWrite {
                push_unique(&mut self.rules.read, path.clone());
            }
        }
        self.report.allowance(kind, id, paths, why);
    }

    fn list(&mut self, kind: Kind) -> &mut Vec<String> {
        match kind {
            Kind::FsWrite => &mut self.rules.write,
            _ => &mut self.rules.read,
        }
    }

    /// The access's default, then the literal trees its allow rules name.
    fn allows(&mut self, access: &Access, kind: Kind, checker: &Checker) {
        if access.default == Effect::Allow {
            self.add(kind, "default", "/".to_owned(), checker);
        }
        for rule in &access.allow {
            for pattern in split(&rule.patterns).0 {
                match literal_tree(pattern) {
                    Some(tree) => self.add(kind, &rule.id, tree.to_owned(), checker),
                    None => self.report.loss(
                        kind,
                        &rule.id,
                        format!("`{pattern}` cannot be granted as a path, so it stays denied"),
                    ),
                }
            }
        }
    }

    /// Grant `path` from the IR unless a deny rule covers it.
    fn add(&mut self, kind: Kind, rule: &str, path: String, checker: &Checker) {
        let atom = match kind {
            Kind::FsWrite => AtomicAction::FsWrite { path: path.clone() },
            _ => AtomicAction::FsRead { path: path.clone() },
        };
        if checker.check_os(&atom) == Some(Effect::Deny) {
            let message = format!("`{path}` is inside a denied path, so it is not granted");
            self.report.loss(kind, rule, message);
        } else {
            push_unique(self.list(kind), path);
        }
    }

    /// Deny rules and `!` exceptions that fall inside a granted tree.
    fn unenforced(&mut self, access: &Access, kind: Kind) {
        let granted = self.list(kind).clone();
        // A pattern is inside a grant when the part before its first glob
        // character is the granted path or below it; `**/x` is anywhere.
        let inside = |pattern: &str| {
            let base = pattern
                .split(['*', '?', '[', '{'])
                .next()
                .unwrap_or(pattern);
            matches!(spot(pattern), Spot::Anywhere(_))
                || granted.iter().any(|g| {
                    base == g || base.starts_with(&format!("{}/", g.trim_end_matches('/')))
                })
        };
        let excluded = access.allow.iter().flat_map(|r| split(&r.patterns).1);
        let denied = access.deny.iter().flat_map(|r| split(&r.patterns).0);
        let mut patterns = Vec::new();
        for pattern in denied.chain(excluded).filter(|p| inside(p)) {
            push_unique(&mut patterns, pattern.to_owned());
        }
        if patterns.is_empty() {
            return;
        }
        let message = "Landlock cannot deny inside a granted directory, so these stay open where \
                       a grant covers them; the hook still decides them";
        self.report
            .allowance(kind, "landlock.inside-grants", patterns, message);
    }
}

#[cfg(test)]
mod tests;
