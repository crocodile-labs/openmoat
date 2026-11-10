//! The way to an OS sandbox for an agent OpenMoat writes none for (ADR-076):
//! the exact `openmoat run` command, why there is none on this system, or why
//! none is offered for this agent. `moat status` and `moat doctor` print it.

use std::path::{Path, PathBuf};

use anyhow::Result;
use openmoat_hosts::{Host, RunFacts, RunWrite};
use serde::Serialize;

use crate::home::Home;
use crate::install::HostConfig;

/// How an agent without a sandbox of its own can get one here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum OsSandbox {
    /// This command starts it in `openmoat run`'s sandbox.
    Command {
        command: String,
        /// What the person must know before using it.
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// `openmoat run` cannot start it on this system.
    Unavailable { why: String },
    /// No command is offered for this agent ([`RunFacts::Unknown`]).
    Unknown { why: &'static str },
}

impl OsSandbox {
    /// The text of the row under the agent.
    pub fn line(&self) -> String {
        match self {
            Self::Command { command, note } => {
                let note = note.as_ref().map_or_else(String::new, |n| format!("; {n}"));
                format!("OS sandbox: {command} (docs/SANDBOX.md){note}")
            }
            Self::Unavailable { why } => format!("no OS sandbox on this system: {why}"),
            Self::Unknown { why } => format!("no `openmoat run` command offered: {why}"),
        }
    }
}

/// What `openmoat run` can do on this system, found once per report: on Linux
/// finding it starts `bwrap`.
#[derive(Debug, Clone)]
pub(super) struct RunHere {
    /// Why `openmoat run` has no sandbox here.
    unavailable: Option<String>,
    /// Why it would refuse a `--write` path outside the project: Linux
    /// without a network namespace (`docs/SANDBOX.md`).
    no_namespace: bool,
    /// `openmoat run`, with `--isolate` where plain `run` leaves the project open.
    start: &'static str,
}

impl RunHere {
    pub(super) fn detect() -> Self {
        Self {
            unavailable: crate::commands::run_unavailable(),
            no_namespace: crate::commands::run_port_only_network().is_some(),
            start: crate::commands::sandboxing_words(),
        }
    }
}

/// The way to an OS sandbox for `host` on this system.
pub(super) fn of(home: &Home, host: Host, here: &RunHere) -> Result<OsSandbox> {
    if let Some(why) = &here.unavailable {
        return Ok(OsSandbox::Unavailable { why: why.clone() });
    }
    let (program, args, writes) = match host.spec().run {
        RunFacts::Known {
            program,
            args,
            writes,
        } => (program, args, writes),
        RunFacts::Unknown { why } => return Ok(OsSandbox::Unknown { why }),
    };
    if here.no_namespace && !writes.is_empty() {
        return Ok(OsSandbox::Unavailable {
            why: format!(
                "`openmoat run` has no network namespace here, so it refuses a `--write` path \
                 outside the project, which {} needs; install bubblewrap and allow unprivileged \
                 user namespaces",
                host.display_name()
            ),
        });
    }
    let user = crate::home::user_home()?;
    let mut paths = Vec::with_capacity(writes.len());
    for write in writes {
        paths.push(path_of(home, host, *write, &user)?);
    }
    let command = line(here.start, &paths, program, args, &user);
    let note = (wrapped_servers(home, host)? > 0)
        .then(|| "its wrapped MCP servers do not start inside `openmoat run`".to_owned());
    Ok(OsSandbox::Command { command, note })
}

/// Where `write` is for `host` here.
fn path_of(home: &Home, host: Host, write: RunWrite, user: &Path) -> Result<PathBuf> {
    Ok(match write {
        RunWrite::ConfigDir => HostConfig::for_host(home, host)?.dir().to_path_buf(),
        RunWrite::Home(path) => user.join(path),
        RunWrite::Cache(name) if cfg!(target_os = "macos") => {
            user.join("Library/Caches").join(name)
        }
        RunWrite::Cache(name) => user.join(".cache").join(name),
    })
}

/// How many of `host`'s user-level servers run through `moat mcp proxy`, which
/// cannot read OpenMoat's state inside `openmoat run` and so refuses to start
/// them there (ADR-049).
fn wrapped_servers(home: &Home, host: Host) -> Result<usize> {
    let sources = crate::mcp::servers::sources(home, host, None)?;
    let scan = crate::mcp::servers::scan(&sources);
    Ok(scan
        .servers
        .iter()
        .filter(|s| crate::mcp::wrap::sandboxed(&s.entry, s.form).is_some())
        .count())
}

/// `start --write <path>… -- program args…`, a path below `user` as `~/…`.
fn line(start: &str, paths: &[PathBuf], program: &str, args: &[&str], user: &Path) -> String {
    let mut words = vec![start.to_owned()];
    for path in paths {
        words.push("--write".to_owned());
        words.push(word(path, user));
    }
    words.push("--".to_owned());
    words.push(program.to_owned());
    words.extend(args.iter().map(|a| (*a).to_owned()));
    words.join(" ")
}

/// `path` as one shell word.
fn word(path: &Path, user: &Path) -> String {
    let safe = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+@%:".contains(c))
    };
    if let Some(rest) = path.strip_prefix(user).ok().and_then(Path::to_str)
        && safe(rest)
    {
        return format!("~/{rest}");
    }
    let text = path.display().to_string();
    if safe(&text) {
        text
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_below_the_home_is_written_with_a_tilde() {
        let user = Path::new("/Users/me");
        let line = line(
            "openmoat run",
            &[PathBuf::from("/Users/me/.gemini"), PathBuf::from("/x/.y")],
            "gemini",
            &["--flag"],
            user,
        );
        assert_eq!(
            line,
            "openmoat run --write ~/.gemini --write /x/.y -- gemini --flag"
        );
    }

    #[test]
    fn a_path_a_shell_would_split_is_quoted() {
        let user = Path::new("/Users/me");
        assert_eq!(
            word(Path::new("/Users/me/my dir"), user),
            "'/Users/me/my dir'"
        );
        assert_eq!(word(Path::new("/o'x"), user), "'/o'\\''x'");
    }

    #[test]
    fn each_state_says_what_it_is() {
        let command = OsSandbox::Command {
            command: "openmoat run -- x".to_owned(),
            note: Some("n".to_owned()),
        };
        assert_eq!(
            command.line(),
            "OS sandbox: openmoat run -- x (docs/SANDBOX.md); n"
        );
        let off = OsSandbox::Unavailable {
            why: "macOS 12".to_owned(),
        };
        assert_eq!(off.line(), "no OS sandbox on this system: macOS 12");
        let unknown = OsSandbox::Unknown { why: "w" };
        assert_eq!(unknown.line(), "no `openmoat run` command offered: w");
    }

    /// Windows and macOS before 13 are named, with no command, before any
    /// file of the host is read.
    #[test]
    fn no_sandbox_here_is_said_before_the_facts_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::at(dir.path().join("state"));
        let here = RunHere {
            unavailable: Some("macOS before 13".to_owned()),
            no_namespace: false,
            start: "openmoat run",
        };
        for host in Host::EVERY {
            assert_eq!(
                of(&home, host, &here).unwrap(),
                OsSandbox::Unavailable {
                    why: "macOS before 13".to_owned()
                },
                "{host:?}"
            );
        }
    }
}
