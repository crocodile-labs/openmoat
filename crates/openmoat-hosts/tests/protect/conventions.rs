// The generated lines of the folders several hosts load by one convention
// (`Convention`, ADR-095): each once, after the hosts' own lines, under a
// line naming the hosts whose specs say they load it. Included by
// `tests/protect.rs` as its `conventions` module.

use std::fmt::Write as _;

use openmoat_hosts::{Convention, Host, Paths, RunsLater};

use super::{WIDTH, runs_later_lines};

/// The lines above a convention's generated lines, `\n`-separated: its name
/// and the hosts whose specs say they load it, wrapped as the hand-written
/// comments are.
pub fn convention_header(convention: &Convention) -> String {
    let hosts: Vec<&str> = convention
        .hosts()
        .into_iter()
        .map(Host::display_name)
        .collect();
    let text = format!("{}, loaded by {}:", convention.name, hosts.join(", "));
    let mut lines: Vec<String> = Vec::new();
    for word in text.split(' ') {
        match lines.last_mut() {
            Some(line) if line.len() + 1 + word.len() <= 80 => {
                line.push(' ');
                line.push_str(word);
            }
            _ => lines.push(word.to_owned()),
        }
    }
    lines.join("\n")
}

/// Each convention in use's `pick` lists, once, as `lines` writes a host's,
/// under [`convention_header`].
pub fn convention_lines(
    pick: fn(&Convention) -> &[Paths],
    comment: fn(&str) -> String,
    glob: fn(&str) -> String,
) -> String {
    let mut out = String::new();
    for convention in Convention::in_use() {
        let lists = pick(convention);
        if lists.is_empty() {
            continue;
        }
        for line in convention_header(convention).lines() {
            let _ = writeln!(out, "{}", comment(line));
        }
        for paths in lists {
            for line in paths.why.lines() {
                let _ = writeln!(out, "{}", comment(line));
            }
            for g in paths.globs {
                let _ = writeln!(out, "{}", glob(g));
            }
        }
    }
    out
}

/// Who a group of `runs-later` entries belongs to: each host, by its
/// display name, then each convention in use once, under its
/// [`convention_header`].
pub struct Group {
    /// The host's display name, or the convention's header.
    pub name: String,
    /// Whether it is a convention's, whose header leads its comments.
    pub convention: bool,
    pub entries: &'static [RunsLater],
}

pub fn runs_later_groups() -> Vec<Group> {
    let hosts = Host::EVERY.into_iter().map(|host| Group {
        name: host.display_name().to_owned(),
        convention: false,
        entries: host.spec().protect.runs_later,
    });
    let conventions = Convention::in_use().map(|c| Group {
        name: convention_header(c),
        convention: true,
        entries: c.runs_later,
    });
    hosts.chain(conventions).collect()
}

/// The shared skills folder is named by every host whose docs say it loads
/// it, and by no other; its globs are written once, in the convention, never
/// again in a host's own lists, and every `runs-later` entry is listed once.
#[test]
fn the_shared_skills_folder_is_one_fact_for_every_host_that_loads_it() {
    let skills = Convention::ALL
        .iter()
        .find(|c| c.name == openmoat_hosts::AGENT_SKILLS.name)
        .unwrap();
    let mut loaders = skills.hosts();
    loaders.sort_by_key(|h| h.display_name());
    let mut want = vec![
        Host::Codex,
        Host::Cursor,
        Host::CopilotCli,
        Host::Pi,
        Host::GeminiCli,
        Host::OpenCode,
        Host::Goose,
        Host::AntigravityCli,
        Host::Crush,
    ];
    want.sort_by_key(|h| h.display_name());
    // Claude Code (`.claude/skills`) and Cline (`.cline/skills`, `.clinerules/skills`,
    // `.claude/skills`) document no `.agents/skills`.
    assert_eq!(loaders, want);
    let globs: Vec<&str> = skills
        .runs_later
        .iter()
        .flat_map(|e| e.paths.globs.iter().copied())
        .chain(skills.taint.iter().flat_map(|p| p.globs.iter().copied()))
        .collect();
    for host in Host::EVERY {
        let protect = &host.spec().protect;
        let own = protect
            .runs_later
            .iter()
            .map(|e| &e.paths)
            .chain(protect.taint)
            .chain(protect.self_paths);
        for paths in own {
            for glob in paths.globs {
                assert!(!globs.contains(glob), "{host:?} lists {glob} itself");
            }
        }
    }
    let listed = openmoat_hosts::every_runs_later()
        .filter(|e| e.paths.globs.contains(&"**/.agents/skills/**"))
        .count();
    assert_eq!(listed, 1);
    let body = runs_later_lines();
    assert_eq!(
        body.matches("\"**/.agents/skills/**\"").count(),
        1,
        "{body}"
    );
    assert!(
        body.contains("# Agent Skills, loaded by Codex, Cursor,"),
        "{body}"
    );
    assert!(body.lines().all(|l| l.len() <= WIDTH), "{body}");
}
