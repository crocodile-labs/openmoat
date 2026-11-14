//! Folders no one host owns that several hosts load by the same convention:
//! written once here, and named by each host whose own docs say it loads
//! them ([`HostSpec::conventions`](crate::HostSpec::conventions)). The
//! generated policy and taint blocks list a convention once, after the hosts'
//! own lines, with the hosts that name it (`tests/protect.rs`).

use super::{Paths, RunsLater};
use crate::Host;

/// A shared folder layout and how the default policy protects it.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Convention {
    /// What it is called, the comment's first words in the generated blocks.
    pub name: &'static str,
    /// Its files that run later, as a host's [`super::Protect::runs_later`].
    pub runs_later: &'static [RunsLater],
    /// Its writes that need review once the session read untrusted content,
    /// as a host's [`super::Protect::taint`].
    pub taint: &'static [Paths],
}

/// The Agent Skills folder (<https://agentskills.io>): `.agents/skills/<skill>/SKILL.md`
/// in a project, found from the working directory up to the project root, and
/// in the home. A skill's instructions and scripts load into the host's later
/// sessions; some hosts honour a skill's own allowed tools.
pub const AGENT_SKILLS: Convention = Convention {
    name: "Agent Skills",
    runs_later: &[
        RunsLater::agent_config(
            "the shared `.agents/skills` folder, whose skills these hosts load into their\n\
             later sessions (in the home too: `**/` matches it there)",
            &["**/.agents/skills/**"],
        ),
        RunsLater::review(
            "the folders above it (a rename away and back edits them)",
            &["**/.agents", "**/.agents/skills"],
        ),
    ],
    taint: &[Paths::new(
        "the shared `.agents/skills` folder and the folder above it",
        &["**/.agents", "**/.agents/skills", "**/.agents/skills/**"],
    )],
};

impl Convention {
    /// Every convention a host may name, in the generated blocks' order.
    pub const ALL: &'static [Convention] = &[AGENT_SKILLS];

    /// The hosts whose specs name this convention, in [`Host::EVERY`] order.
    #[must_use]
    pub fn hosts(&self) -> Vec<Host> {
        Host::EVERY
            .into_iter()
            .filter(|host| host.spec().conventions.iter().any(|c| c.name == self.name))
            .collect()
    }

    /// The conventions at least one host's spec names, each once.
    pub fn in_use() -> impl Iterator<Item = &'static Convention> {
        Self::ALL.iter().filter(|c| !c.hosts().is_empty())
    }
}

/// Every `runs-later` entry: each host's own, in [`Host::EVERY`] order, then
/// each convention in use once.
pub fn every_runs_later() -> impl Iterator<Item = &'static RunsLater> {
    Host::EVERY
        .into_iter()
        .flat_map(|host| host.spec().protect.runs_later)
        .chain(Convention::in_use().flat_map(|c| c.runs_later))
}
