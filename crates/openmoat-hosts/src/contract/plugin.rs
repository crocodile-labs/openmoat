//! The package a host's own plugin channel installs OpenMoat from
//! ([`super::HostSpec::plugin`], ADR-099): a thin shim around the `openmoat`
//! binary, generated into the repository's `plugins/` folder from the host's
//! spec (`openmoat_hosts::plugin::files`).
//!
//! Every package holds no binary and downloads nothing. It runs the
//! `openmoat` on the search path as `openmoat guard --host <id> --plugin`,
//! the hook command `openmoat init` writes plus the flag, and blocks the
//! call when there is no `openmoat` or it gives no answer. `openmoat init`
//! stays the source of the policy and its lock: without a lock the guard
//! denies every call and names `openmoat init`. Where `init`'s own hook is
//! installed and pinned for the host, the guard run from the package gives
//! the host's "no decision" ([`StandAside`]), so each call is decided once.

use crate::Host;
use crate::contract::Paths;

/// How a host installs OpenMoat from a channel of its own, or why it does not.
#[derive(Debug, Clone, Copy)]
pub enum Plugin {
    /// No package: the host's channel cannot carry OpenMoat's hook, or the
    /// hook `openmoat init` writes is already the channel's form. `openmoat
    /// init` is the way in; the text says why.
    None {
        /// Why there is no package, as `plugins/README.md` prints it.
        why: &'static str,
    },
    /// A package for the host's channel.
    Package(&'static PluginSpec),
}

/// A host's package and the channel it is published to.
#[derive(Debug)]
#[non_exhaustive]
pub struct PluginSpec {
    /// The channel, as people know it (`Claude Code plugin marketplace`).
    pub channel: &'static str,
    /// The one command (or step) a person takes in the host to install the
    /// package once it is published.
    pub install: &'static str,
    /// What a person must do to publish it there, in order.
    pub publish: &'static [&'static str],
    /// The official pages the package's layout follows.
    pub sources: &'static [&'static str],
    /// What the guard answers when `openmoat init`'s own hook decides the
    /// call in this host.
    pub stand_aside: StandAside,
    /// Where the host keeps OpenMoat's package once installed, under the home
    /// directory: only OpenMoat's own folder, never every plugin's. The
    /// default policy's `kernel-self` denies an agent writing there, from its
    /// generated block (`tests/protect.rs`); the settings that turn the
    /// package off are the host's own files, already in that rule.
    pub installed: Paths,
    /// The marketplace file that lists the package, for a channel whose
    /// marketplace is a repository of its own; `None` otherwise.
    pub marketplace: Option<Marketplace>,
    /// The package's files, relative to its folder (`plugins/<host id>/`).
    pub files: fn(Host, &Meta) -> Vec<PluginFile>,
}

/// What the guard run from a package answers when `openmoat init`'s hook for
/// the host is installed and pinned: the answer that never changes what
/// another hook of the host decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandAside {
    /// The host's "no decision", as the guard answers a `defer`: the host
    /// runs every hook and takes the strictest answer, or reads no output as
    /// no opinion.
    NoDecision,
    /// `allow`, for a host whose hooks have no "no decision" and which takes
    /// the strictest of every hook's answers, `deny` over `ask` over `allow`
    /// (Cursor): `allow` there leaves the other hook's answer as it is.
    Allow,
}

/// A marketplace file at the root of the `plugins/` folder that lists the
/// package by its folder, so the folder can be published as the
/// marketplace's repository.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Marketplace {
    /// The file, relative to `plugins/` (`.claude-plugin/marketplace.json`).
    pub file: &'static str,
    /// What goes before the folder's name in the entry's `source` (`./`).
    pub source_prefix: &'static str,
}

/// Facts every package shares, from the workspace.
#[derive(Debug, Clone, Copy)]
pub struct Meta {
    /// The release the package goes with.
    pub version: &'static str,
    /// The package's name in every channel.
    pub name: &'static str,
    /// The name shown to people.
    pub display_name: &'static str,
    /// One line on what it does.
    pub description: &'static str,
    /// The publisher.
    pub author: &'static str,
    /// The source repository.
    pub repository: &'static str,
    /// The documentation page.
    pub homepage: &'static str,
    /// The licence, as an SPDX expression.
    pub license: &'static str,
}

/// One file of a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginFile {
    /// The path, relative to the package's folder, with `/` separators.
    pub path: String,
    /// The contents.
    pub text: String,
    /// Whether the host runs the file itself (the guard script).
    pub executable: bool,
}

impl PluginFile {
    /// A file the host reads.
    #[must_use]
    pub fn data(path: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            text: text.into(),
            executable: false,
        }
    }

    /// A file the host runs.
    #[must_use]
    pub fn program(path: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            executable: true,
            ..Self::data(path, text)
        }
    }
}
