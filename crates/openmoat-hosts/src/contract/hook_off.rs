//! What a repository can do to a host's user hook before any call reaches it,
//! and what makes that hook outlast the repository (ADR-095): whether a file a
//! project holds turns OpenMoat's hook off when a session starts, an option of
//! the host's that keeps it on for one session, and the place an
//! administrator's hooks live, which a project's settings cannot turn off.
//!
//! The keys themselves are read by the host's [`crate::SettingsReader`]
//! (`project_switched_off`) over the files of its
//! [`crate::ProjectSettingsSpec`]; these facts say where the host documents it
//! and give one project file that does it, which every host's end-to-end test
//! writes and `openmoat run` must refuse.

use super::SystemFile;

/// A host's facts about a repository turning its hook off
/// ([`crate::HostSpec::hook_off`]).
#[derive(Debug)]
#[non_exhaustive]
pub struct HookOff {
    /// Whether a project's own files turn OpenMoat's user hook off.
    pub project: ProjectOff,
    /// An option of the host's that keeps the hook on for one session
    /// whatever a project's files say; `None` for a host with none.
    pub session_override: Option<SessionOverride>,
    /// Where an administrator's hooks live.
    pub managed: Managed,
}

impl HookOff {
    /// The value a host spec takes when it names none: nothing documented
    /// either way, which the registry's tests refuse.
    pub const BASE: HookOff = HookOff {
        project: ProjectOff::Nothing {
            why: "",
            source: "",
        },
        session_override: None,
        managed: Managed::None {
            why: "",
            source: "",
        },
    };
}

/// Whether a project's files turn a host's user hook off ([`HookOff::project`]).
#[derive(Debug)]
pub enum ProjectOff {
    /// A file the host loads from the project at session start can turn
    /// OpenMoat's hook off: what the host's reader names over its project
    /// settings files, and a plugin of its project plugin directory named as
    /// OpenMoat's.
    Files {
        /// One file that does it, relative to the project.
        example: ProjectFile,
        /// Where the host documents it, or the code that does it.
        source: &'static str,
    },
    /// Nothing a project holds turns the hook off.
    Nothing {
        /// Why, as the host documents it.
        why: &'static str,
        /// Where.
        source: &'static str,
    },
}

/// A file of a project and its whole text ([`ProjectOff::Files`]).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ProjectFile {
    /// Its path relative to the project, with `/` separators.
    pub path: &'static str,
    /// Its text.
    pub text: &'static str,
}

impl ProjectFile {
    /// The file at `path` holding `text`.
    #[must_use]
    pub const fn new(path: &'static str, text: &'static str) -> Self {
        Self { path, text }
    }
}

/// Arguments of the host's that keep its hooks on for one session whatever a
/// project's files set ([`HookOff::session_override`]).
#[derive(Debug)]
#[non_exhaustive]
pub struct SessionOverride {
    /// The arguments, placed before the person's own.
    pub args: &'static [&'static str],
    /// The top-level keys of a project file whose values these arguments
    /// replace for the session: a file that turns the hook off with these
    /// keys alone no longer does.
    pub keys: &'static [&'static str],
    /// Options of the person's own arguments that would take the place of
    /// [`Self::args`] (a second `--settings`): then they are not added.
    pub clashes: &'static [&'static str],
    /// Where the host documents it.
    pub source: &'static str,
}

/// Where an administrator's hooks live ([`HookOff::managed`]).
#[derive(Debug)]
pub enum Managed {
    /// `openmoat init --managed` writes OpenMoat's hook there.
    Written(ManagedHooks),
    /// The host has such a place, which OpenMoat protects but does not write.
    Manual {
        /// The files there, each on the platforms that read it.
        locations: &'static [SystemFile],
        /// Why OpenMoat does not write it, and what an administrator does.
        why: &'static str,
        /// Where the host documents it.
        source: &'static str,
    },
    /// The host documents none.
    None {
        /// What its documentation says instead.
        why: &'static str,
        /// Where.
        source: &'static str,
    },
}

impl Managed {
    /// The files of the place, each on the platforms that read it; none for
    /// [`Managed::None`].
    #[must_use]
    pub fn locations(&self) -> &'static [SystemFile] {
        match self {
            Self::Written(hooks) => hooks.files,
            Self::Manual { locations, .. } => locations,
            Self::None { .. } => &[],
        }
    }

    /// Where the host documents it.
    #[must_use]
    pub fn source(&self) -> &'static str {
        match self {
            Self::Written(hooks) => hooks.source,
            Self::Manual { source, .. } | Self::None { source, .. } => source,
        }
    }
}

/// The file `openmoat init --managed` writes OpenMoat's hook into
/// ([`Managed::Written`]). It holds the document `openmoat init` writes into
/// the person's own hook file, started from an empty one: the host reads
/// both in the same format.
#[derive(Debug)]
#[non_exhaustive]
pub struct ManagedHooks {
    /// The file, on each platform that reads it.
    pub files: &'static [SystemFile],
    /// How the host reads it.
    pub shape: ManagedShape,
    /// The host loads the file only when root owns it and no group or other
    /// account may write it: OpenMoat never writes it itself, it prints the
    /// command that installs it so.
    pub root_owned: bool,
    /// The host's documentation says a project's settings cannot turn a hook
    /// there off. Only then does `openmoat run` start an agent whose project
    /// would turn its user hook off once this file holds OpenMoat's hook.
    pub outlasts_project: bool,
    /// Sources that, when present, make the host skip this file altogether
    /// (Claude Code applies one managed source by default, a device
    /// management profile before the file); none for most hosts.
    pub shadowed_by: &'static [SystemFile],
    /// Where the host documents it.
    pub source: &'static str,
}

/// How a host reads the file of [`ManagedHooks::files`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedShape {
    /// A file of OpenMoat's own in a directory whose files the host merges
    /// (Claude Code's `managed-settings.d`): written and removed whole.
    DropIn,
    /// The host's one file there: written only while it is missing or holds
    /// OpenMoat's hook alone; an administrator's own file is never edited.
    WholeFile,
}
