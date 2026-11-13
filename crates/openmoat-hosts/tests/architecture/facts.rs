//! What each host's spec names it by, gathered from [`Host::EVERY`] so a new
//! host is scanned for without editing this file, and the one matcher that
//! finds those names in a piece of text.

use openmoat_hosts::{Host, McpFile, RunFacts};

/// Every name a host's spec gives it, deduplicated across hosts.
pub struct Facts {
    /// `codex`, `claude-code`: matched only where text uses an id as a host
    /// (quoted whole, a path component, after `--host`), so `continue` the
    /// id is not `--continue` the option.
    pub ids: Vec<&'static str>,
    /// `.codex`, `.pi/agent` and its first segment `.pi`: matched as a path
    /// segment (`~/.codex/config.toml`, `**/.codex/hooks.json`).
    pub dirs: Vec<&'static str>,
    /// `claude`, `cursor-agent`: matched as a whole word or path component.
    pub programs: Vec<&'static str>,
    /// `Claude Code`, `Gemini CLI`: matched as whole words.
    pub display_names: Vec<&'static str>,
    /// `settings.json`, `.claude.json`: one in the home directory matched as
    /// a path segment, any other only quoted whole.
    pub files: Vec<&'static str>,
}

/// Directories a host's spec names that are not the host's own: every XDG
/// program's `.config` (OpenCode's `.config/opencode`), and the repository's
/// `.github` (GitHub Copilot CLI's project settings), where CI's workflows
/// live too. A host's own directory below one (`.config/opencode`) is still
/// matched whole.
const SHARED_DIRS: &[&str] = &[".config", ".github"];

/// The characters a word, program or file name is made of; anything else
/// ends one.
fn is_name_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '.')
}

impl Facts {
    pub fn from_specs() -> Facts {
        let mut facts = Facts {
            ids: Vec::new(),
            dirs: Vec::new(),
            programs: Vec::new(),
            display_names: Vec::new(),
            files: Vec::new(),
        };
        for host in Host::EVERY {
            facts.add(host.spec());
        }
        // A name without an extension (Cline's hook file `PreToolUse`) is
        // also the event every host speaking Claude Code's format sends.
        facts.files.retain(|file| file.contains('.'));
        for list in [
            &mut facts.ids,
            &mut facts.dirs,
            &mut facts.programs,
            &mut facts.display_names,
            &mut facts.files,
        ] {
            list.retain(|name| !name.is_empty());
            list.sort_unstable();
            list.dedup();
        }
        facts
    }

    fn add(&mut self, spec: &'static openmoat_hosts::HostSpec) {
        self.ids.push(spec.id);
        self.display_names.push(spec.display_name);
        let mut dirs = Vec::new();
        if let Some(install) = &spec.install {
            dirs.push(install.dir_name);
            self.files.push(file_name(install.config_file));
            self.programs
                .extend(install.versions.as_ref().map(|v| v.program));
        }
        if let Some(detect) = &spec.detect {
            dirs.push(detect.dir_name);
            self.programs.push(detect.binary);
        }
        if let Some(project) = &spec.project_settings {
            dirs.push(project.dir);
            let named = [project.shared, project.user_file]
                .into_iter()
                .chain(project.local)
                .chain(project.more.iter().copied())
                .chain(project.user_more.iter().copied());
            self.files.extend(named.map(file_name));
        }
        if let Some(sandbox) = &spec.sandbox {
            self.files.push(file_name(sandbox.file));
        }
        if let Some(mcp) = &spec.mcp {
            self.files
                .extend(mcp_files(mcp.user_file).iter().map(|f| file_name(f)));
        }
        for dir in dirs.into_iter().filter(|dir| !SHARED_DIRS.contains(dir)) {
            self.dirs.push(dir);
            // `.pi` for `.pi/agent`
            self.dirs.extend(
                dir.split_once('/')
                    .map(|(first, _)| first)
                    .filter(|first| !SHARED_DIRS.contains(first)),
            );
        }
        self.programs.extend(spec.process.names.iter().copied());
        self.programs.push(spec.advisories.program);
        if let RunFacts::Known { program, .. } = spec.run {
            self.programs.push(program);
        }
    }

    /// The first of a host's names `text` uses, described for a failure
    /// message, or `None`.
    pub fn named_in(&self, text: &str) -> Option<String> {
        // Most text holds none of the names: rule it out before the matchers
        // build their patterns.
        let lists = [
            &self.ids,
            &self.dirs,
            &self.programs,
            &self.display_names,
            &self.files,
        ];
        if !lists
            .iter()
            .any(|list| list.iter().any(|name| text.contains(name)))
        {
            return None;
        }
        if let Some(id) = self.ids.iter().find(|id| names_id(text, id)) {
            return Some(format!("id `{id}`"));
        }
        if let Some(dir) = self.dirs.iter().find(|dir| names_dir(text, dir)) {
            return Some(format!("directory `{dir}`"));
        }
        let words = words(text);
        let word = |name: &&&str| {
            words
                .iter()
                .any(|w| w == *name || w.strip_suffix(".exe") == Some(**name))
        };
        if let Some(program) = self.programs.iter().find(word) {
            return Some(format!("program `{program}`"));
        }
        if let Some(file) = self.files.iter().find(|file| names_file(text, file)) {
            return Some(format!("file `{file}`"));
        }
        self.display_names
            .iter()
            .find(|name| names_phrase(text, name))
            .map(|name| format!("display name `{name}`"))
    }
}

/// The names a [`McpFile`] gives files of its own.
fn mcp_files(file: McpFile) -> Vec<&'static str> {
    match file {
        McpFile::HookFile => Vec::new(),
        McpFile::BesideHookFile(name)
        | McpFile::InConfigDir(name)
        | McpFile::BesideDefaultDir(name) => vec![name],
        McpFile::EachInConfigDir(names) => names.to_vec(),
    }
}

/// The last segment of a path.
fn file_name(path: &'static str) -> &'static str {
    path.rsplit('/').next().unwrap_or(path)
}

/// `text` split into words and program names; `claude` in `/tmp/claude-*`
/// too.
fn words(text: &str) -> Vec<&str> {
    text.split(|c: char| !is_name_char(c))
        .map(|w| w.trim_end_matches(['.', '-']))
        .filter(|w| !w.is_empty())
        .collect()
}

/// Each place `name` starts in `text` with `before` true of the character
/// before it (or the start) and `after` of the one after it (or the end).
fn bounded(
    text: &str,
    name: &str,
    before: impl Fn(Option<char>) -> bool,
    after: impl Fn(Option<char>) -> bool,
) -> bool {
    text.match_indices(name).any(|(at, _)| {
        before(text[..at].chars().next_back()) && after(text[at + name.len()..].chars().next())
    })
}

/// Whether `text` uses `id` as a host: quoted whole (`"codex"`, `'codex'`),
/// after `--host`, or as a whole path component (`hosts/codex/`). A bare
/// word is not enough: `continue` is a host's id and a shell keyword, and
/// `--continue` an option of `wget`.
fn names_id(text: &str, id: &str) -> bool {
    let quoted = ['"', '\'']
        .iter()
        .any(|q| text.contains(&format!("{q}{id}{q}")));
    let flag = ["--host ", "--host="].iter().any(|f| {
        bounded(
            text,
            &format!("{f}{id}"),
            |_| true,
            |c| !c.is_some_and(is_name_char),
        )
    });
    let edge = |c: Option<char>| c.is_none_or(|c| !is_name_char(c));
    let component = bounded(text, id, |c| c == Some('/'), edge)
        || bounded(text, id, |c| edge(c) && c != Some('-'), |c| c == Some('/'));
    quoted || flag || component
}

/// Whether `text` holds `dir` as a whole path segment (`~/.codex`,
/// `"**/.codex/config.toml"`), not as part of a longer name (`.codexrc`,
/// `.claude.json`).
fn names_dir(text: &str, dir: &str) -> bool {
    bounded(
        text,
        dir,
        |c| c.is_none_or(|c| !is_name_char(c)),
        |c| c.is_none_or(|c| !is_name_char(c)),
    )
}

/// Whether `text` names the host's file `file`: a file of the home directory
/// (`.claude.json`) as a path segment, as a directory is; any other
/// (`settings.json`, `config.toml`) only quoted whole, as code compares a
/// file name, since other programs' paths end in the same names
/// (`.cargo/config.toml`).
fn names_file(text: &str, file: &str) -> bool {
    if file.starts_with('.') {
        names_dir(text, file)
    } else {
        ['"', '\'']
            .iter()
            .any(|q| text.contains(&format!("{q}{file}{q}")))
    }
}

/// Whether `text` holds `phrase` as whole words (`pi,`, not `712-pi-dialog`).
fn names_phrase(text: &str, phrase: &str) -> bool {
    let edge = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric() && c != '-' && c != '_');
    bounded(text, phrase, edge, edge)
}
