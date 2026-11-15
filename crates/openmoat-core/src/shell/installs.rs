//! Package installs and the names they fetch from a registry (ADR-030).
//!
//! `npm install x`, `pip install y`, `cargo add z` and the like are read for
//! the packages the command line names. A name that is a near miss of a
//! popular package (`crate::packages`) gives `@package-near-miss <ecosystem>
//! <name> <popular name>`, which the default policy's `package-near-miss`
//! group holds for review. Any other install gives no atom of its own, so it decides
//! exactly as the command alone does: an atom for every install would fall to
//! the catch-all, and under strictest-wins hold for review again an install a rule allows.
//! Versions, extras and options are taken off; paths, URLs, git sources and
//! requirement files name no registry package, and an install from the
//! lockfile or a requirements file (`npm install`, `pip install -r
//! requirements.txt`) names none.
//!
//! A command that fetches a package and runs it at once (`npx x`, `uvx y`,
//! `pipx run z`, `runs.rs`) gives the same near-miss atom, and for a name
//! that is not on the popular list either `@package-run-unknown <ecosystem>
//! <name>`, which the default policy's `package-run-unknown` group holds for
//! review: the package's code runs now, and nothing says what it is. A popular
//! name gives no atom, as an install's does not.

mod runs;
mod tools;

use super::{ClassifyError, Sink};
use crate::action::AtomicAction;
use crate::packages::{self, Ecosystem};
use tools::Tool;

/// The atom for an installed name that is a near miss of a popular package.
pub(crate) const NEAR_MISS: &str = "@package-near-miss";

/// The atom for a package a runner fetches and runs at once whose name is
/// not on the popular list.
pub(crate) const UNKNOWN_RUN: &str = "@package-run-unknown";

/// The last word of an [`UNKNOWN_RUN`] atom whose name may be a program the
/// project installed rather than a package to fetch.
pub(crate) const MAY_BE_LOCAL: &str = "or-local-program";

/// At most this many names of one command are checked.
const MAX_NAMES: usize = 64;

/// The package atoms of `argv`, whose program's base name is `program`.
pub(super) fn note(argv: &[String], program: &str, sink: &mut Sink) -> Result<(), ClassifyError> {
    for argv in near_misses(argv, program)
        .into_iter()
        .chain(unknown_runs(argv, program))
    {
        sink.push(AtomicAction::Shell { argv })?;
    }
    Ok(())
}

/// Each `@package-near-miss <ecosystem> <name> <popular>` and
/// `@package-run-unknown <ecosystem> <name>` atom `command` gives, as one
/// line, wherever on the line the install or run is (`cd app && pip install
/// …`, `sh -c '…'`): what `moat allow --always` adds to its rule so the
/// package a person approved is not held for review again. Package names are
/// not paths, so the directories the command runs in do not matter here.
#[must_use]
pub fn package_atoms(command: &str) -> Vec<String> {
    let cwd = [Some("/".to_owned())];
    let ctx = super::ShellContext {
        home: "/",
        cwd: &cwd,
    };
    let (atoms, _) = super::classify_globs(command, &ctx).0.into_parts();
    let mut lines: Vec<String> = Vec::new();
    for atom in atoms {
        if let AtomicAction::Shell { argv } = atom
            && argv
                .first()
                .is_some_and(|tag| tag == NEAR_MISS || tag == UNKNOWN_RUN)
        {
            let line = argv.join(" ");
            if !lines.contains(&line) {
                lines.push(line);
            }
        }
    }
    lines
}

/// The `@package-near-miss <ecosystem> <name> <popular>` argv of each name
/// `argv` installs that is a near miss of a popular package.
fn near_misses(argv: &[String], program: &str) -> Vec<Vec<String>> {
    let Some((ecosystem, names)) = requested(argv, program) else {
        return Vec::new();
    };
    names
        .into_iter()
        .take(MAX_NAMES)
        .filter_map(|name| {
            let popular = packages::near_miss(ecosystem, &name)?;
            Some(vec![
                NEAR_MISS.to_owned(),
                ecosystem.id().to_owned(),
                name,
                popular.to_owned(),
            ])
        })
        .collect()
}

/// The `@package-run-unknown <ecosystem> <name>` argv of each package `argv`
/// fetches and runs at once whose name is neither popular nor a near miss of
/// a popular one (that gives its near-miss atom). A word that may be a
/// program the project installed (an npm runner's first word, with no
/// version and no package option: `npx tsc`) ends in [`MAY_BE_LOCAL`], so
/// the engine can ask whether the project has it (`engine/packages.rs`).
fn unknown_runs(argv: &[String], program: &str) -> Vec<Vec<String>> {
    let Some((ecosystem, words)) = runs::fetched(argv, program) else {
        return Vec::new();
    };
    let mut atoms: Vec<Vec<String>> = Vec::new();
    for fetched in words.into_iter().take(MAX_NAMES) {
        let Some(name) = clean(ecosystem, fetched.word) else {
            continue;
        };
        if packages::is_popular(ecosystem, &name) || packages::near_miss(ecosystem, &name).is_some()
        {
            continue;
        }
        let local = fetched.program_word && ecosystem == Ecosystem::Npm && fetched.word == name;
        let mut atom = vec![UNKNOWN_RUN.to_owned(), ecosystem.id().to_owned(), name];
        if local {
            atom.push(MAY_BE_LOCAL.to_owned());
        }
        if !atoms.contains(&atom) {
            atoms.push(atom);
        }
    }
    atoms
}

/// The registry and the package names `argv` installs from it, or fetches
/// and runs at once (`npx x`), if it does; the names may be none (`npm
/// install` from the lockfile).
pub(crate) fn requested(argv: &[String], program: &str) -> Option<(Ecosystem, Vec<String>)> {
    if let Some((ecosystem, words)) = runs::fetched(argv, program) {
        let names = words
            .into_iter()
            .filter_map(|w| clean(ecosystem, w.word))
            .collect();
        return Some((ecosystem, names));
    }
    let (tool, operands) = tools::find(argv, program)?;
    let rest = tool
        .subcommands
        .iter()
        .find_map(|words| after_subcommand(operands, words, tool))?;
    let mut names = Vec::new();
    let mut options_ended = false;
    let mut skip_value = false;
    for arg in rest {
        if skip_value {
            skip_value = false;
            continue;
        }
        if !options_ended && arg == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended && arg.starts_with('-') && arg.len() > 1 {
            let flag = arg.split_once('=').map_or(arg.as_str(), |(f, _)| f);
            // `cargo add --git URL name`: the names are not the registry's
            if tool.foreign.contains(&flag) {
                return Some((tool.ecosystem, Vec::new()));
            }
            skip_value = !arg.contains('=') && tool.values.contains(&flag);
            continue;
        }
        if let Some(name) = clean(tool.ecosystem, arg)
            && !names.contains(&name)
        {
            names.push(name);
        }
    }
    Some((tool.ecosystem, names))
}

/// The arguments after `words` (`["pip", "install"]`), when they are the
/// command's first words other than options and option values.
fn after_subcommand<'a>(args: &'a [String], words: &[&str], tool: &Tool) -> Option<&'a [String]> {
    let mut matched = 0;
    let mut skip_value = false;
    for (i, arg) in args.iter().enumerate() {
        if skip_value {
            skip_value = false;
            continue;
        }
        // `cargo +nightly add`: a toolchain, not a subcommand
        if (arg.starts_with('-') && arg.len() > 1) || arg.starts_with('+') {
            skip_value = !arg.contains('=') && tool.values.contains(&arg.as_str());
            continue;
        }
        if words.get(matched) != Some(&arg.as_str()) {
            return None;
        }
        matched += 1;
        if matched == words.len() {
            return Some(&args[i + 1..]);
        }
    }
    None
}

/// The registry name a package argument names, without version, extras or
/// markers; `None` for a path, a URL, an archive, a git source or a word
/// that is no package name.
fn clean(ecosystem: Ecosystem, word: &str) -> Option<String> {
    if word.contains("://") || word.starts_with(['.', '/', '~', '\\']) || is_archive(word) {
        return None;
    }
    let name = match ecosystem {
        Ecosystem::Npm => npm_name(word)?,
        Ecosystem::Pypi => {
            if word.contains(['/', '\\']) || word.starts_with("git+") {
                return None;
            }
            let end = word
                .find(['[', '=', '<', '>', '!', '~', ';', '@', ' ', '(', ','])
                .unwrap_or(word.len());
            word[..end].trim().to_owned()
        }
        Ecosystem::Crates => word.split('@').next()?.to_owned(),
        Ecosystem::Rubygems => {
            if word.contains('/') {
                return None;
            }
            word.split(':').next()?.to_owned()
        }
        Ecosystem::Go => {
            let module = word.split('@').next()?;
            // `go get ./...`, `go install std`: no module of a registry
            let host = module.split('/').next()?;
            if !host.contains('.') || module.contains("...") {
                return None;
            }
            module.to_owned()
        }
    };
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '@');
    let well_formed = !name.is_empty()
        && name.chars().all(allowed)
        && name.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '@')
        && name.split('/').all(|part| !part.is_empty());
    well_formed.then_some(name)
}

/// The package an npm argument names: `lodash@4` → `lodash`,
/// `@types/node@20` → `@types/node`, an alias `x@npm:lodash@4` → `lodash`.
fn npm_name(word: &str) -> Option<String> {
    let word = word.split_once("@npm:").map_or(word, |(_, real)| real);
    // `github:user/repo`, `file:../x`, `git+ssh:…`
    if word.contains(':') {
        return None;
    }
    if let Some(scoped) = word.strip_prefix('@') {
        let name = scoped.split('@').next()?;
        return (name.matches('/').count() == 1).then(|| format!("@{name}"));
    }
    let name = word.split('@').next()?;
    // `user/repo` is a GitHub repository
    (!name.contains('/')).then(|| name.to_owned())
}

fn is_archive(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    [
        ".whl", ".zip", ".tar.gz", ".tgz", ".tar", ".tar.bz2", ".gem", ".crate",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
}
