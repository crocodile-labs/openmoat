//! Package installs and the names they fetch from a registry (ADR-030).
//!
//! `npm install x`, `pip install y`, `cargo add z` and the like give one atom
//! `@package-install <ecosystem> <name>` per package the command line names,
//! and a name that is a near miss of a popular package (`crate::packages`)
//! also gives `@package-near-miss <ecosystem> <name> <popular name>`, which
//! the default policy's `package-near-miss` group asks for. Versions, extras
//! and options are taken off; paths, URLs, git sources and requirement files
//! name no registry package. An install from the lockfile or a requirements
//! file (`npm install`, `pip install -r requirements.txt`) gives no atom.

mod tools;

use super::{ClassifyError, Sink};
use crate::action::AtomicAction;
use crate::packages::{self, Ecosystem};
use tools::Tool;

/// The atom for a package a command installs.
pub(crate) const INSTALL: &str = "@package-install";
/// The atom for an installed name that is a near miss of a popular package.
pub(crate) const NEAR_MISS: &str = "@package-near-miss";

/// At most this many names of one command are checked.
const MAX_NAMES: usize = 64;

/// The install atoms of `argv`, whose program's base name is `program`.
pub(super) fn note(argv: &[String], program: &str, sink: &mut Sink) -> Result<(), ClassifyError> {
    let Some((ecosystem, names)) = requested(argv, program) else {
        return Ok(());
    };
    for name in names.into_iter().take(MAX_NAMES) {
        if let Some(popular) = packages::near_miss(ecosystem, &name) {
            sink.push(AtomicAction::Shell {
                argv: vec![
                    NEAR_MISS.to_owned(),
                    ecosystem.id().to_owned(),
                    name.clone(),
                    popular.to_owned(),
                ],
            })?;
        }
        sink.push(AtomicAction::Shell {
            argv: vec![INSTALL.to_owned(), ecosystem.id().to_owned(), name],
        })?;
    }
    Ok(())
}

/// The registry and the package names `argv` installs from it, if it is an
/// install; the names may be none (`npm install` from the lockfile).
pub(crate) fn requested(argv: &[String], program: &str) -> Option<(Ecosystem, Vec<String>)> {
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
