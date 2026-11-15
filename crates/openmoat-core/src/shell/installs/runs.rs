//! Commands that fetch a package from a registry and run it in one step:
//! `npx`, `bunx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bun x`, `uvx`, `uv tool
//! run` and `pipx run`.
//!
//! They install into a cache and start the package's program at once, with
//! the person's permissions, so the package named is code that runs now. The
//! package is the value of the runner's package option (`-p`, `--package`,
//! `--from`, `--spec`) where it has one, otherwise the first word that is not
//! an option; `uv`'s `--with` adds one. A runner told never to download (`npx
//! --no`, `npx --no-install`, `uvx --offline`) fetches nothing, so it names none.

use crate::packages::Ecosystem;

/// One runner's grammar.
struct Runner {
    ecosystem: Ecosystem,
    /// The words after the program that start a run (`exec`, `tool run`).
    subcommand: &'static [&'static str],
    /// Options whose value is the package to fetch, in place of the first word.
    package: &'static [&'static str],
    /// Options whose value is a package fetched besides it.
    extra: &'static [&'static str],
    /// Other options followed by a value in the next word.
    values: &'static [&'static str],
    /// Options that mean nothing is fetched.
    offline: &'static [&'static str],
}

impl Runner {
    fn takes_value(&self, flag: &str) -> bool {
        [self.package, self.extra, self.values]
            .iter()
            .any(|list| list.contains(&flag))
    }
}

const NPM_VALUES: &[&str] = &[
    "-c",
    "--call",
    "--registry",
    "--cache",
    "--userconfig",
    "-w",
    "--workspace",
    "--prefix",
    "--loglevel",
    "-C",
    "--dir",
    "--cwd",
];

const fn npm(subcommand: &'static [&'static str]) -> Runner {
    Runner {
        ecosystem: Ecosystem::Npm,
        subcommand,
        package: &["-p", "--package"],
        extra: &[],
        values: NPM_VALUES,
        offline: &["--no", "--no-install", "--offline"],
    }
}

const UV_VALUES: &[&str] = &[
    "-p",
    "--python",
    "--with-requirements",
    "--with-editable",
    "--index",
    "--default-index",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "--directory",
    "--project",
    "--config-file",
    "--cache-dir",
    "--exclude-newer",
    "--color",
    "--env-file",
    "-C",
    "--config-setting",
];

const fn uv(subcommand: &'static [&'static str]) -> Runner {
    Runner {
        ecosystem: Ecosystem::Pypi,
        subcommand,
        package: &["--from"],
        extra: &["-w", "--with"],
        values: UV_VALUES,
        offline: &["--offline"],
    }
}

const PIPX_RUN: Runner = Runner {
    ecosystem: Ecosystem::Pypi,
    subcommand: &["run"],
    package: &["--spec"],
    extra: &[],
    values: &["--python", "--pip-args", "--index-url", "--backend"],
    offline: &[],
};

const NPX: Runner = npm(&[]);
const NPM_EXEC: [Runner; 2] = [npm(&["exec"]), npm(&["x"])];
const DLX: Runner = npm(&["dlx"]);
const BUN_X: Runner = npm(&["x"]);
const UVX: Runner = uv(&[]);
const UV_TOOL_RUN: Runner = uv(&["tool", "run"]);

/// The runners `program` may be.
fn runners(program: &str) -> &'static [Runner] {
    match program {
        "npx" | "bunx" | "pnpx" => std::slice::from_ref(&NPX),
        "npm" => &NPM_EXEC,
        "pnpm" | "yarn" => std::slice::from_ref(&DLX),
        "bun" => std::slice::from_ref(&BUN_X),
        "uvx" => std::slice::from_ref(&UVX),
        "uv" => std::slice::from_ref(&UV_TOOL_RUN),
        "pipx" => std::slice::from_ref(&PIPX_RUN),
        _ => &[],
    }
}

/// The registry and the package words `argv`, whose program's base name is
/// `program`, fetches and runs, if it is such a run; the words are as written
/// (`ruff@0.5`, `@scope/x@1`), not cleaned.
pub(super) fn fetched<'a>(argv: &'a [String], program: &str) -> Option<(Ecosystem, Vec<&'a str>)> {
    let operands = argv.get(1..)?;
    runners(program).iter().find_map(|runner| {
        let n = runner.subcommand.len();
        let starts = operands.len() >= n
            && operands[..n]
                .iter()
                .zip(runner.subcommand)
                .all(|(a, w)| a == w);
        if !starts {
            return None;
        }
        Some((runner.ecosystem, packages(&operands[n..], runner)?))
    })
}

/// The package words of a run's arguments `rest`; `None` when the runner
/// fetches nothing.
fn packages<'a>(rest: &'a [String], runner: &Runner) -> Option<Vec<&'a str>> {
    let mut named = Vec::new();
    let mut extra = Vec::new();
    let mut first = None;
    let mut words = rest.iter();
    while let Some(arg) = words.next() {
        if arg == "--" {
            first = words.next().map(String::as_str);
            break;
        }
        if !arg.starts_with('-') || arg.len() == 1 {
            first = Some(arg.as_str());
            break;
        }
        let (flag, attached) = match arg.split_once('=') {
            Some((f, v)) => (f, Some(v)),
            None => (arg.as_str(), None),
        };
        if runner.offline.contains(&flag) {
            return None;
        }
        let value = match attached {
            Some(v) => Some(v),
            None if runner.takes_value(flag) => words.next().map(String::as_str),
            None => None,
        };
        if runner.package.contains(&flag) {
            named.extend(value);
        } else if runner.extra.contains(&flag) {
            extra.extend(value);
        }
    }
    // With a package option the first word is one of its programs, not a package.
    if named.is_empty() {
        named.extend(first);
    }
    named.extend(extra);
    Some(named)
}
