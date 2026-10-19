//! The package managers whose installs `installs.rs` reads: the subcommands
//! that install a named package, and the options that take a value.

use crate::packages::Ecosystem;

/// One package manager's install grammar.
#[derive(Debug)]
pub(super) struct Tool {
    pub(super) ecosystem: Ecosystem,
    /// The words that start an install (`install`, `pip install`).
    pub(super) subcommands: &'static [&'static [&'static str]],
    /// Options followed by a value in the next word (`-r FILE`, `--features X`).
    pub(super) values: &'static [&'static str],
    /// Options that take the names from another source than the registry.
    pub(super) foreign: &'static [&'static str],
}

const NPM: Tool = Tool {
    ecosystem: Ecosystem::Npm,
    // npm's own aliases of `install`
    subcommands: &[
        &["install"],
        &["i"],
        &["add"],
        &["in"],
        &["ins"],
        &["inst"],
        &["insta"],
        &["instal"],
        &["isnt"],
        &["isnta"],
        &["isntal"],
        &["isntall"],
    ],
    values: &[
        "--registry",
        "--tag",
        "-w",
        "--workspace",
        "--prefix",
        "--omit",
        "--include",
        "--install-strategy",
        "--cache",
        "--userconfig",
        "--before",
        "--save-prefix",
        "--loglevel",
        "--otp",
    ],
    foreign: &[],
};

const PNPM: Tool = Tool {
    ecosystem: Ecosystem::Npm,
    subcommands: &[&["add"]],
    values: &[
        "-C",
        "--dir",
        "--filter",
        "-F",
        "--registry",
        "--store-dir",
        "--reporter",
        "--loglevel",
        "--config",
    ],
    foreign: &[],
};

const YARN: Tool = Tool {
    ecosystem: Ecosystem::Npm,
    subcommands: &[&["add"], &["global", "add"]],
    values: &[
        "--cwd",
        "--registry",
        "--modules-folder",
        "--cache-folder",
        "--network-timeout",
        "--mutex",
    ],
    foreign: &[],
};

const BUN: Tool = Tool {
    ecosystem: Ecosystem::Npm,
    subcommands: &[&["add"], &["a"], &["install"], &["i"]],
    values: &[
        "--cwd",
        "-c",
        "--config",
        "--registry",
        "--cache-dir",
        "--backend",
        "--omit",
    ],
    foreign: &[],
};

/// pip's options with a value, global and `install` ones alike.
const PIP_VALUES: &[&str] = &[
    "-r",
    "--requirement",
    "-c",
    "--constraint",
    "-e",
    "--editable",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "-t",
    "--target",
    "--prefix",
    "--root",
    "--src",
    "--platform",
    "--python-version",
    "--implementation",
    "--abi",
    "--only-binary",
    "--no-binary",
    "--upgrade-strategy",
    "--trusted-host",
    "--cert",
    "--client-cert",
    "--cache-dir",
    "--log",
    "--proxy",
    "--timeout",
    "--retries",
    "--exists-action",
    "--progress-bar",
    "--report",
    "-C",
    "--config-settings",
    "--global-option",
    "--python",
    "--keyring-provider",
    "--root-user-action",
    "--group",
];

const PIP: Tool = Tool {
    ecosystem: Ecosystem::Pypi,
    subcommands: &[&["install"]],
    values: PIP_VALUES,
    foreign: &[],
};

const UV: Tool = Tool {
    ecosystem: Ecosystem::Pypi,
    subcommands: &[&["pip", "install"], &["add"], &["tool", "install"]],
    values: &[
        "-r",
        "--requirements",
        "--requirement",
        "-c",
        "--constraint",
        "--constraints",
        "--overrides",
        "-e",
        "--editable",
        "--index",
        "-i",
        "--index-url",
        "--default-index",
        "--extra-index-url",
        "-f",
        "--find-links",
        "-p",
        "--python",
        "--group",
        "--optional",
        "--extra",
        "--package",
        "--project",
        "--directory",
        "--branch",
        "--tag",
        "--rev",
        "-m",
        "--marker",
        "--target",
        "--prefix",
        "--exclude-newer",
        "--resolution",
        "--prerelease",
        "--index-strategy",
        "--keyring-provider",
        "--config-file",
        "--cache-dir",
        "--color",
        "--refresh-package",
        "--reinstall-package",
        "-P",
        "--upgrade-package",
        "--python-platform",
        "--link-mode",
        "--torch-backend",
        "-w",
        "--with",
        "--with-requirements",
        "--with-editable",
        "--from",
        "--script",
        "--bounds",
        "-C",
        "--config-setting",
    ],
    foreign: &[],
};

const POETRY: Tool = Tool {
    ecosystem: Ecosystem::Pypi,
    subcommands: &[&["add"]],
    values: &[
        "-G",
        "--group",
        "-E",
        "--extras",
        "--source",
        "--python",
        "--platform",
        "--markers",
        "-C",
        "--directory",
        "-P",
        "--project",
    ],
    foreign: &[],
};

const PIPX: Tool = Tool {
    ecosystem: Ecosystem::Pypi,
    subcommands: &[&["install"]],
    values: &[
        "--python",
        "--pip-args",
        "--suffix",
        "--index-url",
        "--preinstall",
    ],
    foreign: &[],
};

const CARGO: Tool = Tool {
    ecosystem: Ecosystem::Crates,
    subcommands: &[&["add"], &["install"]],
    values: &[
        "-F",
        "--features",
        "--branch",
        "--tag",
        "--rev",
        "--rename",
        "-p",
        "--package",
        "--manifest-path",
        "--target",
        "--lockfile-path",
        "-Z",
        "--config",
        "--color",
        "--version",
        "--vers",
        "--root",
        "--bin",
        "--example",
        "--profile",
        "--target-dir",
        "-j",
        "--jobs",
    ],
    foreign: &["--git", "--path", "--registry", "--index"],
};

const GEM: Tool = Tool {
    ecosystem: Ecosystem::Rubygems,
    subcommands: &[&["install"], &["i"]],
    values: &[
        "-v",
        "--version",
        "-i",
        "--install-dir",
        "-n",
        "--bindir",
        "--platform",
        "-P",
        "--trust-policy",
        "-g",
        "--file",
        "--build-root",
        "-p",
        "--http-proxy",
        "--target-rbconfig",
    ],
    foreign: &["-s", "--source", "--clear-sources"],
};

const GO: Tool = Tool {
    ecosystem: Ecosystem::Go,
    subcommands: &[&["get"], &["install"]],
    values: &[
        "-C",
        "-modfile",
        "-tags",
        "-ldflags",
        "-gcflags",
        "-asmflags",
        "-o",
        "-p",
        "-mod",
        "-pkgdir",
        "-overlay",
        "-pgo",
        "-toolexec",
        "-exec",
        "-buildmode",
        "-compiler",
        "-gccgoflags",
        "-installsuffix",
    ],
    foreign: &[],
};

/// The install grammar of `program` and the arguments it reads, if it is a
/// package manager: `python -m pip …` reads pip's arguments after `-m pip`.
pub(super) fn find<'a>(argv: &'a [String], program: &str) -> Option<(&'static Tool, &'a [String])> {
    let operands = argv.get(1..)?;
    let tool = match program {
        "npm" => &NPM,
        "pnpm" => &PNPM,
        "yarn" => &YARN,
        "bun" => &BUN,
        "uv" => &UV,
        "poetry" => &POETRY,
        "pipx" => &PIPX,
        "cargo" => &CARGO,
        "gem" => &GEM,
        "go" => &GO,
        p if versioned(p, "pip") => &PIP,
        p if versioned(p, "python") || p == "py" => {
            return Some((&PIP, after_module(operands)?));
        }
        _ => return None,
    };
    Some((tool, operands))
}

/// `pip`, `pip3`, `pip3.12` for `name` `pip`.
fn versioned(program: &str, name: &str) -> bool {
    program
        .strip_prefix(name)
        .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// An interpreter's arguments after `-m pip`, when that is the module it runs.
fn after_module(args: &[String]) -> Option<&[String]> {
    for (i, arg) in args.iter().enumerate() {
        match arg.as_str() {
            "-m" => {
                let module = args.get(i + 1)?;
                return versioned(module, "pip").then(|| &args[i + 2..]);
            }
            // `-c CODE`, or a script: the interpreter runs no module
            "-c" => return None,
            a if a.starts_with('-') => {}
            _ => return None,
        }
    }
    None
}
