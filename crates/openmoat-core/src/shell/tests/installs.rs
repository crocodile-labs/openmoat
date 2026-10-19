//! Package installs: the names each package manager fetches, and the
//! near-miss atom for a name close to a popular package (ADR-030).

use super::{has_shell, parsed};
use crate::action::AtomicAction;
use crate::packages::Ecosystem;
use crate::shell::installs::requested;

fn names(cmd: &str) -> Option<(Ecosystem, Vec<String>)> {
    let argv: Vec<String> = cmd.split(' ').map(str::to_owned).collect();
    let program = crate::shell::program_name(&argv).to_owned();
    requested(&argv, &program)
}

fn installs(cmd: &str, ecosystem: Ecosystem, expected: &[&str]) {
    let (found, got) = names(cmd).unwrap_or_else(|| panic!("`{cmd}` is no install"));
    assert_eq!(found, ecosystem, "{cmd}");
    assert_eq!(got, expected, "{cmd}");
}

fn near_misses(cmd: &str) -> Vec<Vec<String>> {
    parsed(cmd)
        .into_iter()
        .filter_map(|a| match a {
            AtomicAction::Shell { argv } if argv[0] == "@package-near-miss" => Some(argv),
            _ => None,
        })
        .collect()
}

#[test]
fn every_package_manager_names_its_packages() {
    use Ecosystem::{Crates, Go, Npm, Pypi, Rubygems};
    installs("npm install lodash", Npm, &["lodash"]);
    installs(
        "npm i -D @types/node@20 lodash@^4.17",
        Npm,
        &["@types/node", "lodash"],
    );
    installs("npm add --save-dev vitest", Npm, &["vitest"]);
    installs("npm install --registry https://r.example x", Npm, &["x"]);
    installs("npm i my-lodash@npm:lodash@4", Npm, &["lodash"]);
    installs("pnpm add -D react react-dom", Npm, &["react", "react-dom"]);
    installs("pnpm --filter web add zod", Npm, &["zod"]);
    installs("yarn add axios", Npm, &["axios"]);
    installs("yarn global add typescript", Npm, &["typescript"]);
    installs("bun add hono", Npm, &["hono"]);
    installs(
        "pip install requests==2.32.0 flask<3",
        Pypi,
        &["requests", "flask"],
    );
    installs("pip3 install uvicorn[standard]>=0.30", Pypi, &["uvicorn"]);
    installs("pip3.12 install --user black", Pypi, &["black"]);
    installs("python -m pip install -U pip", Pypi, &["pip"]);
    installs("python3 -I -m pip install httpx", Pypi, &["httpx"]);
    installs("uv pip install ruff", Pypi, &["ruff"]);
    installs("uv add --dev pytest", Pypi, &["pytest"]);
    installs("uv tool install ruff", Pypi, &["ruff"]);
    installs("poetry add -G dev mypy", Pypi, &["mypy"]);
    installs("pipx install poetry", Pypi, &["poetry"]);
    installs("cargo add serde --features derive", Crates, &["serde"]);
    installs(
        "cargo add serde@1.0 -F derive tokio",
        Crates,
        &["serde", "tokio"],
    );
    installs("cargo +nightly install ripgrep", Crates, &["ripgrep"]);
    installs("cargo install --locked cargo-deny", Crates, &["cargo-deny"]);
    installs("gem install rails -v 7.1.0", Rubygems, &["rails"]);
    installs(
        "gem install rails:7.1.0 --no-document",
        Rubygems,
        &["rails"],
    );
    installs(
        "go get github.com/spf13/cobra@v1.8.0",
        Go,
        &["github.com/spf13/cobra"],
    );
    installs(
        "go install golang.org/x/tools/gopls@latest",
        Go,
        &["golang.org/x/tools/gopls"],
    );
}

#[test]
fn lockfile_installs_paths_and_other_sources_name_no_package() {
    for cmd in [
        "npm install",
        "npm ci",
        "npm i ./local-pkg",
        "npm i ../x.tgz",
        "npm i github:user/repo",
        "npm i user/repo",
        "npm i git+https://github.com/u/r.git",
        "pnpm install",
        "yarn",
        "pip install -r requirements.txt",
        "pip install -e .",
        "pip install ./dist/x-1.0-py3-none-any.whl",
        "pip install git+https://github.com/u/r",
        "uv pip install -r requirements.txt",
        "cargo install --path .",
        "cargo add --git https://github.com/u/r serde",
        "gem install ./x-1.0.gem",
        "go install ./...",
        "go get -u",
        "npm install $PKG",
    ] {
        assert!(names(cmd).is_none_or(|(_, n)| n.is_empty()), "{cmd}");
    }
    for cmd in [
        "npm run build",
        "pip list",
        "cargo build",
        "python script.py install x",
    ] {
        assert!(names(cmd).is_none(), "{cmd}");
    }
}

#[test]
fn a_near_miss_of_a_popular_package_is_its_own_atom() {
    assert!(has_shell(
        &parsed("pip install reqeusts"),
        "@package-near-miss pypi reqeusts requests"
    ));
    assert!(has_shell(
        &parsed("npm i lodahs"),
        "@package-near-miss npm lodahs lodash"
    ));
    assert!(has_shell(
        &parsed("cd app && pip3 install -q python-dateutl"),
        "@package-near-miss pypi python-dateutl python-dateutil"
    ));
    assert!(has_shell(
        &parsed("sh -c 'cargo add tokoi'"),
        "@package-near-miss crates tokoi tokio"
    ));
}

#[test]
fn an_ordinary_install_is_only_its_command() {
    // no atom of its own: one would fall to the catch-all and, strictest
    // wins, re-ask an install a rule allows
    for cmd in ["npm i left-pad", "pip install requests", "cargo add serde"] {
        let argv: Vec<String> = cmd.split(' ').map(str::to_owned).collect();
        assert_eq!(parsed(cmd), vec![AtomicAction::Shell { argv }], "{cmd}");
    }
    let atoms = parsed("npm i lodahs");
    assert_eq!(atoms.len(), 2, "{atoms:?}");
    assert!(has_shell(&atoms, "npm i lodahs"));
}

#[test]
fn popular_and_unknown_names_are_no_near_misses() {
    for cmd in [
        "pip install numpy pandas",
        "pip install requests",
        "npm i react react-dom",
        "npm i some-new-internal-pkg",
        "npm install left-pad-pro",
        "cargo add serde",
        "cargo add serde_json tokio --features full",
        "gem install rails",
        "go get github.com/stretchr/testify",
        "pip install -e .",
        "npm install",
    ] {
        assert!(near_misses(cmd).is_empty(), "{cmd}: {:?}", near_misses(cmd));
    }
}
