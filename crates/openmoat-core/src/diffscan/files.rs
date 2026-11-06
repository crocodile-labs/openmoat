//! What kind of file a path names, for the checks that read it: by its name,
//! compared without letter case, as the path checks do (ADR-050).

use crate::packages::Ecosystem;

/// A package manifest the supply-chain checks read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Manifest {
    /// `package.json`.
    Npm,
    /// `requirements*.txt`, `constraints*.txt`.
    Requirements,
    /// `pyproject.toml`.
    PyProject,
    /// `Cargo.toml`.
    Cargo,
    /// `go.mod`.
    GoMod,
    /// `Gemfile`, `*.gemspec`.
    Gemfile,
}

/// A lockfile the supply-chain checks read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Lock {
    /// `package-lock.json`, `npm-shrinkwrap.json`.
    Npm,
    /// `pnpm-lock.yaml`.
    Pnpm,
    /// `yarn.lock`.
    Yarn,
    /// `Cargo.lock`.
    Cargo,
    /// `poetry.lock`, `uv.lock`.
    Python,
}

impl Lock {
    pub(super) fn ecosystem(self) -> Ecosystem {
        match self {
            Self::Npm | Self::Pnpm | Self::Yarn => Ecosystem::Npm,
            Self::Cargo => Ecosystem::Crates,
            Self::Python => Ecosystem::Pypi,
        }
    }
}

/// What a file is, for the checks that read only some kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// A GitHub workflow or action definition.
    Workflow,
    Dockerfile,
    /// Prose: a reader follows it, nothing runs it.
    Doc,
    /// Source code a program runs (for the encoded-blob check).
    Code,
    /// A dotenv file (`.env`, `.env.local`, `prod.env`, `.envrc`).
    Dotenv,
    /// A Python path configuration file.
    Pth,
    /// Anything else: configuration, data, scripts without an extension.
    Other,
}

/// What the checks know of one path.
#[derive(Debug)]
pub(super) struct File {
    pub manifest: Option<Manifest>,
    pub lock: Option<Lock>,
    pub kind: Kind,
    /// Under a test or fixture folder, or named as a test.
    pub test: bool,
}

impl File {
    pub(super) fn is(&self, kind: Kind) -> bool {
        self.kind == kind
    }
}

/// Extensions of prose files.
const DOC_EXTENSIONS: &[&str] = &["md", "markdown", "mdx", "rst", "adoc", "txt", "org"];
/// Names of prose files without an extension.
const DOC_NAMES: &[&str] = &[
    "license",
    "licence",
    "notice",
    "authors",
    "changelog",
    "copying",
];
/// Extensions of source code a program runs.
const CODE_EXTENSIONS: &[&str] = &[
    "js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx", "py", "rb", "sh", "bash", "zsh", "ps1",
    "psm1", "bat", "cmd", "go", "rs", "php", "pl", "pm", "java", "kt", "kts", "cs", "lua", "swift",
    "scala", "groovy", "gradle", "vbs",
];
/// Folder names (any depth) whose files are tests, fixtures or examples.
const TEST_DIRS: &[&str] = &[
    "test",
    "tests",
    "testdata",
    "test-data",
    "test_data",
    "testing",
    "fixtures",
    "fixture",
    "__fixtures__",
    "__tests__",
    "__mocks__",
    "mocks",
    "spec",
    "specs",
    "examples",
    "example",
];

pub(super) fn classify(path: &str) -> File {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let (dirs, name) = lower.rsplit_once('/').unwrap_or(("", &lower));
    let extension = name.rsplit_once('.').map(|(_, e)| e);
    let manifest = match name {
        "package.json" => Some(Manifest::Npm),
        "pyproject.toml" => Some(Manifest::PyProject),
        "cargo.toml" => Some(Manifest::Cargo),
        "go.mod" => Some(Manifest::GoMod),
        "gemfile" => Some(Manifest::Gemfile),
        _ if name.ends_with(".gemspec") => Some(Manifest::Gemfile),
        _ if (name.starts_with("requirements") || name.starts_with("constraints"))
            && extension.is_some_and(|e| matches!(e, "txt" | "in")) =>
        {
            Some(Manifest::Requirements)
        }
        _ => None,
    };
    let lock = match name {
        "package-lock.json" | "npm-shrinkwrap.json" => Some(Lock::Npm),
        "pnpm-lock.yaml" => Some(Lock::Pnpm),
        "yarn.lock" => Some(Lock::Yarn),
        "cargo.lock" => Some(Lock::Cargo),
        "poetry.lock" | "uv.lock" => Some(Lock::Python),
        _ => None,
    };
    let yaml = extension.is_some_and(|e| matches!(e, "yml" | "yaml"));
    let workflow = yaml
        && (format!("/{dirs}/").contains("/.github/workflows/") || name.starts_with("action."));
    let doc = manifest.is_none()
        && (extension.is_some_and(|e| DOC_EXTENSIONS.contains(&e))
            || DOC_NAMES.iter().any(|d| {
                // `LICENSE`, `LICENSE.md`, `LICENSE-APACHE`, `COPYING_GPL`
                name.strip_prefix(d)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '-', '_']))
            }));
    let dotenv =
        name == ".env" || name.starts_with(".env.") || extension == Some("env") || name == ".envrc";
    let dockerfile = name == "dockerfile"
        || name == "containerfile"
        || name.starts_with("dockerfile.")
        || extension == Some("dockerfile");
    let code = extension.is_some_and(|e| CODE_EXTENSIONS.contains(&e)) && !name.contains(".min.");
    let kind = if dotenv {
        Kind::Dotenv
    } else if extension == Some("pth") {
        Kind::Pth
    } else if workflow {
        Kind::Workflow
    } else if dockerfile {
        Kind::Dockerfile
    } else if doc {
        Kind::Doc
    } else if code {
        Kind::Code
    } else {
        Kind::Other
    };
    let test = dirs.split('/').any(|d| TEST_DIRS.contains(&d))
        || name.contains(".test.")
        || name.contains(".spec.")
        || name.contains("_test.")
        || name.starts_with("test_")
        || name.starts_with("test.")
        || name.starts_with("tests.")
        || name.contains("fixture");
    File {
        manifest,
        lock,
        kind,
        test,
    }
}

/// Whether `line` is only a comment in the common syntaxes (`//`, `#`, `/*`,
/// `*`, `<!--`, `;`, `REM`). Not `--`: a shell line continued with
/// `--url https://…` starts so too.
pub(super) fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    ["//", "#", "/*", "*", "<!--", ";", "rem ", "REM "]
        .iter()
        .any(|p| t.starts_with(p))
        && !t.starts_with("#!")
}
