//! Option values that name files, in every spelling the tool accepts.
//!
//! `cmake -B/tmp/x` writes a build tree in `/tmp/x`, but the word starts with `-`
//! and has no `=`, so the generic argument scan sees no path in it. [`TOOLS`] lists,
//! per tool, the options whose value (the next word, after `=`, or attached to a
//! single letter: `-B dir`, `--outDir=dir`, `-Bdir`) is a file it reads, a
//! directory it writes, or code it loads; the last leaves the command unparseable,
//! so it asks whatever the policy allows. For every program, a short option with a
//! path attached (`-X/…`, `-X~/…`, `-X./…`, `-X../…`) is read and written, since
//! the classifier cannot tell which.

use super::tables::{MAKES, NO_FILE_OPERANDS};
use super::text::Operands;
use super::tokens::basename;
use super::{ClassifyError, ShellContext, Sink};
use crate::paths;

/// What a tool does with the path an option names.
#[derive(Debug, Clone, Copy)]
enum Use {
    Read,
    Write,
    /// Runs code from the file or module it names.
    Code,
}

/// How one tool takes path-valued options; each list is words separated by spaces.
struct Tool {
    programs: &'static [&'static str],
    reads: &'static str,
    writes: &'static str,
    code: &'static str,
    /// Short options whose attached value is data, a pattern or a character set
    /// (`grep -e/api/v1`, `tr -d/`), never a path.
    data: &'static str,
    /// Whole words that are flags, though they start with a valued option
    /// (`mvn -fae` is not `-f ae`).
    flags: &'static str,
    /// Go's flag package: `-name` and `--name` are the same, and a value is
    /// never attached to a single letter.
    go: bool,
}

const NONE: Tool = Tool {
    programs: &[],
    reads: "",
    writes: "",
    code: "",
    data: "",
    flags: "",
    go: false,
};

/// The tools `dev-shell` runs, and the package managers and compilers next to them.
const TOOLS: &[Tool] = &[
    Tool {
        programs: &["cmake"],
        reads: "-S",
        writes: "-B --build --install --prefix --install-prefix --graphviz",
        // an initial-cache, script or toolchain file is CMake code
        code: "-C -P --toolchain",
        ..NONE
    },
    Tool {
        programs: &["ctest"],
        reads: "--test-dir --resource-spec-file",
        writes: "-O --output-log --output-junit",
        code: "-S -SP -SR",
        ..NONE
    },
    Tool {
        programs: &["go"],
        reads: "-C -modfile -overlay -pgo",
        writes: concat!(
            "-o -pkgdir -outputdir -trace -coverprofile -cpuprofile -memprofile ",
            "-blockprofile -mutexprofile"
        ),
        go: true,
        ..NONE
    },
    Tool {
        programs: &["dotnet"],
        reads: "--project --configfile -s --settings",
        writes: "-o --output --artifacts-path --results-directory -d --diag",
        code: "--test-adapter-path",
        ..NONE
    },
    Tool {
        programs: &["mvn", "mvnw"],
        reads: concat!(
            "-f --file -s --settings -gs --global-settings ",
            "-t --toolchains -gt --global-toolchains"
        ),
        writes: "-l --log-file -Dmaven.repo.local",
        flags: "-fae -ff -fn -llr",
        ..NONE
    },
    Tool {
        programs: &["gradle", "gradlew"],
        reads: "-p --project-dir -c --settings-file -b --build-file",
        writes: "-g --gradle-user-home --project-cache-dir",
        code: "-I --init-script",
        ..NONE
    },
    Tool {
        programs: &["cargo"],
        reads: "--manifest-path -C --lockfile-path",
        writes: "--target-dir --artifact-dir --out-dir",
        // `--config` can set `build.rustc-wrapper` and other programs to run
        code: "--config",
        ..NONE
    },
    Tool {
        programs: &["grep", "egrep", "fgrep"],
        reads: "-f --file",
        data: "-e",
        ..NONE
    },
    Tool {
        programs: &["rg"],
        reads: "-f --file --ignore-file",
        data: "-e -g -t -T -r -M -E",
        ..NONE
    },
    Tool {
        programs: &["ag"],
        reads: "-p --path-to-ignore",
        data: "-G",
        ..NONE
    },
    // `tr` takes no option values; `tr -d/` deletes slashes
    Tool {
        programs: &["tr"],
        data: "-c -C -d -s -t",
        ..NONE
    },
    Tool {
        programs: MAKES,
        reads: "-C --directory -f --file --makefile -I --include-dir",
        ..NONE
    },
    Tool {
        programs: &["npm"],
        reads: "--userconfig --globalconfig",
        writes: "-C --prefix --cache",
        ..NONE
    },
    Tool {
        programs: &["tsc"],
        reads: "-p --project --rootDir --baseUrl",
        writes: "--outDir --outFile --declarationDir --tsBuildInfoFile",
        ..NONE
    },
    Tool {
        programs: &["pytest", "py.test"],
        reads: "-c --config-file --rootdir --confcutdir",
        writes: "--basetemp --junitxml --junit-xml --log-file --debug",
        // a plugin is a module pytest imports; `-p no:name` only disables one
        code: "-p",
        ..NONE
    },
    Tool {
        programs: &["uv"],
        reads: "--directory --project --config-file --env-file",
        writes: "--cache-dir",
        ..NONE
    },
    Tool {
        programs: &["rake"],
        reads: "-f --rakefile -I --libdir -R --rakelibdir -C --directory",
        code: "-r --require",
        ..NONE
    },
    Tool {
        programs: &["rspec"],
        reads: "-I -O --options --default-path",
        writes: "-o --out",
        code: "-r --require",
        ..NONE
    },
    Tool {
        programs: &["phpunit"],
        reads: "-c --configuration --include-path",
        writes: "--log-junit --coverage-html --coverage-clover --cache-directory",
        code: "--bootstrap",
        ..NONE
    },
];

impl Tool {
    fn options(&self) -> impl Iterator<Item = (&'static str, Use)> {
        let with = |list: &'static str, usage| list.split_whitespace().map(move |o| (o, usage));
        with(self.reads, Use::Read)
            .chain(with(self.writes, Use::Write))
            .chain(with(self.code, Use::Code))
    }
}

/// Turn path-valued options into `fs` atoms and add the words they consume to
/// `ops.data`, so the generic argument scan does not read them again.
pub(super) fn classify(
    argv: &[String],
    program: &str,
    ops: &mut Operands,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    let end = argv.iter().position(|a| a == "--").unwrap_or(argv.len());
    let (name, start) = subject(argv, program);
    let tool = TOOLS.iter().find(|t| t.programs.contains(&name));
    if let Some(tool) = tool {
        let mut i = start;
        while i < end {
            let found = (!ops.data.contains(&i)).then(|| option_value(tool, argv, i));
            let Some(found) = found.flatten() else {
                i += 1;
                continue;
            };
            ops.data.extend(i..i + found.words);
            if let Some(value) = found.value.filter(|v| !v.is_empty()) {
                apply(name, &found, value, ctx, sink)?;
            }
            i += found.words;
        }
    }
    if NO_FILE_OPERANDS.contains(&program) {
        return Ok(());
    }
    let data = |arg: &str| {
        tool.into_iter()
            .flat_map(|t| t.data.split_whitespace())
            .any(|o| arg.len() > o.len() && arg.starts_with(o))
    };
    for (i, arg) in argv.iter().enumerate().take(end).skip(1) {
        if let Some(path) = attached_path(arg).filter(|_| !ops.data.contains(&i) && !data(arg)) {
            sink.read(ctx, path)?;
            sink.write(ctx, path)?;
        }
    }
    Ok(())
}

/// The tool whose options the words from the returned index on are:
/// `python -m pytest …` is `pytest`, `bundle exec rspec …` is `rspec`.
fn subject<'a>(argv: &'a [String], program: &'a str) -> (&'a str, usize) {
    match (argv.get(1).map(String::as_str), argv.get(2)) {
        (Some("-m"), Some(module)) if program.starts_with("python") => (module, 3),
        (Some("exec"), Some(inner)) if program == "bundle" => (basename(inner), 3),
        _ => (program, 1),
    }
}

/// A path-valued option found at one argv index.
struct Found<'a> {
    option: &'static str,
    usage: Use,
    value: Option<&'a str>,
    /// The words it takes: 2 when the value is the next word.
    words: usize,
}

/// The path-valued option of `tool` at `argv[i]`, if it is one.
fn option_value<'a>(tool: &Tool, argv: &'a [String], i: usize) -> Option<Found<'a>> {
    let arg = argv[i].as_str();
    if tool.flags.split_whitespace().any(|f| f == arg) {
        return None;
    }
    // Go reads `--name` as `-name`.
    let word = match arg.strip_prefix('-') {
        Some(rest) if tool.go && rest.starts_with('-') => rest,
        _ => arg,
    };
    let found = |(option, usage), value, words| Found {
        option,
        usage,
        value,
        words,
    };
    let mut attached: Option<Found<'a>> = None;
    for entry in tool.options() {
        let option = entry.0;
        if word == option {
            return Some(found(entry, argv.get(i + 1).map(String::as_str), 2));
        }
        let Some(rest) = word.strip_prefix(option) else {
            continue;
        };
        if let Some(value) = rest.strip_prefix('=') {
            return Some(found(entry, Some(value), 1));
        }
        // Only a single-dash option takes its value attached, the longest that fits.
        let longer = attached
            .as_ref()
            .is_none_or(|a| a.option.len() < option.len());
        if !tool.go && !option.starts_with("--") && longer {
            attached = Some(found(entry, Some(rest), 1));
        }
    }
    attached
}

fn apply(
    program: &str,
    found: &Found<'_>,
    value: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    match found.usage {
        Use::Read => sink.read(ctx, value),
        Use::Write => sink.write(ctx, value),
        // `pytest -p no:name` disables a plugin instead of loading one
        Use::Code if found.option == "-p" && value.starts_with("no:") => Ok(()),
        Use::Code => {
            sink.skip(ClassifyError::LoadsCode {
                program: program.to_owned(),
                option: found.option.to_owned(),
            });
            sink.read(ctx, value)
        }
    }
}

/// The path attached to a short option (`-B/tmp/x`, `-o~/bin/app`,
/// `-I=../include`). A bare `~` is a backup suffix (`sed -i~`, `perl -i~`),
/// not the home directory, and a bare `/` is a separator or a set.
fn attached_path(arg: &str) -> Option<&str> {
    if arg.starts_with("--") {
        return None;
    }
    let mut chars = arg.strip_prefix('-')?.chars();
    chars.next()?;
    let rest = chars.as_str();
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    let bare = rest == "~" || rest.chars().all(|c| c == '/');
    (!bare && paths::looks_like_path(rest)).then_some(rest)
}
