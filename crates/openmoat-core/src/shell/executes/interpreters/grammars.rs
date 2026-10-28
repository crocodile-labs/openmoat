//! Each interpreter's option grammar, read by `interpreters.rs`.

/// How one interpreter reads its options.
#[derive(Default)]
pub(super) struct Grammar {
    /// Options taking the next word as their value (or `--name=value`).
    pub(super) values: &'static [&'static str],
    /// Options after which no program file runs: inline code, a version or
    /// help screen, a syntax check, a package script.
    pub(super) no_file: &'static [&'static str],
    /// Options whose value is a file or module loaded and run before the program.
    pub(super) preloads: &'static [&'static str],
    /// Options whose value is the program file.
    pub(super) file_options: &'static [&'static str],
    /// getopt-style clusters of one-letter options (`-uB`, `-pi.bak`, `-Ilib`).
    pub(super) cluster: Option<Cluster>,
    /// Options are read without case (`pwsh -FILE`).
    pub(super) any_case: bool,
    /// Only an operand that looks like a file names one (`bun run build` runs a
    /// `package.json` script, `bun run x.ts` the file).
    pub(super) file_like_only: bool,
}

/// The meaning of each letter in a cluster of one-letter options.
#[derive(Default, Clone, Copy)]
pub(super) struct Cluster {
    /// Letters after which no program file runs (`-c`, `-e`).
    pub(super) no_file: &'static str,
    /// Letters taking the rest of the word as their value, or the next word
    /// when they end it (`-W error`, `-Ilib`).
    pub(super) value: &'static str,
    /// Letters taking only the rest of the word, possibly empty (`-i.bak`, `-0777`).
    pub(super) glued: &'static str,
    /// The letter whose value is a module (`python -m`).
    pub(super) module: Option<char>,
    /// Letters whose value is a file or library loaded before the program (`ruby -r`).
    pub(super) preload: &'static str,
}

pub(super) const PYTHON: Grammar = Grammar {
    values: &["--check-hash-based-pycs"],
    no_file: &[
        "--help",
        "--version",
        "--help-env",
        "--help-xoptions",
        "--help-all",
    ],
    cluster: Some(Cluster {
        no_file: "chV?",
        value: "WX",
        glued: "",
        module: Some('m'),
        preload: "",
    }),
    ..EMPTY
};

pub(super) const PERL: Grammar = Grammar {
    no_file: &["--help", "--version"],
    cluster: Some(Cluster {
        no_file: "eEhvc",
        value: "I",
        glued: "MmxilCdD0V",
        module: None,
        preload: "",
    }),
    ..EMPTY
};

pub(super) const RUBY: Grammar = Grammar {
    values: &["--encoding", "--external-encoding", "--internal-encoding"],
    no_file: &["--help", "--version", "--yydebug"],
    cluster: Some(Cluster {
        no_file: "ech",
        value: "ICEFr",
        glued: "xKTW0",
        module: None,
        preload: "r",
    }),
    ..EMPTY
};

pub(super) const NODE: Grammar = Grammar {
    values: &[
        "-r",
        "--require",
        "--import",
        "--loader",
        "--experimental-loader",
        "--input-type",
        "--env-file",
        "--env-file-if-exists",
        "-C",
        "--conditions",
        "--title",
        "--inspect-port",
        "--test-reporter",
        "--test-reporter-destination",
        "--test-name-pattern",
        "--watch-path",
    ],
    no_file: &[
        "-e",
        "--eval",
        "-p",
        "--print",
        "-v",
        "--version",
        "-h",
        "--help",
        "-c",
        "--check",
        "-i",
        "--interactive",
        "--run",
        "--v8-options",
    ],
    preloads: &[
        "-r",
        "--require",
        "--import",
        "--loader",
        "--experimental-loader",
    ],
    ..EMPTY
};

pub(super) const DENO_RUN: Grammar = Grammar {
    values: &[
        "-c",
        "--config",
        "--import-map",
        "--lock",
        "--cert",
        "--location",
        "--seed",
        "--ext",
        "-L",
        "--log-level",
        "--preload",
    ],
    no_file: &["-h", "--help"],
    preloads: &["--preload"],
    ..EMPTY
};

pub(super) const BUN: Grammar = Grammar {
    values: &[
        "--cwd",
        "-c",
        "--config",
        "--env-file",
        "--tsconfig-override",
        "--port",
        "--main-fields",
        "--extension-order",
        "--define",
        "-d",
        "--loader",
        "-l",
        "--external",
        "--filter",
        "-F",
        "-r",
        "--preload",
        "--require",
        "--import",
    ],
    no_file: &[
        "-e",
        "--eval",
        "-p",
        "--print",
        "-v",
        "--version",
        "-h",
        "--help",
    ],
    preloads: &["-r", "--preload", "--require", "--import"],
    file_like_only: true,
    ..EMPTY
};

pub(super) const PHP: Grammar = Grammar {
    values: &[
        "-c",
        "--php-ini",
        "-d",
        "--define",
        "-z",
        "--zend-extension",
        "-t",
        "--docroot",
        "-S",
        "--server",
    ],
    no_file: &[
        "-r",
        "--run",
        "-R",
        "--process-code",
        "-B",
        "--process-begin",
        "-E",
        "--process-end",
        "-v",
        "--version",
        "-h",
        "--help",
        "-i",
        "--info",
        "-m",
        "--modules",
        "-l",
        "--syntax-check",
        "-a",
        "--interactive",
        "-s",
        "--syntax-highlight",
        "-w",
        "--strip",
    ],
    file_options: &["-f", "--file", "-F", "--process-file"],
    ..EMPTY
};

pub(super) const PWSH: Grammar = Grammar {
    values: &[
        "-executionpolicy",
        "-ex",
        "-ep",
        "-exe",
        "-exec",
        "-workingdirectory",
        "-wd",
        "-wo",
        "-configurationname",
        "-config",
        "-outputformat",
        "-o",
        "-of",
        "-inputformat",
        "-if",
        "-inp",
        "-windowstyle",
        "-w",
        "-settingsfile",
        "-custompipename",
        "-configurationfile",
        "-encodedarguments",
        "-ea",
    ],
    no_file: &[
        "-command",
        "-c",
        "-co",
        "-com",
        "-comm",
        "-encodedcommand",
        "-e",
        "-ec",
        "-en",
        "-enc",
        "-version",
        "-v",
        "-help",
        "-h",
        "-?",
    ],
    file_options: &["-file", "-f", "-fi", "-fil"],
    any_case: true,
    ..EMPTY
};

pub(super) const TSX: Grammar = Grammar {
    values: &["--tsconfig", "--env-file", "--import", "--require", "-r"],
    no_file: &[
        "-e",
        "--eval",
        "-p",
        "--print",
        "-v",
        "--version",
        "-h",
        "--help",
    ],
    preloads: &["--import", "--require", "-r"],
    ..EMPTY
};

pub(super) const TS_NODE: Grammar = Grammar {
    values: &[
        "-P",
        "--project",
        "-O",
        "--compiler-options",
        "-C",
        "--compiler",
        "--cwd",
        "-I",
        "--ignore",
        "--dir",
        "--scope-dir",
        "-r",
        "--require",
    ],
    no_file: &[
        "-e",
        "--eval",
        "-p",
        "--print",
        "-v",
        "--version",
        "-h",
        "--help",
        "-i",
        "--interactive",
    ],
    preloads: &["-r", "--require"],
    ..EMPTY
};

pub(super) const LUA: Grammar = Grammar {
    values: &["-e", "-l"],
    no_file: &["-v"],
    ..EMPTY
};

pub(super) const RSCRIPT: Grammar = Grammar {
    no_file: &["-e", "--version", "--help"],
    ..EMPTY
};

pub(super) const OSASCRIPT: Grammar = Grammar {
    values: &["-l", "-s"],
    no_file: &["-e"],
    ..EMPTY
};

pub(super) const EMPTY: Grammar = Grammar {
    values: &[],
    no_file: &[],
    preloads: &[],
    file_options: &[],
    cluster: None,
    any_case: false,
    file_like_only: false,
};

/// `go run` build flags that take a value.
pub(super) const GO_RUN_VALUES: &[&str] = &[
    "-C",
    "-p",
    "-tags",
    "-ldflags",
    "-gcflags",
    "-asmflags",
    "-gccgoflags",
    "-mod",
    "-modfile",
    "-overlay",
    "-pkgdir",
    "-toolexec",
    "-exec",
    "-buildmode",
    "-compiler",
    "-installsuffix",
    "-pgo",
    "-covermode",
    "-coverpkg",
    "-o",
];

/// `deno` subcommands, so `deno x.ts` (Deno 2 runs a file named first) is told
/// from `deno fmt`.
pub(super) const DENO_SUBCOMMANDS: &[&str] = &[
    "add",
    "bench",
    "cache",
    "check",
    "clean",
    "compile",
    "completions",
    "coverage",
    "doc",
    "eval",
    "fmt",
    "help",
    "info",
    "init",
    "install",
    "jupyter",
    "lint",
    "lsp",
    "outdated",
    "publish",
    "remove",
    "repl",
    "task",
    "test",
    "types",
    "uninstall",
    "upgrade",
    "vendor",
    "x",
];
