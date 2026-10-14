//! Program and extension tables that drive classification.
//!
//! Data only; the modules next to this one hold the behaviour. Tables used by
//! a single module (`decoders`, `make`, `options`) live in that module.

pub const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish"];

/// Programs whose first non-option argument is itself a command to run.
pub const WRAPPERS: &[&str] = &[
    "sudo",
    "doas",
    "env",
    "nohup",
    "time",
    "nice",
    "ionice",
    "xargs",
    "command",
    "exec",
    "builtin",
    "timeout",
    "watch",
    "caffeinate",
    "stdbuf",
    "chroot",
    "unbuffer",
    "npx",
    "bunx",
];

/// Wrappers that take one positional value before the wrapped command.
pub const WRAPPERS_WITH_VALUE: &[&str] = &["timeout", "chroot"];

/// Package runners whose listed subcommand executes an arbitrary program
/// (`pnpm exec sh -c …`, `yarn dlx pkg`, `npm exec -- cmd`, `bun x pkg`,
/// `uv run cmd`).
pub const WRAPPER_SUBCOMMANDS: &[(&str, &[&str])] = &[
    ("pnpm", &["exec", "dlx"]),
    ("yarn", &["exec", "dlx"]),
    ("npm", &["exec", "x"]),
    ("bun", &["x"]),
    ("uv", &["run"]),
];

/// Package runners that accept a shell string via `-c`/`--call`.
pub const PACKAGE_RUNNERS: &[&str] = &["npx", "bunx", "npm", "pnpm", "yarn", "bun"];

/// Wrapper options that consume the following argument (`sudo -u root …`).
pub const WRAPPER_OPTIONS_WITH_VALUE: &[(&str, &[&str])] = &[
    (
        "sudo",
        &["-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t", "-D"],
    ),
    ("doas", &["-u", "-C"]),
    ("env", &["-u", "-C", "-S", "--unset", "--chdir"]),
    ("nice", &["-n"]),
    ("npx", &["-p", "--package"]),
    ("bunx", &["-p", "--package"]),
    ("ionice", &["-c", "-n", "-p"]),
    ("xargs", &["-I", "-L", "-n", "-P", "-s", "-d", "-E", "-a"]),
    ("timeout", &["-s", "-k", "--signal", "--kill-after"]),
    ("watch", &["-n", "-d"]),
    ("stdbuf", &["-i", "-o", "-e"]),
    ("exec", &["-a"]),
];

pub const ENV_BUILTINS: &[&str] = &["export", "declare", "typeset", "local", "readonly", "set"];

/// Build tools whose command line can carry shell code (`shell/make.rs`).
pub const MAKES: &[&str] = &["make", "gmake"];

pub const SOURCE_BUILTINS: &[&str] = &["source", "."];

/// Interpreters with an inline-code flag whose payload is scanned, not parsed as shell.
pub const INLINE_INTERPRETERS: &[(&str, &[&str])] = &[
    ("python", &["-c"]),
    ("python3", &["-c"]),
    ("node", &["-e", "--eval", "-p", "--print"]),
    ("deno", &["eval"]),
    ("bun", &["-e"]),
    ("perl", &["-e", "-E"]),
    ("ruby", &["-e"]),
    ("php", &["-r"]),
    ("osascript", &["-e"]),
    ("pwsh", &["-c", "-Command"]),
    ("powershell", &["-c", "-Command"]),
    ("lua", &["-e"]),
    ("luajit", &["-e"]),
    ("Rscript", &["-e"]),
];

/// The inline-code options of `program`, also when it is spelled with a version
/// (`python3.12`, `python2.7`, `ruby3.3`, `lua5.4`).
#[must_use]
pub fn inline_flags(program: &str) -> Option<&'static [&'static str]> {
    let exact = |p: &str| {
        INLINE_INTERPRETERS
            .iter()
            .find(|(n, _)| *n == p)
            .map(|(_, f)| *f)
    };
    exact(program).or_else(|| {
        let base = program.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
        let versioned = base.len() < program.len()
            && program[base.len()..].starts_with(|c: char| c.is_ascii_digit());
        // `python3.12` → `python3`, `python2.7` → `python`
        let base = if base == "python" { "python3" } else { base };
        versioned.then(|| exact(base)).flatten()
    })
}

/// Programs for which every path argument is a write.
pub const WRITE_ALL_PATHS: &[&str] = &[
    "rm", "rmdir", "touch", "mkdir", "chmod", "chown", "chgrp", "truncate", "unlink", "shred",
    "tee", "install", "mkfifo", "mknod", "mv",
];

/// Programs for which the last operand is a write and the others are reads.
pub const WRITE_LAST_PATH: &[&str] = &["cp", "ln", "rsync", "scp"];

/// Programs whose operands are files they read, so a plain name (`cat s`) is a
/// file read (`operands.rs`). Pattern operands (`grep foo .`) become reads of
/// a path that usually does not exist, which only costs a project-local atom.
pub const FILE_OPERANDS: &[&str] = &[
    "cat",
    "tac",
    "head",
    "tail",
    "less",
    "more",
    "bat",
    "nl",
    "od",
    "xxd",
    "hexdump",
    "strings",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "ack",
    "wc",
    "diff",
    "cmp",
    "sort",
    "uniq",
    "cut",
    "paste",
    "column",
    "base64",
    "base32",
    "md5",
    "md5sum",
    "shasum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "cksum",
    "file",
    "stat",
    "ls",
    "tree",
    "find",
    "du",
    "tar",
    "zip",
    "unzip",
    "gzip",
    "gunzip",
    "zcat",
    "bzip2",
    "xz",
    "jq",
    "yq",
    "gofmt",
    // interpreters read the script they run; later words are treated as files too
    "python",
    "python3",
    "node",
    "openssl",
    "ssh-keygen",
    "split",
    "fold",
    "fmt",
    "iconv",
    "awk",
    "sed",
    "vi",
    "vim",
    "nvim",
    "nano",
    "emacs",
    "code",
    "open",
];

/// Programs whose arguments are never files: `echo` and `printf` print them,
/// `tr` takes character sets. A `/` in them is text.
pub const NO_FILE_OPERANDS: &[&str] = &["echo", "printf", "tr"];

/// Words before a command that leave it running in the current shell, so a
/// `cd` after them still moves it (`builtin cd`, `if cd x; then`, `{ cd x; }`).
pub const CWD_PREFIXES: &[&str] = &[
    "builtin", "command", "time", "{", "!", "if", "then", "else", "elif", "while", "until", "do",
];

/// Shell reserved words that start a command inside a compound one: the command
/// after them is classified on its own (`do git log`, `if cat .env; then`).
pub const RESERVED_PREFIXES: &[&str] = &[
    "do", "then", "else", "elif", "if", "while", "until", "!", "{",
];

/// Reserved words that close a compound command and run nothing themselves.
pub const RESERVED_CLOSERS: &[&str] = &["done", "fi", "}", "esac"];

/// Builtins that may move the shell somewhere the classifier cannot see
/// (`cwd.rs`): `eval` and `source` may run a `cd`; `popd` returns to a
/// directory pushed before this command line.
pub const MAY_CHANGE_CWD: &[&str] = &["eval", "source", ".", "popd"];

/// Special parameters that are not environment variables.
pub const SPECIAL_PARAMS: &[char] = &['?', '$', '!', '#', '@', '*', '-', '0'];

/// Variables that are expanded by the classifier itself or carry no secret.
pub const IGNORED_VARS: &[&str] = &["HOME", "PWD", "OLDPWD", "USER", "SHELL", "TERM", "project"];

/// Programs whose arguments name hosts: a host-shaped word there is network
/// evidence (`Net`), elsewhere only a word that looks like one (`NetWord`, ADR-025).
pub const HOST_PROGRAMS: &[&str] = &[
    "curl",
    "wget",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "nc",
    "ncat",
    "netcat",
    "telnet",
    "ftp",
    "ping",
    "dig",
    "nslookup",
    "host",
    // more clients that connect where their arguments say
    "openssl",
    "socat",
    "mosh",
    "lftp",
    "aria2c",
    "nmap",
    "psql",
    "mysql",
    "redis-cli",
    "mongo",
    "mongosh",
    "http",
    "https",
    "xh",
    "curlie",
    "wget2",
    "whois",
    "traceroute",
    "mtr",
];

/// `git` subcommands whose arguments name a remote host ([`HOST_PROGRAMS`]).
pub const GIT_HOST_SUBCOMMANDS: &[&str] = &["clone", "fetch", "pull", "push", "ls-remote"];

/// Top-level domains accepted for a bare dotted token (no scheme). Dotted
/// identifiers in code (`sys.version`, `os.system`, `console.log`) and names
/// like `fix.bug` are not hosts; a token with a scheme is always one.
pub const KNOWN_TLDS: &[&str] = &[
    "com", "org", "net", "io", "dev", "ai", "co", "app", "sh", "me", "us", "uk", "de", "fr", "jp",
    "cn", "in", "ru", "br", "edu", "gov", "mil", "int", "info", "biz", "xyz", "cloud", "tech",
    "so", "to", "ly", "gg", "tv", "fm", "am", "is", "it", "nl", "se", "no", "fi", "dk", "ch", "at",
    "be", "es", "pt", "pl", "cz", "au", "nz", "ca", "mx", "ar", "cl", "kr", "tw", "hk", "sg", "id",
    "ph", "vn", "th", "il", "za", "ng", "ke", "eg", "ie", "eu", "asia", "online", "site", "store",
    "space", "live", "run", "page", "zone", "link", "click", "top", "pro", "name", "mobi",
    "network", "systems", "services", "digital", "email", "host", "cc", "ws", "nu", "la", "im",
    "pw", "tk", "ml", "ga", "cf", "gq", "onion", "local", "internal", "lan", "arpa", "ee", "lv",
    "lt", "ua", "by", "kz", "tr", "gr", "hu", "ro", "bg", "rs", "hr", "si", "sk", "pk", "bd", "lk",
    "np", "ir", "iq", "sa", "ae", "qa", "my", "pe", "ve", "uy", "ec",
];

/// Suffixes that make a dotted token a file name rather than a host.
pub const FILE_EXTENSIONS: &[&str] = &[
    "rs", "js", "ts", "tsx", "jsx", "mjs", "cjs", "py", "rb", "php", "go", "java", "kt", "swift",
    "c", "h", "cpp", "hpp", "cs", "md", "txt", "json", "yaml", "yml", "toml", "lock", "sh", "bash",
    "zsh", "html", "css", "scss", "vue", "svelte", "png", "jpg", "jpeg", "gif", "svg", "pdf",
    "zip", "tar", "gz", "tgz", "bz2", "xz", "log", "env", "cfg", "ini", "xml", "csv", "sql", "db",
    "sqlite", "wasm", "so", "dylib", "dll", "exe", "bin", "o", "a", "class", "jar", "war", "plist",
    "conf", "pem", "key", "crt",
];

/// Output redirection targets that are no file: the data sink and the
/// command's own standard output and error (`2>/dev/null`, `>&2` spelt as a
/// path). Compared with the resolved path; `/dev/tty`, `/dev/fd/3` and every
/// other device stay writes.
pub const STREAM_SINKS: &[&str] = &[
    "/dev/null",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/fd/1",
    "/dev/fd/2",
];

/// Input redirection sources that are no file: the empty source and the
/// command's own standard input (`</dev/null`).
pub const STREAM_SOURCES: &[&str] = &["/dev/null", "/dev/stdin", "/dev/fd/0"];
