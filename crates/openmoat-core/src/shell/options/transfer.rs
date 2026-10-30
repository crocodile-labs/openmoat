//! One reading of a `curl` or `wget` command line, shared by the fetch check
//! (ADR-035, `commands/fetch.rs`) and the files the command writes.
//!
//! Short options cluster as getopt reads them (`-sSo out`, `-oout`, `-fsSo.envrc`,
//! `wget -qO file`): a letter that takes a value takes the rest of the word, or
//! the next word when nothing is left. A long option takes `--name=value`, or the
//! next word when it is one that takes a value. wget (getopt) and curl before 8.3
//! also accept an unambiguous prefix of a long name (`--output-doc`), so a prefix
//! of exactly one known name is read as that name. A letter or a name these tables
//! do not know is read as a flag: its value, if it has one, is then read as an
//! operand or an option of its own, which only adds writes (stricter).

/// The program a command line is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::shell) enum Client {
    Curl,
    Wget,
}

/// curl's short options that take a value (curl 8).
const CURL_SHORT_VALUED: &str = "AbcCdDeEFHKmoPQrtTuUwxXYyz";
/// wget's short options that take a value; `-n` takes the letter after it (`-nv`).
const WGET_SHORT_VALUED: &str = "oaeiBtOTwQPUlARDXIn";

/// curl long options that take a value. Only real ones: a flag listed here
/// would swallow the word after it (`--x -o FILE` would lose the write).
const CURL_LONG_VALUED: &[&str] = &[
    "output",
    "output-dir",
    "request",
    "max-time",
    "connect-timeout",
    "retry",
    "retry-delay",
    "retry-max-time",
    "range",
    "continue-at",
    "write-out",
    "max-redirs",
    "max-filesize",
    "limit-rate",
    "url",
    "data",
    "data-ascii",
    "data-binary",
    "data-raw",
    "data-urlencode",
    "json",
    "form",
    "form-string",
    "header",
    "user",
    "user-agent",
    "referer",
    "cookie",
    "cookie-jar",
    "config",
    "upload-file",
    "dump-header",
    "proxy",
    "resolve",
    "connect-to",
];
/// curl long options that take no value, so the word after them is not theirs.
const CURL_LONG_FLAGS: &[&str] = &[
    "silent",
    "show-error",
    "fail",
    "fail-with-body",
    "fail-early",
    "include",
    "head",
    "insecure",
    "verbose",
    "remote-name",
    "remote-name-all",
    "remote-header-name",
    "remote-time",
    "globoff",
    "no-buffer",
    "compressed",
    "progress-bar",
    "no-progress-meter",
    "create-dirs",
    "ipv4",
    "ipv6",
    "http1.1",
    "http2",
    "retry-connrefused",
    "retry-all-errors",
    "disable",
    "location",
    "netrc",
    "netrc-optional",
    "next",
];
const WGET_LONG_VALUED: &[&str] = &[
    "output-document",
    "directory-prefix",
    "tries",
    "timeout",
    "read-timeout",
    "connect-timeout",
    "dns-timeout",
    "wait",
    "waitretry",
    "limit-rate",
    "max-redirect",
    "progress",
    "output-file",
    "append-output",
    "execute",
    "input-file",
    "header",
    "user-agent",
    "post-data",
    "post-file",
    "body-data",
    "body-file",
    "method",
    "user",
    "password",
    "config",
];
const WGET_LONG_FLAGS: &[&str] = &[
    "quiet",
    "verbose",
    "no-verbose",
    "continue",
    "timestamping",
    "server-response",
    "no-clobber",
    "no-check-certificate",
    "show-progress",
    "no-parent",
    "no-directories",
    "spider",
    "content-disposition",
    "inet4-only",
    "inet6-only",
    "no-config",
    "no-netrc",
];

impl Client {
    /// The client `program` names, if it is `curl` or `wget`.
    pub(in crate::shell) fn of(program: &str) -> Option<Self> {
        match program {
            "curl" => Some(Self::Curl),
            "wget" => Some(Self::Wget),
            _ => None,
        }
    }

    fn short_valued(self) -> &'static str {
        match self {
            Self::Curl => CURL_SHORT_VALUED,
            Self::Wget => WGET_SHORT_VALUED,
        }
    }

    pub(in crate::shell) fn long_valued(self) -> &'static [&'static str] {
        match self {
            Self::Curl => CURL_LONG_VALUED,
            Self::Wget => WGET_LONG_VALUED,
        }
    }

    pub(in crate::shell) fn long_flags(self) -> &'static [&'static str] {
        match self {
            Self::Curl => CURL_LONG_FLAGS,
            Self::Wget => WGET_LONG_FLAGS,
        }
    }

    /// The long name `written` stands for, and whether it was spelled out in full.
    fn resolve(self, written: &str) -> (&str, bool) {
        let known = || self.long_valued().iter().chain(self.long_flags());
        if known().any(|n| *n == written) {
            return (written, true);
        }
        let mut hits = known().filter(|n| !written.is_empty() && n.starts_with(written));
        match (hits.next(), hits.next()) {
            (Some(name), None) => (name, false),
            _ => (written, false),
        }
    }
}

/// One option or operand of the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::shell) enum Arg<'a> {
    /// `--name`, `--name=value` or `--name value`; `exact` when not abbreviated.
    Long {
        name: &'a str,
        exact: bool,
        value: Option<&'a str>,
    },
    /// One letter of a cluster, with its value when it takes one.
    Short {
        letter: char,
        value: Option<&'a str>,
    },
    /// A URL (or anything else that is not an option).
    Operand(&'a str),
    /// `--`
    EndOfOptions,
    /// An option that takes a value, at the end of the line without one.
    Missing,
}

/// The options and operands of `argv` (the program at index 0), in order.
pub(in crate::shell) fn parse(argv: &[String], client: Client) -> Vec<Arg<'_>> {
    parse_indexed(argv, client)
        .into_iter()
        .map(|(_, arg)| arg)
        .collect()
}

/// [`parse`], with each argument's place in `argv`: the index of the word its
/// value came from when it has one (`-o FILE` is the index of `FILE`, `-oFILE`
/// and `--output=FILE` that of the one word), else of the word itself.
pub(in crate::shell) fn parse_indexed(argv: &[String], client: Client) -> Vec<(usize, Arg<'_>)> {
    let mut parsed = Vec::new();
    let mut words = argv.iter().enumerate().skip(1);
    let mut ended = false;
    while let Some((at, word)) = words.next() {
        let word = word.as_str();
        if ended || word == "-" || !word.starts_with('-') {
            parsed.push((at, Arg::Operand(word)));
        } else if word == "--" {
            ended = true;
            parsed.push((at, Arg::EndOfOptions));
        } else if let Some(long) = word.strip_prefix("--") {
            let (written, attached) = long
                .split_once('=')
                .map_or((long, None), |(n, v)| (n, Some(v)));
            let (name, exact) = client.resolve(written);
            let (at, value) = match attached {
                None if client.long_valued().contains(&name) => {
                    let Some((at, v)) = words.next() else {
                        parsed.push((at, Arg::Missing));
                        continue;
                    };
                    (at, Some(v.as_str()))
                }
                other => (at, other),
            };
            parsed.push((at, Arg::Long { name, exact, value }));
        } else {
            let cluster = &word[1..];
            for (pos, letter) in cluster.char_indices() {
                if !client.short_valued().contains(letter) {
                    parsed.push((
                        at,
                        Arg::Short {
                            letter,
                            value: None,
                        },
                    ));
                    continue;
                }
                let rest = &cluster[pos + letter.len_utf8()..];
                let (at, value) = if rest.is_empty() {
                    match words.next() {
                        Some((at, v)) => (at, Some(v.as_str())),
                        None => (at, None),
                    }
                } else {
                    (at, Some(rest))
                };
                parsed.push((
                    at,
                    value.map_or(Arg::Missing, |v| Arg::Short {
                        letter,
                        value: Some(v),
                    }),
                ));
                break;
            }
        }
    }
    parsed
}

/// What one option means for the files the command writes.
enum Role<'a> {
    Output(&'a str),
    Dir(&'a str),
    RemoteName,
    WriteOut(&'a str),
    Url(&'a str),
    Spider,
    Other,
}

/// An option by its letter or its (resolved) long name.
#[derive(Clone, Copy)]
enum Opt<'a> {
    S(char),
    L(&'a str),
}

fn role<'a>(arg: &Arg<'a>, client: Client) -> Role<'a> {
    let (opt, value) = match *arg {
        Arg::Operand(url) => return Role::Url(url),
        Arg::Short { letter, value } => (Opt::S(letter), value),
        Arg::Long { name, value, .. } => (Opt::L(name), value),
        Arg::EndOfOptions | Arg::Missing => return Role::Other,
    };
    match (client, opt, value) {
        (Client::Curl, Opt::L("url"), Some(url)) => Role::Url(url),
        (Client::Curl, Opt::S('o') | Opt::L("output"), Some(v))
        | (Client::Wget, Opt::S('O') | Opt::L("output-document"), Some(v)) => Role::Output(v),
        (Client::Curl, Opt::L("output-dir"), Some(v))
        | (Client::Wget, Opt::S('P') | Opt::L("directory-prefix"), Some(v)) => Role::Dir(v),
        (
            Client::Curl,
            Opt::S('O' | 'J') | Opt::L("remote-name" | "remote-name-all" | "remote-header-name"),
            _,
        ) => Role::RemoteName,
        (Client::Curl, Opt::S('w') | Opt::L("write-out"), Some(v)) => Role::WriteOut(v),
        (Client::Wget, Opt::L("spider"), _) => Role::Spider,
        _ => Role::Other,
    }
}

/// Whether `arg` names a file or directory the command writes to (`-o FILE`,
/// `--output-dir DIR`, wget `-O FILE`, `-P DIR`): the one place a word the
/// shell expands only names what is written, never what is sent.
pub(in crate::shell) fn names_output(arg: &Arg<'_>, client: Client) -> bool {
    matches!(role(arg, client), Role::Output(_) | Role::Dir(_))
}

/// The last segment of a URL's path, without its query or fragment (`""` when
/// the URL has no path): the name `curl -O` and a plain `wget` save it under.
pub(in crate::shell) fn last_segment(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let Some(at) = rest.find(['/', '?', '#']) else {
        return "";
    };
    let path = rest[at..].split(['?', '#']).next().unwrap_or("");
    path.rsplit('/').next().unwrap_or("")
}

/// Whether `curl -O` or `wget` saves `url` under a name the line shows: not
/// empty, not `.` or `..`, no glob, and no `%` escape (whether one is decoded
/// depends on the program and its version).
pub(in crate::shell) fn names_its_file(url: &str) -> bool {
    let name = last_segment(url);
    !matches!(name, "" | "." | "..") && !name.contains(['%', '{', '}', '[', ']', '\\'])
}

/// The files the command line writes: each `-o`/`-O` output, the remote file name
/// `curl -O` and a plain `wget` save a URL under, and each `%output{FILE}` of a
/// curl `--write-out`; under every `--output-dir` or `-P` directory the line names
/// (curl joins it to `-o` and `-O` names alike). An absolute output is also listed
/// as written, and wget's `-O` both with and without `-P`: stricter, never looser.
/// Standard output and the data sink (`-o -`, `-o /dev/stdout`, `-o /dev/null`)
/// write no file, as for a redirection (`tables::STREAM_SINKS`).
pub(in crate::shell) fn written(argv: &[String], client: Client) -> Vec<String> {
    let parsed = parse(argv, client);
    let roles: Vec<Role<'_>> = parsed.iter().map(|a| role(a, client)).collect();
    let dirs: Vec<&str> = roles
        .iter()
        .filter_map(|r| match r {
            Role::Dir(d) if !d.is_empty() => Some(*d),
            _ => None,
        })
        .collect();
    let mut files: Vec<String> = Vec::new();
    let mut outputs = false;
    for r in &roles {
        match r {
            Role::Output(file) => {
                outputs = true;
                if !file.is_empty()
                    && *file != "-"
                    && !crate::shell::tables::STREAM_SINKS.contains(file)
                {
                    under(&dirs, file, client == Client::Wget, &mut files);
                }
            }
            Role::WriteOut(format) => {
                for part in format.split("%output{").skip(1) {
                    if let Some((file, _)) = part.split_once('}') {
                        files.push(file.strip_prefix(">>").unwrap_or(file).to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    let by_name = match client {
        Client::Curl => roles.iter().any(|r| matches!(r, Role::RemoteName)),
        Client::Wget => !outputs && !roles.iter().any(|r| matches!(r, Role::Spider)),
    };
    if by_name {
        for r in &roles {
            if let Role::Url(url) = r {
                let name = match (last_segment(url), client) {
                    ("", Client::Wget) => "index.html",
                    ("", Client::Curl) => "curl_response",
                    (name, _) => name,
                };
                under(&dirs, name, false, &mut files);
            }
        }
    }
    files
}

fn under(dirs: &[&str], file: &str, also_plain: bool, files: &mut Vec<String>) {
    if dirs.is_empty() || also_plain || file.starts_with('/') {
        files.push(file.to_owned());
    }
    for dir in dirs {
        let dir = dir.trim_end_matches('/');
        files.push(format!("{dir}/{}", file.trim_start_matches('/')));
    }
}

#[cfg(test)]
mod tests;
