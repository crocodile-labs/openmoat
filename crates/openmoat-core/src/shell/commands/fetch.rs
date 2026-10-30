//! `curl` and `wget` commands that provably send nothing but the request line
//! (ADR-035): decided as a fetch, like a host's own fetch tool, not as `net`.
//! A download (`curl -o FILE URL`, `-O`, `wget -O FILE URL`, a plain `wget URL`)
//! is such a fetch plus the `fs.write` of the file it saves, which the path
//! rules decide (`options/transfer.rs`).
//!
//! The check is an allowlist. Every word must be a URL, or an option on the
//! lists below whose value (when it takes one) is checked too; anything else
//! (a body, a form, an upload, a header, credentials, a cookie, a config file,
//! `--next`, `--write-out`, a server-chosen file name, an option not on the
//! lists) keeps the command `net`. So does a word the shell expands (`$X`,
//! `$(…)`, a backtick) anywhere but in the name of the file written (`-o
//! $TMPDIR/x.tgz`: the write is then of a path the hook cannot place, which the
//! catch-all decides), an `@` in a value or in a URL's user part, and a
//! variable set earlier on the line that points the program at another
//! configuration file or a proxy (`CURL_HOME`, `WGETRC`).
//!
//! Redirects are followed (`curl -L`, and wget by default): the agent's prompt
//! or the person sees the URL, as for a browser page open (ADR-047). Both
//! programs read configuration files on their own, which can add a body or an
//! upload (`data = @~/.ssh/id_rsa` in `~/.curlrc`); `shell-rc` denies writing
//! those files and `env-poison` denies moving them (`CURL_HOME`,
//! `XDG_CONFIG_HOME`, `WGETRC`), so a command need not turn them off. The
//! words are read by the same parser that finds the files the command writes,
//! so a write is never hidden in a short cluster.

use crate::action::AtomicAction;
use crate::lexer::Word;
use crate::shell::Sink;
use crate::shell::options::transfer::{self, Arg, Client};

/// curl long options that take no value and send nothing. Not `-J`/
/// `--remote-header-name`: the server would choose the file name. Not
/// `--location-trusted`: it sends the credentials on to the redirect target.
const CURL_FLAGS: &[&str] = &[
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
];
/// curl long options that take a value and send nothing. Not `--write-out`:
/// since curl 8.3 its `%output{FILE}` writes text the agent chooses to a file.
const CURL_VALUED: &[&str] = &[
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
    "max-redirs",
    "max-filesize",
    "limit-rate",
];
/// curl short flags with no value (`-sSL`), and short options with one.
const CURL_SHORT_FLAGS: &str = "sSfiIkvOgNR46#qL";
const CURL_SHORT_VALUED: &str = "oXmrC";

/// wget long options that send nothing. Not `--content-disposition`: the
/// server would choose the file name.
const WGET_FLAGS: &[&str] = &[
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
    "inet4-only",
    "inet6-only",
    "no-config",
    "no-netrc",
];
const WGET_VALUED: &[&str] = &[
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
];
/// The letters wget's `-n` takes (`-nv`, `-nc`, `-nH`, …), single short
/// flags, valued short options.
const WGET_N_LETTERS: &[&str] = &["v", "c", "d", "H", "p"];
const WGET_SHORT_FLAGS: &str = "qvcNS46";
const WGET_SHORT_VALUED: &str = "OPtT";

/// Variables that make curl or wget read another configuration file, which may
/// add a body or headers, or send the request through another host.
fn redirects_config(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CURL_HOME" | "XDG_CONFIG_HOME" | "HOME" | "WGETRC" | "SYSTEM_WGETRC"
    ) || upper.ends_with("_PROXY")
}

struct Options {
    client: Client,
    flags: &'static [&'static str],
    valued: &'static [&'static str],
    short_flags: &'static str,
    short_valued: &'static str,
}

const CURL: Options = Options {
    client: Client::Curl,
    flags: CURL_FLAGS,
    valued: CURL_VALUED,
    short_flags: CURL_SHORT_FLAGS,
    short_valued: CURL_SHORT_VALUED,
};
const WGET: Options = Options {
    client: Client::Wget,
    flags: WGET_FLAGS,
    valued: WGET_VALUED,
    short_flags: WGET_SHORT_FLAGS,
    short_valued: WGET_SHORT_VALUED,
};

/// Whether `argv` (the words `words`) is a `curl` or `wget` request that sends
/// nothing but its URLs, with nothing set earlier on the line (`sink`) that
/// changes what it reads or where it connects.
pub(super) fn sends_nothing(argv: &[String], program: &str, words: &[Word], sink: &Sink) -> bool {
    let options = match program {
        "curl" => &CURL,
        "wget" => &WGET,
        _ => return false,
    };
    // A word the shell expands could be any option or URL, except where it can
    // only name the file written, whose write is checked on its own.
    let outputs = output_words(argv, options.client);
    let expands = argv.iter().zip(words).enumerate().any(|(i, (text, word))| {
        !outputs.contains(&i) && (!word.substitutions.is_empty() || text.contains(['$', '`']))
    });
    let configured = sink
        .atoms
        .iter()
        .any(|a| matches!(a, AtomicAction::EnvSet { name } if redirects_config(name)));
    !expands && !configured && words_send_nothing(argv, options)
}

/// The indices of the words that are, or hold, the name of a file or
/// directory the command writes to (`-o FILE`, `-oFILE`, `--output=FILE`,
/// `--output-dir DIR`, wget `-O FILE`, `-P DIR`).
fn output_words(argv: &[String], client: Client) -> Vec<usize> {
    transfer::parse_indexed(argv, client)
        .into_iter()
        .filter(|(_, arg)| transfer::names_output(arg, client))
        .map(|(at, _)| at)
        .collect()
}

fn words_send_nothing(argv: &[String], options: &Options) -> bool {
    let parsed = transfer::parse(argv, options.client);
    parsed.iter().all(|a| sends_nothing_arg(a, options)) && names_known(&parsed, options)
}

fn sends_nothing_arg(arg: &Arg<'_>, options: &Options) -> bool {
    let value = match *arg {
        Arg::EndOfOptions => return true,
        Arg::Missing => return false,
        Arg::Operand(word) => return word != "-" && plain_url(word),
        Arg::Long { name, exact, value } => {
            if !exact {
                return false;
            }
            match value {
                None => return options.flags.contains(&name),
                Some(_) if !options.valued.contains(&name) => return false,
                Some(v) if name == "request" && !read_method(v) => return false,
                Some(v) if name == "output" && v.contains('#') => return false,
                Some(v) => v,
            }
        }
        Arg::Short { letter, value } => match value {
            None => return options.short_flags.contains(letter),
            // wget's `-nv` and friends
            Some(v) if options.client == Client::Wget && letter == 'n' => {
                return WGET_N_LETTERS.contains(&v);
            }
            Some(_) if !options.short_valued.contains(letter) => return false,
            // curl's `-X`, wget has none: only a method that sends no body
            Some(v) if letter == 'X' && !read_method(v) => return false,
            // curl's `-o "#1"` names a file after a URL glob
            Some(v) if letter == 'o' && v.contains('#') => return false,
            Some(v) => v,
        },
    };
    !value.starts_with('@')
}

/// Whether every file saved under its remote name (`curl -O`, a `wget` without
/// `-O`) gets a name the line shows.
fn names_known(args: &[Arg<'_>], options: &Options) -> bool {
    let has = |letter: char, long: &str| {
        args.iter().any(|a| match *a {
            Arg::Short { letter: l, .. } => l == letter,
            Arg::Long { name, .. } => name == long,
            _ => false,
        })
    };
    let by_name = match options.client {
        Client::Curl => has('O', "remote-name") || has('O', "remote-name-all"),
        Client::Wget => !has('O', "output-document") && !has('\0', "spider"),
    };
    let known = |url: &&str| match options.client {
        Client::Wget if transfer::last_segment(url).is_empty() => true,
        Client::Curl | Client::Wget => transfer::names_its_file(url),
    };
    !by_name
        || args
            .iter()
            .filter_map(|a| match *a {
                Arg::Operand(url) => Some(url),
                _ => None,
            })
            .all(|url| known(&url))
}

fn read_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

/// A URL operand with no `@` before its path: no `@file`, no user or password.
fn plain_url(word: &str) -> bool {
    let rest = word.split_once("://").map_or(word, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    !word.starts_with('@') && !authority.contains('@')
}

/// Whether `host` is a domain name a fetch may name ([`crate::host::fetchable`]).
pub(super) fn fetchable_host(host: &str) -> bool {
    crate::host::fetchable(host)
}

#[cfg(test)]
mod tests;
