//! `curl` and `wget` commands that provably send nothing but the request line
//! (ADR-035): decided as a fetch, like a host's own fetch tool, not as `net`.
//!
//! The check is an allowlist. Every word must be a URL, or an option on the
//! lists below whose value (when it takes one) is checked too; anything else
//! (a body, a form, an upload, a header, credentials, a cookie, a config file,
//! `--next`, an option not on the lists) keeps the command `net`. So does a
//! word the shell expands (`$X`, `$(…)`, a backtick), an `@` in a value or in
//! a URL's user part, and a variable set earlier on the line that points the
//! program at another configuration file or a proxy (`CURL_HOME`, `WGETRC`).

use crate::action::AtomicAction;
use crate::lexer::Word;
use crate::shell::Sink;

/// curl options that take no value and send nothing.
const CURL_FLAGS: &[&str] = &[
    "--silent",
    "--show-error",
    "--fail",
    "--fail-with-body",
    "--fail-early",
    "--include",
    "--head",
    "--insecure",
    "--verbose",
    "--remote-name",
    "--remote-name-all",
    "--remote-header-name",
    "--remote-time",
    "--globoff",
    "--no-buffer",
    "--compressed",
    "--progress-bar",
    "--no-progress-meter",
    "--create-dirs",
    "--ipv4",
    "--ipv6",
    "--http1.1",
    "--http2",
    "--retry-connrefused",
    "--retry-all-errors",
    "--disable",
];
/// curl options that take a value and send nothing.
const CURL_VALUED: &[&str] = &[
    "--output",
    "--output-dir",
    "--request",
    "--max-time",
    "--connect-timeout",
    "--retry",
    "--retry-delay",
    "--retry-max-time",
    "--range",
    "--continue-at",
    "--write-out",
    "--max-redirs",
    "--max-filesize",
    "--limit-rate",
];
/// curl short flags with no value (`-sS`), and short options with one. `-L`
/// (`--location`) is left out: a redirect leads where the hook cannot see.
const CURL_SHORT_FLAGS: &str = "sSfiIkvOgNRJ46#q";
const CURL_SHORT_VALUED: &str = "oXmrCw";

const WGET_FLAGS: &[&str] = &[
    "--quiet",
    "--verbose",
    "--no-verbose",
    "--continue",
    "--timestamping",
    "--server-response",
    "--no-clobber",
    "--no-check-certificate",
    "--show-progress",
    "--no-parent",
    "--no-directories",
    "--spider",
    "--content-disposition",
    "--inet4-only",
    "--inet6-only",
];
const WGET_VALUED: &[&str] = &[
    "--output-document",
    "--directory-prefix",
    "--tries",
    "--timeout",
    "--read-timeout",
    "--connect-timeout",
    "--dns-timeout",
    "--wait",
    "--waitretry",
    "--limit-rate",
    "--max-redirect",
    "--progress",
];
/// wget's two-letter short options (`-nv`), single short flags, valued short options.
const WGET_PAIRS: &[&str] = &["-nv", "-nc", "-nd", "-nH", "-np"];
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
    flags: &'static [&'static str],
    valued: &'static [&'static str],
    pairs: &'static [&'static str],
    short_flags: &'static str,
    short_valued: &'static str,
}

const CURL: Options = Options {
    flags: CURL_FLAGS,
    valued: CURL_VALUED,
    pairs: &[],
    short_flags: CURL_SHORT_FLAGS,
    short_valued: CURL_SHORT_VALUED,
};
const WGET: Options = Options {
    flags: WGET_FLAGS,
    valued: WGET_VALUED,
    pairs: WGET_PAIRS,
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
    let expands = words.iter().any(|w| !w.substitutions.is_empty())
        || argv.iter().any(|a| a.contains(['$', '`']));
    let configured = sink
        .atoms
        .iter()
        .any(|a| matches!(a, AtomicAction::EnvSet { name } if redirects_config(name)));
    // wget follows redirects unless told not to; curl only with `-L`, which is not listed
    let stays = program != "wget" || wget_follows_no_redirect(argv);
    !expands && !configured && stays && words_send_nothing(argv, options)
}

/// Whether the last `--max-redirect` of a wget command line is `0`: a redirect
/// leads where the hook cannot see, a link-local address included.
fn wget_follows_no_redirect(argv: &[String]) -> bool {
    let mut last = None;
    let mut words = argv.iter();
    while let Some(arg) = words.next() {
        if let Some(value) = arg.strip_prefix("--max-redirect=") {
            last = Some(value);
        } else if arg == "--max-redirect" {
            last = words.next().map(String::as_str);
        }
    }
    last == Some("0")
}

fn words_send_nothing(argv: &[String], options: &Options) -> bool {
    let mut i = 1;
    let mut options_ended = false;
    while let Some(arg) = argv.get(i) {
        i += 1;
        if options_ended || !arg.starts_with('-') || arg == "-" {
            if arg == "-" || !plain_url(arg) {
                return false;
            }
            continue;
        }
        if arg == "--" {
            options_ended = true;
            continue;
        }
        let value = if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(n, v)| (n, Some(v)));
            let name = format!("--{name}");
            if options.flags.contains(&name.as_str()) && attached.is_none() {
                continue;
            }
            if !options.valued.contains(&name.as_str()) {
                return false;
            }
            let Some(value) = attached.or_else(|| next(argv, &mut i)) else {
                return false;
            };
            if name == "--request" && !read_method(value) {
                return false;
            }
            value
        } else if options.pairs.contains(&arg.as_str()) {
            continue;
        } else {
            match short(arg, options, argv, &mut i) {
                Some(value) => value,
                None => return false,
            }
        };
        if value.starts_with('@') {
            return false;
        }
    }
    true
}

/// The value of a cluster of short options (`-sSLo out`, `-oout`), `""` when
/// it takes none; `None` when one of them is not on the lists.
fn short<'a>(
    arg: &'a str,
    options: &Options,
    argv: &'a [String],
    i: &mut usize,
) -> Option<&'a str> {
    let cluster = &arg[1..];
    for (pos, c) in cluster.char_indices() {
        if options.short_flags.contains(c) {
            continue;
        }
        if !options.short_valued.contains(c) {
            return None;
        }
        let rest = &cluster[pos + c.len_utf8()..];
        let value = if rest.is_empty() {
            next(argv, i)?
        } else {
            rest
        };
        // curl's `-X`, wget has none: only a method that sends no body
        if c == 'X' && !read_method(value) {
            return None;
        }
        return Some(value);
    }
    Some("")
}

fn next<'a>(argv: &'a [String], i: &mut usize) -> Option<&'a str> {
    let value = argv.get(*i)?;
    *i += 1;
    Some(value)
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

/// Whether `host` is a domain name a fetch may name: dotted, ending in a
/// letters-only top-level label, with no all-digit label. IP literals in any
/// spelling (`2852039166`, `0x7f000001`, `[::1]`, `203.0.113.7`) and
/// single-label names (`intranet`) stay `net`.
pub(super) fn fetchable_host(host: &str) -> bool {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && !l.chars().all(|c| c.is_ascii_digit())
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.chars().all(|c| c.is_ascii_alphabetic()))
}

#[cfg(test)]
mod tests {
    use super::{CURL, WGET, fetchable_host, wget_follows_no_redirect, words_send_nothing};

    fn argv(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn requests_that_send_nothing() {
        for line in [
            "curl https://docs.rs/serde",
            "curl -sS https://example.com/f.txt -o out.txt",
            "curl -X GET -fsS https://example.com/api",
            "curl --request=HEAD https://example.com",
            "curl -w %{http_code} https://example.com",
            "curl -- https://example.com",
        ] {
            assert!(words_send_nothing(&argv(line), &CURL), "{line}");
        }
        for line in [
            "wget https://x.test/a.tar.gz",
            "wget -qO- https://x.test/a",
            "wget -nv --tries=3 -P dl https://x.test/a",
        ] {
            assert!(words_send_nothing(&argv(line), &WGET), "{line}");
        }
    }

    #[test]
    fn redirects_keep_the_command_net() {
        for line in ["curl -sSL https://x.test", "curl --location https://x.test"] {
            assert!(!words_send_nothing(&argv(line), &CURL), "{line}");
        }
        assert!(wget_follows_no_redirect(&argv(
            "wget --max-redirect=0 https://x.test"
        )));
        assert!(wget_follows_no_redirect(&argv(
            "wget --max-redirect 0 https://x.test"
        )));
        for line in [
            "wget https://x.test",
            "wget --max-redirect=0 --max-redirect=5 https://x.test",
            "wget --max-redirect=3 https://x.test",
        ] {
            assert!(!wget_follows_no_redirect(&argv(line)), "{line}");
        }
    }

    #[test]
    fn requests_that_may_send_data() {
        for line in [
            "curl -d x https://x.test",
            "curl -sd x https://x.test",
            "curl -X POST https://x.test",
            "curl -sXPUT https://x.test",
            "curl -H a:b https://x.test",
            "curl -K cfg https://x.test",
            "curl -u a:b https://x.test",
            "curl -b c.txt https://x.test",
            "curl -A agent https://x.test",
            "curl https://x.test --next https://y.test",
            "curl https://a:b@x.test/",
            "curl @urls",
            "curl -o @x https://x.test",
            "curl --head=x https://x.test",
            "curl -o",
        ] {
            assert!(!words_send_nothing(&argv(line), &CURL), "{line}");
        }
        for line in [
            "wget --post-file=x https://x.test",
            "wget --method=GET https://x.test",
            "wget -i list",
            "wget -e cmd https://x.test",
            "wget --header=a:b https://x.test",
        ] {
            assert!(!words_send_nothing(&argv(line), &WGET), "{line}");
        }
    }

    #[test]
    fn only_domain_names_are_fetchable() {
        assert!(fetchable_host("docs.rs"));
        assert!(fetchable_host("x.test"));
        assert!(fetchable_host("a-b.example.com"));
        for host in [
            "localhost",
            "intranet",
            "2852039166",
            "0x7f000001",
            "203.0.113.7",
            "169.254.169.254",
            "::1",
            "fd00:ec2::254",
            "169.254.169.254.nip.io",
            "x.123",
        ] {
            assert!(!fetchable_host(host), "{host}");
        }
    }
}
