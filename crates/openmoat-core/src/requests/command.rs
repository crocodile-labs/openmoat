//! The HTTP requests a command will send, as far as its words show them
//! (ADR-062, the hook's half): the method, the host and the path of each
//! request `curl`, `wget`, `HTTPie` (`http`, `https`), `xh` and `gh` (`gh api`,
//! `gh gist`) send, and the fetch tools' URL (a `GET`).
//!
//! Only what the words make certain counts as known. A URL or a method built
//! at run time (`$URL`, `` `…` ``), a curl URL glob, options read from a file
//! (`curl -K`, `wget -i`, `wget -e`) and an option that sets the request
//! another way (`curl --request-target`, `--next`, `--expand-…`) leave the part
//! they touch unknown, and the hook holds such a request for review when a rule
//! could refuse it (`hook.rs`); it never takes a guess for an allow.
//!
//! This module reads the argument vector of each simple command the shell
//! classifier found, after it unwrapped `sudo`, `sh -c` and the rest; it is
//! kept apart from the classifier itself (`crate::shell`).

mod others;

use crate::route::{Partial, RequestPath};

/// One request a command will send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Seen {
    /// The program, for reasons (`curl`, `gh api`).
    pub(crate) program: &'static str,
    /// The host, lowercase; `None` when it is not known.
    pub(crate) host: Option<String>,
    /// Every method it may be sent with; `None` when that is not known.
    pub(crate) methods: Option<Vec<String>>,
    /// The request target (path and query).
    pub(crate) target: Target,
    /// The names of the headers the command adds.
    pub(crate) headers: Vec<String>,
}

/// The path and query of a request, as far as they are known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// Known in full, as the request line holds it.
    Known(String),
    /// Known in part: decoded segments and unknown ones.
    Partial(Vec<Partial>),
    /// Not known at all.
    Unknown,
}

/// Characters of a word whose text the shell makes at run time.
const EXPANDED: &[char] = &['$', '`'];

/// curl's URL globs: `{a,b}` and `[1-9]`, expanded unless `-g`.
const GLOB: &[char] = &['{', '}', '[', ']'];

/// The requests `argv` (one simple command) sends; none for another program.
pub(crate) fn read(argv: &[String]) -> Vec<Seen> {
    let Some((first, words)) = argv.split_first() else {
        return Vec::new();
    };
    let base = first.rsplit(['/', '\\']).next().unwrap_or(first);
    let base = base.trim_start_matches('\\').to_ascii_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    match base {
        "curl" => curl(words),
        "wget" => wget(words),
        "http" => others::httpie(words, "http", "http"),
        "https" => others::httpie(words, "https", "https"),
        "xh" => others::httpie(words, "xh", "http"),
        "xhs" => others::httpie(words, "xhs", "https"),
        // curlie takes HTTPie's syntax and sends with curl.
        "curlie" => others::httpie(words, "curlie", "https"),
        "gh" => others::gh(words),
        other => others::inline(other, words),
    }
}

/// The request a fetch tool sends for `url`: a `GET`.
pub(crate) fn fetch(url: &str) -> Option<Seen> {
    let (host, target) = url_parts(url, "https", false)?;
    Some(Seen {
        program: "fetch tool",
        host,
        methods: Some(vec!["GET".to_owned()]),
        target,
        headers: Vec::new(),
    })
}

/// The host and target of `word`, a URL with or without a scheme (`default`
/// then); `None` for another scheme than HTTP's. `globs`: curl expands
/// `{…}` and `[…]`, so they leave the part they are in unknown.
pub(crate) fn url_parts(
    word: &str,
    default: &str,
    globs: bool,
) -> Option<(Option<String>, Target)> {
    let unknown = |c: char| EXPANDED.contains(&c) || (globs && GLOB.contains(&c));
    let (scheme, rest) = word.split_once("://").unwrap_or((default, word));
    if scheme.contains(unknown) {
        return Some((None, Target::Unknown));
    }
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let tail = tail.split('#').next().unwrap_or_default();
    let host = if authority.contains(unknown) {
        None
    } else {
        let after_user = authority.rsplit('@').next().unwrap_or(authority);
        let host = match after_user.rsplit_once(':') {
            Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => after_user,
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.contains('%') {
            // An encoded name: the client may decode it into a listed host.
            None
        } else if host.is_empty() {
            Some("localhost".to_owned())
        } else {
            Some(host)
        }
    };
    let target = if tail.starts_with('/') {
        tail.to_owned()
    } else {
        format!("/{tail}")
    };
    let target = target_of(&target, &unknown, &|_| false);
    if host.is_none() {
        // A variable in the host may hold a path too: `$BASE/gists`.
        return Some((None, unhosted(target)));
    }
    Some((host, target))
}

/// `target` of a request whose host is not known: whatever names the host
/// may hold a path in front of it too.
fn unhosted(target: Target) -> Target {
    let mut parts = vec![Partial::Rest];
    match target {
        Target::Known(known) => parts.extend(
            RequestPath::parse(&known)
                .ok()
                .into_iter()
                .flat_map(|p| p.segments().to_vec())
                .map(Partial::Known),
        ),
        Target::Partial(rest) => parts.extend(rest),
        Target::Unknown => return Target::Unknown,
    }
    Target::Partial(parts)
}

/// A request nothing about is known: options or URLs read from a file, or
/// set by a configuration file the command's environment moves.
pub(crate) fn unknown_request(program: &'static str) -> Seen {
    Seen {
        program,
        host: None,
        methods: None,
        target: Target::Unknown,
        headers: Vec::new(),
    }
}

/// `target` as known: in full, or by segment where `unknown` (any number of
/// segments) or `one` (exactly one, such as `gh`'s `{owner}`) marks a part
/// the command makes at run time.
pub(crate) fn target_of(
    target: &str,
    unknown: &dyn Fn(char) -> bool,
    one: &dyn Fn(&str) -> bool,
) -> Target {
    let path = target.split('?').next().unwrap_or_default();
    if !target.contains(unknown) && !path.split('/').any(one) {
        return Target::Known(target.to_owned());
    }
    let segments = path
        .split('/')
        .skip(1)
        .map(|segment| {
            if segment.contains(unknown) {
                Partial::Rest
            } else if one(segment) {
                Partial::One
            } else {
                match RequestPath::parse(&format!("/{segment}")) {
                    Ok(p) => p
                        .segments()
                        .first()
                        .map_or(Partial::Known(String::new()), |s| Partial::Known(s.clone())),
                    Err(_) => Partial::Rest,
                }
            }
        })
        .collect();
    Target::Partial(segments)
}

/// The name of a header given as `Name: value`, when it is known.
pub(crate) fn header_name(value: &str) -> Option<String> {
    let (name, _) = value.split_once(':')?;
    let name = name.trim();
    (!name.is_empty() && !name.contains(EXPANDED)).then(|| name.to_owned())
}

/// curl long options that take a value, besides those `curl` reads itself.
const CURL_VALUED_LONG: &[&str] = &[
    "--output",
    "--user",
    "--user-agent",
    "--referer",
    "--proxy",
    "--proxy-user",
    "--cookie",
    "--cookie-jar",
    "--cacert",
    "--capath",
    "--cert",
    "--key",
    "--max-time",
    "--connect-timeout",
    "--retry",
    "--retry-delay",
    "--retry-max-time",
    "--write-out",
    "--resolve",
    "--connect-to",
    "--dump-header",
    "--limit-rate",
    "--range",
    "--interface",
    "--oauth2-bearer",
    "--unix-socket",
    "--abstract-unix-socket",
    "--proto",
    "--proto-redir",
    "--proto-default",
    "--max-redirs",
    "--stderr",
    "--trace",
    "--trace-ascii",
    "--netrc-file",
    "--keepalive-time",
    "--url-query",
    "--variable",
    "--aws-sigv4",
    "--ciphers",
    "--local-port",
    "--dns-servers",
    "--doh-url",
    "--pinnedpubkey",
    "--hsts",
    "--alt-svc",
    "--etag-save",
    "--etag-compare",
    "--output-dir",
    "--create-file-mode",
    "--mail-from",
    "--mail-rcpt",
    "--quote",
    "--socks5",
    "--socks5-hostname",
    "--preproxy",
    "--noproxy",
    "--time-cond",
    "--tls-max",
    "--max-filesize",
    "--speed-limit",
    "--speed-time",
    "--continue-at",
    "--cert-type",
    "--key-type",
    "--pass",
    "--engine",
    "--happy-eyeballs-timeout-ms",
    "--expect100-timeout",
    "--parallel-max",
];

/// curl short options that take a value: the rest of the word, or the next word.
const CURL_VALUED: &str = "AbcCdDeEFHKmoPQrtTuUwxXyYz";

/// What curl's options say about the requests it sends.
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each is one curl option that decides the method; an enum per flag would only \
              rename them"
)]
struct Curl<'a> {
    method: Option<String>,
    data: bool,
    upload: bool,
    head: bool,
    get: bool,
    globoff: bool,
    /// An option that sets the request in a way this reading does not follow.
    unknown: bool,
    /// Options read from a file (`-K`): more URLs, methods and data.
    config: bool,
    /// `--request-target`: the path sent is not the URL's.
    target: bool,
    /// `--connect-to`, `--resolve` or a `Host:` header: the request may go to
    /// another host than the URL names.
    rerouted: bool,
    headers: Vec<String>,
    urls: Vec<&'a str>,
}

impl<'a> Curl<'a> {
    /// Take option `name` (long spelling, or `-c`), with its value if it has one.
    fn take(&mut self, name: &str, value: Option<&'a str>) {
        match name {
            "--request" | "-X" => self.method = value.map(str::to_owned),
            "--data" | "-d" | "--data-ascii" | "--data-binary" | "--data-raw"
            | "--data-urlencode" | "--json" | "--form" | "-F" | "--form-string" => self.data = true,
            "--upload-file" | "-T" => self.upload = true,
            "--url" => self.urls.extend(value),
            "--header" | "-H" => {
                let name = value.and_then(header_name);
                // A header made at run time may be `Host:` too.
                let unknown = value.is_some_and(|v| v.contains(EXPANDED) || !v.contains(':'));
                if unknown
                    || name
                        .as_deref()
                        .is_some_and(|n| n.eq_ignore_ascii_case("host"))
                {
                    self.rerouted = true;
                }
                self.headers.extend(name);
            }
            "--get" | "-G" => self.get = true,
            "--head" | "-I" => self.head = true,
            "--globoff" | "-g" => self.globoff = true,
            "--config" | "-K" => self.config = true,
            "--request-target" => self.target = true,
            "--connect-to" | "--resolve" => self.rerouted = true,
            "--next" | "-:" => self.unknown = true,
            other if other.starts_with("--expand-") => self.unknown = true,
            _ => {}
        }
    }

    fn valued_long(name: &str) -> bool {
        matches!(
            name,
            "--request"
                | "--data"
                | "--data-ascii"
                | "--data-binary"
                | "--data-raw"
                | "--data-urlencode"
                | "--json"
                | "--form"
                | "--form-string"
                | "--upload-file"
                | "--url"
                | "--header"
                | "--config"
                | "--request-target"
        ) || name.starts_with("--expand-")
            || CURL_VALUED_LONG.contains(&name)
    }

    fn methods(&self) -> Option<Vec<String>> {
        if self.unknown || self.config || self.method.as_ref().is_some_and(|m| m.contains(EXPANDED))
        {
            return None;
        }
        let method = match &self.method {
            Some(method) => method.as_str(),
            None if self.head => "HEAD",
            None if self.upload => "PUT",
            None if self.data && !self.get => "POST",
            None => "GET",
        };
        Some(vec![method.to_owned()])
    }
}

fn curl(args: &[String]) -> Vec<Seen> {
    let mut c = Curl::default();
    let mut i = 0;
    let mut options = true;
    while let Some(word) = args.get(i) {
        i += 1;
        if !options || !word.starts_with('-') || word == "-" {
            c.urls.push(word);
            continue;
        }
        if word == "--" {
            options = false;
        } else if let Some((name, value)) = word.split_once('=').filter(|_| word.starts_with("--"))
        {
            c.take(name, Some(value));
        } else if word.starts_with("--") {
            let value = if Curl::valued_long(word) {
                i += 1;
                args.get(i - 1).map(String::as_str)
            } else {
                None
            };
            c.take(word, value);
        } else {
            for (at, letter) in word.char_indices().skip(1) {
                let name = format!("-{letter}");
                if CURL_VALUED.contains(letter) {
                    let rest = &word[at + letter.len_utf8()..];
                    let value = if rest.is_empty() {
                        i += 1;
                        args.get(i - 1).map(String::as_str)
                    } else {
                        Some(rest)
                    };
                    c.take(&name, value);
                    break;
                }
                c.take(&name, None);
            }
        }
    }
    let methods = c.methods();
    let mut seen: Vec<Seen> = c
        .urls
        .iter()
        .filter_map(|url| url_parts(url, "http", !c.globoff))
        .map(|(host, target)| {
            let (host, target) = match (c.rerouted, c.target) {
                (_, true) => (host.filter(|_| !c.rerouted), Target::Unknown),
                (true, false) => (None, unhosted(target)),
                (false, false) => (host, target),
            };
            Seen {
                program: "curl",
                host,
                methods: methods.clone(),
                target,
                headers: c.headers.clone(),
            }
        })
        .collect();
    if c.config || c.unknown {
        // `-K FILE` (or `-K -`) reads more URLs and options; after `--next`
        // and `--expand-…` the options of each URL are not followed here.
        seen.push(unknown_request("curl"));
    }
    seen
}

/// wget short options that take a value.
const WGET_VALUED: &str = "aABDeiIlOoPQTtUwX";

/// wget long options that take a value as the next word.
const WGET_VALUED_LONG: &[&str] = &[
    "--method",
    "--post-data",
    "--post-file",
    "--body-data",
    "--body-file",
    "--header",
    "--execute",
    "--input-file",
    "--config",
    "--output-document",
    "--output-file",
    "--user",
    "--password",
    "--http-user",
    "--http-password",
    "--user-agent",
    "--referer",
    "--directory-prefix",
    "--tries",
    "--timeout",
    "--wait",
    "--load-cookies",
    "--save-cookies",
    "--ca-certificate",
    "--certificate",
    "--private-key",
    "--level",
    "--accept",
    "--reject",
    "--domains",
    "--limit-rate",
];

fn wget(args: &[String]) -> Vec<Seen> {
    let (mut method, mut post, mut unknown) = (None::<String>, false, false);
    let mut headers = Vec::new();
    let mut urls: Vec<&str> = Vec::new();
    let mut take = |name: &str, value: Option<&str>| match name {
        "--method" => method = value.map(str::to_owned),
        "--post-data" | "--post-file" => post = true,
        "--header" => headers.extend(value.and_then(header_name)),
        // `--config FILE` and `-e` set any wgetrc command (`method`,
        // `post_data`, `input`); `-i FILE` reads more URLs.
        "--execute" | "-e" | "--input-file" | "-i" | "--config" => unknown = true,
        _ => {}
    };
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if !word.starts_with('-') {
            urls.push(word);
        } else if let Some((name, value)) = word.split_once('=').filter(|_| word.starts_with("--"))
        {
            take(name, Some(value));
        } else if word.starts_with("--") {
            let value = WGET_VALUED_LONG.contains(&word.as_str()).then(|| {
                i += 1;
                args.get(i - 1).map(String::as_str)
            });
            take(word, value.flatten());
        } else {
            // Every letter of a cluster (`-qi urls.txt`): the first that
            // takes a value takes the rest of the word or the next word.
            for (at, letter) in word.char_indices().skip(1) {
                if WGET_VALUED.contains(letter) {
                    if word[at + letter.len_utf8()..].is_empty() {
                        i += 1;
                    }
                    take(&format!("-{letter}"), None);
                    break;
                }
            }
        }
    }
    let methods = if unknown || method.as_ref().is_some_and(|m| m.contains(EXPANDED)) {
        None
    } else {
        Some(vec![method.unwrap_or_else(|| {
            if post { "POST" } else { "GET" }.to_owned()
        })])
    };
    let mut seen: Vec<Seen> = urls
        .iter()
        .filter_map(|url| url_parts(url, "http", false))
        .map(|(host, target)| Seen {
            program: "wget",
            host,
            methods: methods.clone(),
            target,
            headers: headers.clone(),
        })
        .collect();
    if unknown {
        seen.push(unknown_request("wget"));
    }
    seen
}

#[cfg(test)]
mod tests;
