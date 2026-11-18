//! `HTTPie` and `xh` (`[METHOD] URL [ITEM …]`), and `gh api` and `gh gist`.

use super::{EXPANDED, Seen, Target, header_name, target_of, url_parts};
use crate::route::Partial::{self, Known, One, Rest};

/// `HTTPie` and `xh` options that take a value as the next word.
const HTTPIE_VALUED: &[&str] = &[
    "--auth",
    "-a",
    "--auth-type",
    "-A",
    "--output",
    "-o",
    "--session",
    "--session-read-only",
    "--verify",
    "--cert",
    "--cert-key",
    "--cert-key-pass",
    "--proxy",
    "--timeout",
    "--max-redirects",
    "--print",
    "-p",
    "--style",
    "-s",
    "--format-options",
    "--pretty",
    "--max-headers",
    "--boundary",
    "--ssl",
    "--ciphers",
    "--default-scheme",
    "--history-print",
    "-P",
    "--response-charset",
    "--response-mime",
    "--unix-socket",
    "--http-version",
    "--resolve",
    "--interface",
    "--bearer",
    "--raw",
];

/// The request `http`, `https`, `xh` or `xhs` sends. Without a method, it is
/// `POST` when the items or `--raw` carry data and `GET` otherwise, unless
/// standard input is read for a body (no `--ignore-stdin`), which may make it
/// a `POST` too.
pub(super) fn httpie(args: &[String], program: &'static str, scheme: &str) -> Vec<Seen> {
    let (mut data, mut ignore_stdin) = (false, false);
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if !word.starts_with('-') || word == "-" {
            positional.push(word);
            continue;
        }
        let name = word.split_once('=').map_or(word.as_str(), |(n, _)| n);
        match name {
            "--offline" => return Vec::new(),
            "--ignore-stdin" | "-I" => ignore_stdin = true,
            "--raw" => data = true,
            _ => {}
        }
        if !word.contains('=') && HTTPIE_VALUED.contains(&name) {
            i += 1;
        }
    }
    let (method, rest) = match positional.as_slice() {
        [first, url, rest @ ..] if first.bytes().all(|b| b.is_ascii_alphabetic()) => {
            (Some(first.to_ascii_uppercase()), (url, rest))
        }
        [url, rest @ ..] => (None, (url, rest)),
        [] => return Vec::new(),
    };
    let (url, items) = rest;
    let mut headers = Vec::new();
    for item in items {
        match item.find(['=', ':', '@']).map(|at| (&item[at..], at)) {
            Some((sep, _)) if sep.starts_with("==") => {}
            Some((sep, _)) if sep.starts_with(":=") || !sep.starts_with(':') => data = true,
            Some(_) => headers.extend(header_name(item)),
            None => {}
        }
    }
    let methods = match method {
        Some(m) if m.contains(EXPANDED) => None,
        Some(m) => Some(vec![m]),
        None if data => Some(vec!["POST".to_owned()]),
        None if ignore_stdin => Some(vec!["GET".to_owned()]),
        None => Some(vec!["GET".to_owned(), "POST".to_owned()]),
    };
    // `:3000/x` and `:/x` are this machine.
    let url = url
        .strip_prefix(':')
        .map_or_else(|| (*url).to_owned(), |rest| format!("localhost:{rest}"));
    url_parts(&url, scheme, false)
        .map(|(host, target)| Seen {
            program,
            host,
            methods,
            target,
            headers,
        })
        .into_iter()
        .collect()
}

/// `gh api` options that take a value (`-X POST`, `-XPOST`, `--method=POST`).
const GH_API_VALUED: &[&str] = &[
    "-X",
    "--method",
    "-H",
    "--header",
    "-f",
    "--raw-field",
    "-F",
    "--field",
    "--input",
    "-q",
    "--jq",
    "-t",
    "--template",
    "--hostname",
    "-p",
    "--preview",
    "--cache",
];

/// The API host of github.com.
const API_HOST: &str = "api.github.com";

/// The requests of `gh api` and `gh gist`. Other `gh` commands choose their
/// own requests (mostly GraphQL), which the command does not show: they are
/// left to the proxy.
pub(super) fn gh(args: &[String]) -> Vec<Seen> {
    match args.first().map(String::as_str) {
        Some("api") => gh_api(&args[1..]).into_iter().collect(),
        Some("gist") => gh_gist(&args[1..]).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn gh_api(args: &[String]) -> Option<Seen> {
    let (mut method, mut fields, mut hostname) = (None::<String>, false, None::<String>);
    let mut headers = Vec::new();
    let mut endpoint = None;
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        if !word.starts_with('-') {
            endpoint = endpoint.or(Some(word.as_str()));
            continue;
        }
        let (name, value) =
            if let Some((n, v)) = word.split_once('=').filter(|_| word.starts_with("--")) {
                (n, Some(v.to_owned()))
            } else if let Some((short, rest)) = word
                .split_at_checked(2)
                .filter(|(s, r)| !s.starts_with("--") && !r.is_empty() && GH_API_VALUED.contains(s))
            {
                (short, Some(rest.to_owned()))
            } else if GH_API_VALUED.contains(&word.as_str()) {
                i += 1;
                (word.as_str(), args.get(i - 1).cloned())
            } else {
                (word.as_str(), None)
            };
        match name {
            "-X" | "--method" => method = value,
            "-f" | "--raw-field" | "-F" | "--field" | "--input" => fields = true,
            "-H" | "--header" => headers.extend(value.as_deref().and_then(header_name)),
            "--hostname" => hostname = value,
            _ => {}
        }
    }
    let endpoint = endpoint?;
    let graphql = endpoint.trim_start_matches('/') == "graphql";
    let methods = match method {
        Some(m) if m.contains(EXPANDED) => None,
        Some(m) => Some(vec![m]),
        None if fields || graphql => Some(vec!["POST".to_owned()]),
        None => Some(vec!["GET".to_owned()]),
    };
    let unknown = |c: char| EXPANDED.contains(&c);
    let placeholder = |segment: &str| segment.starts_with('{') && segment.ends_with('}');
    let (host, target) = if endpoint.contains("://") {
        url_parts(endpoint, "https", false)?
    } else {
        let path = format!("/{}", endpoint.trim_start_matches('/'));
        // GitHub Enterprise Server serves its API under `/api/v3`.
        let (host, path) = match hostname.as_deref() {
            None | Some("github.com") => (Some(API_HOST.to_owned()), path),
            Some(h) if h.contains(EXPANDED) => (None, path),
            Some(h) => (Some(h.to_ascii_lowercase()), format!("/api/v3{path}")),
        };
        (host, target_of(&path, &unknown, &placeholder))
    };
    Some(Seen {
        program: "gh api",
        host,
        methods,
        target,
        headers,
    })
}

fn gh_gist(args: &[String]) -> Option<Seen> {
    // The gist: its id, or the last segment of its URL; unknown when made
    // at run time or not given.
    let id = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .map(|a| {
            a.trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or_default()
        })
        .filter(|id| {
            !id.is_empty()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    let one = id.map_or(One, |id| Known(id.to_ascii_lowercase()));
    let known = |m: &str, path: Vec<Partial>| (Some(vec![m.to_owned()]), path);
    let gists = || Known("gists".to_owned());
    let (methods, path) = match args.first().map(String::as_str)? {
        "create" | "new" => known("POST", vec![gists()]),
        "edit" | "rename" => known("PATCH", vec![gists(), one]),
        "delete" => known("DELETE", vec![gists(), one]),
        "list" => known("GET", vec![gists()]),
        "view" => known("GET", vec![gists(), one]),
        "clone" => return None,
        _ => (None, vec![gists(), Rest]),
    };
    let target = if path.iter().all(|p| matches!(p, Known(_))) {
        let text: Vec<String> = path
            .iter()
            .filter_map(|p| match p {
                Known(s) => Some(s.clone()),
                _ => None,
            })
            .collect();
        Target::Known(format!("/{}", text.join("/")))
    } else {
        Target::Partial(path)
    };
    Some(Seen {
        program: "gh gist",
        host: Some(API_HOST.to_owned()),
        methods,
        target,
        headers: Vec::new(),
    })
}
