//! An MCP call that only opens or reads one web page (ADR-047).
//!
//! Browser servers navigate with one URL and a few settings that send
//! nothing: Chrome DevTools MCP `navigate_page {pageId, type, url, timeout}`
//! and `new_page {url, background}`, Playwright MCP `browser_navigate {url}`
//! and `browser_tabs {action: "new", url}`, Puppeteer `puppeteer_navigate
//! {url}`, Claude in Chrome `navigate {url, tabId}` and Browserbase `navigate
//! {url}`. Such a call is
//! reported as `opens` instead of `hosts`, and the engine decides it as a
//! `fetch` of a plain web page, as it decides `WebFetch`.
//!
//! The check is an allowlist, as for a `curl` that sends nothing (ADR-035):
//! the tool's name has a word that opens a page and none that sends data;
//! the arguments are one object holding exactly one URL under a URL key, and
//! otherwise only the keys of [`INERT_KEYS`] with a plain value. Anything else
//! (a script to run on the page such as `initScript`, launch options, headers,
//! text to type, a second URL, a nested object) keeps the call as it was: its
//! URL a `net` host, denied for unlisted hosts by the default policy.
//!
//! A generic HTTP server's `fetch` is not a page open: such servers differ in
//! what else they send (methods, headers, bodies under names of their own),
//! so their URLs stay `net` hosts.

use serde_json::{Map, Value};

use super::snake;

/// Words of a tool's name (in snake case, split at `_`) that open a page.
const OPEN_WORDS: &[&str] = &["navigate", "goto", "visit", "open"];
/// Two words in a row that open a page (`new_page`, `go_to`).
const OPEN_PAIRS: &[[&str; 2]] = &[["new", "page"], ["new", "tab"], ["go", "to"]];
/// Words that make a tool do more than open a page, whatever its arguments.
const SENDING_WORDS: &[&str] = &[
    "type", "fill", "click", "press", "submit", "upload", "evaluate", "eval", "execute", "exec",
    "run", "script", "inject", "cookie", "cookies", "header", "headers", "post", "send", "form",
    "select", "drag", "drop", "hover", "act", "write", "set", "input", "key", "emulate", "route",
    "install", "launch", "login", "auth",
];

/// Argument keys (in snake case) that only say which tab, how long to wait or
/// how much to return: nothing in them reaches the page or the network.
const INERT_KEYS: &[&str] = &[
    "page_id",
    "tab_id",
    "timeout",
    "ignore_cache",
    "handle_before_unload",
    "background",
    "isolated_context",
    "wait_until",
];

/// Keys whose value says what kind of navigation it is (`type` of Chrome
/// DevTools `navigate_page`, `action` of Playwright `browser_tabs`), with the
/// values that open the URL or move through the tab's history.
const KIND_KEYS: &[(&str, &[&str])] = &[
    ("type", &["url", "back", "forward", "reload"]),
    ("action", &["new", "open", "navigate", "goto"]),
];

/// A `url` value that names a step through the tab's history, not a URL
/// (Claude in Chrome `navigate {url: "back"}`).
const HISTORY: &[&str] = &["back", "forward"];

/// What a read-only open names.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Open {
    /// The one URL it opens.
    Url(String),
    /// A step back or forward through the tab's history: no URL.
    History,
}

/// The page `tool` (its own name, without `mcp__<server>__`) only opens with
/// arguments `args`, if it does nothing else.
pub(super) fn open(tool: &str, args: &Value) -> Option<Open> {
    let Value::Object(map) = args else {
        return None;
    };
    let words: Vec<String> = snake(tool).split('_').map(str::to_owned).collect();
    if words.iter().any(|w| SENDING_WORDS.contains(&w.as_str())) {
        return None;
    }
    let opens_by_name = words.iter().any(|w| OPEN_WORDS.contains(&w.as_str()))
        || words.windows(2).any(|pair| {
            OPEN_PAIRS
                .iter()
                .any(|p| pair[0] == p[0] && pair[1] == p[1])
        });
    let opens_by_kind = map
        .iter()
        .any(|(k, v)| snake(k) == "action" && v.as_str().is_some_and(|v| v == "new"));
    if !(opens_by_name || opens_by_kind) {
        return None;
    }
    let url = only_url(map)?;
    if HISTORY.iter().any(|h| url.eq_ignore_ascii_case(h)) {
        return Some(Open::History);
    }
    Some(Open::Url(url))
}

/// The one string under a URL key of `map`, when every other key is inert.
fn only_url(map: &Map<String, Value>) -> Option<String> {
    let mut url: Option<String> = None;
    for (key, value) in map {
        let key = snake(key);
        if super::names_url(&key) {
            match value {
                Value::String(s) if !s.is_empty() && url.is_none() => url = Some(s.clone()),
                _ => return None,
            }
        } else if !inert(&key, value) {
            return None;
        }
    }
    url
}

/// Whether `key` is inert with `value`: a plain value under [`INERT_KEYS`], or
/// one of the values a [`KIND_KEYS`] key allows.
fn inert(key: &str, value: &Value) -> bool {
    if let Some((_, values)) = KIND_KEYS.iter().find(|(k, _)| *k == key) {
        return value.as_str().is_some_and(|v| values.contains(&v));
    }
    INERT_KEYS.contains(&key)
        && matches!(
            value,
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
        )
}

#[cfg(test)]
mod tests {
    use super::{Open, open};
    use serde_json::json;

    fn url(u: &str) -> Open {
        Open::Url(u.to_owned())
    }

    /// The navigation tools of the popular browser servers, as their schemas
    /// spell them (ADR-047 lists the sources).
    #[test]
    fn the_browser_servers_navigation_tools_only_open_a_page() {
        let u = "https://docs.rs/serde";
        for (tool, args) in [
            (
                "navigate_page",
                json!({"pageId": 1, "type": "url", "url": u, "timeout": 5000}),
            ),
            (
                "navigate_page",
                json!({"pageId": 1, "url": u, "ignoreCache": true}),
            ),
            (
                "new_page",
                json!({"url": u, "background": false, "timeout": 1}),
            ),
            ("browser_navigate", json!({"url": u})),
            ("browser_tabs", json!({"action": "new", "url": u})),
            ("puppeteer_navigate", json!({"url": u})),
            ("navigate", json!({"url": u, "tabId": 7})),
            ("browserbase_stagehand_navigate", json!({"url": u})),
        ] {
            assert_eq!(open(tool, &args), Some(url(u)), "{tool} {args}");
        }
        assert_eq!(
            open("navigate", &json!({"url": "back", "tabId": 7})),
            Some(Open::History)
        );
    }

    #[test]
    fn a_call_that_sends_anything_else_is_not_an_open() {
        let u = "https://docs.rs/";
        for (tool, args) in [
            // a script run on the page before it loads
            (
                "navigate_page",
                json!({"pageId": 1, "url": u, "initScript": "fetch('//x')"}),
            ),
            (
                "puppeteer_navigate",
                json!({"url": u, "launchOptions": {"args": ["--proxy-server=x"]}}),
            ),
            (
                "puppeteer_navigate",
                json!({"url": u, "allowDangerous": true}),
            ),
            (
                "browser_navigate",
                json!({"url": u, "headers": {"Authorization": "x"}}),
            ),
            ("browser_navigate", json!({"url": [u]})),
            ("browser_navigate", json!({"url": u, "href": u})),
            ("browser_navigate", json!({"url": u, "timeout": {"ms": 1}})),
            ("browser_tabs", json!({"action": "close", "url": u})),
            ("navigate_page", json!({"type": "submit", "url": u})),
            ("browser_type", json!({"url": u})),
            ("browser_click", json!({"url": u})),
            ("navigate_and_fill", json!({"url": u})),
            ("evaluate_script", json!({"url": u})),
            ("browser_file_upload", json!({"url": u})),
            ("get_pull_request", json!({"url": u})),
            ("take_screenshot", json!({"url": u})),
            ("fetch", json!({"url": u, "max_length": 5000})),
            ("navigate", json!(u)),
        ] {
            assert_eq!(open(tool, &args), None, "{tool} {args}");
        }
        assert_eq!(open("browser_navigate_back", &json!({})), None, "no URL");
    }
}
