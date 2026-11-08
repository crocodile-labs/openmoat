//! The HTML pages: what each view's JSON holds, shown as it is, and the
//! events as a table. Every piece of text from the audit log or the policy
//! is cleaned as the terminal output is (`render::clean_lines`) and escaped;
//! the pages hold no script and load only this server's stylesheet.

use std::fmt::Write as _;

use openmoat_audit::Event;

use super::request::encode;
use super::token::Token;
use crate::render;

/// The stylesheet `/style.css` serves, the only thing a page loads.
pub const STYLE: &str = "body{font:15px/1.45 system-ui,sans-serif;margin:0;color:#1b1f24;\
background:#fafbfc}header{background:#0b3d4f;color:#fff;padding:.6em 1.2em}\
header a{color:#cfe8f0;margin-right:1em}main{padding:1em 1.2em}\
pre{background:#fff;border:1px solid #d0d7de;padding:.8em;overflow:auto;white-space:pre-wrap}\
table{border-collapse:collapse;background:#fff}td,th{border:1px solid #d0d7de;\
padding:.25em .5em;text-align:left;vertical-align:top}footer{color:#57606a;\
padding:1em 1.2em;font-size:13px}.deny{color:#a40e26}.review{color:#7d4e00}";

/// A link to `path` with `params` and the token, escaped for an attribute.
pub fn href(path: &str, params: &[(&str, &str)], token: &Token) -> String {
    let mut url = format!("{path}?");
    for (name, value) in params {
        let _ = write!(url, "{name}={}&", encode(value));
    }
    url.push_str("token=");
    url.push_str(token.as_str());
    escape(&url)
}

/// A whole page: the navigation, `title`, `body` (HTML already escaped) and
/// a link to the same view as JSON (`json`, an escaped href).
pub fn page(title: &str, body: &str, json: &str, token: &Token) -> String {
    let nav = [
        ("status", href("/", &[], token)),
        ("recent decisions", href("/show", &[], token)),
        ("report (7 days)", href("/report", &[], token)),
        ("newest deny or review", href("/why", &[], token)),
    ]
    .map(|(label, link)| format!("<a href=\"{link}\">{label}</a>"))
    .join("");
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <title>OpenMoat · {title}</title>\
         <link rel=\"stylesheet\" href=\"{style}\"></head><body>\
         <header><strong>OpenMoat</strong> · {nav}</header><main><h1>{title}</h1>{body}\
         <p><a href=\"{json}\">this view as JSON</a></p></main>\
         <footer>Read-only. Served by <code>openmoat serve</code> on this machine; the same \
         data the commands print with <code>--format json</code>.</footer></body></html>\n",
        title = escape(title),
        style = href("/style.css", &[], token),
    )
}

/// `value` as indented JSON in a `<pre>`.
pub fn json(value: &serde_json::Value) -> String {
    let text = serde_json::to_string_pretty(value).unwrap_or_default();
    format!("<pre>{}</pre>", shown(&text))
}

/// The events as `openmoat show` lists them, each linked to its explanation
/// and its session.
pub fn events(events: &[Event], token: &Token) -> String {
    if events.is_empty() {
        return "<p>no events</p>".to_owned();
    }
    let mut out = String::from(
        "<table><tr><th>id</th><th>time (UTC)</th><th>host</th><th>session</th>\
         <th>verdict</th><th>rules</th><th>action</th></tr>",
    );
    for event in events {
        let id = event.id.to_string();
        let verdict = event.verdict.as_str();
        let _ = write!(
            out,
            "<tr><td><a href=\"{why}\">{id}</a></td><td>{time}</td><td>{host}</td>\
             <td><a href=\"{session_link}\">{session}</a></td><td class=\"{verdict}\">{verdict}</td>\
             <td>{rules}</td><td>{action}</td></tr>",
            why = href("/why", &[("event", &id)], token),
            time = crate::time::timestamp(event.ts_ms),
            host = shown(&event.host),
            session_link = href("/show", &[("session", &event.session_id)], token),
            session = shown(&event.session_id),
            rules = shown(&event.rules.join(", ")),
            action = shown(&render::describe(event)),
        );
    }
    out.push_str("</table>");
    out
}

/// Text from the log or the policy, cleaned as on a terminal and escaped.
pub fn shown(text: &str) -> String {
    escape(&render::clean_lines(text))
}

/// `text` safe inside an element or a double-quoted attribute.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}
