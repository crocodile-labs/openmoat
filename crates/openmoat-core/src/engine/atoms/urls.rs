//! The atoms of a URL a tool names or opens (ADR-047).
//!
//! A URL in a tool's arguments is a `net` connection to every host a client
//! may read it as reaching ([`web::readings`]); a `file:` URL is a read of the
//! file it names; a URL whose scheme names no network address
//! (`javascript:`, `data:`, `chrome:`) asks, since nothing a rule names can
//! be read from it; `about:blank` is nothing. A call that only opens one page
//! ([`Action::McpTool`]'s `opens`) is a `fetch` of a plain web page instead,
//! with the hosts of the URLs inside it, which a browser follows on a
//! redirect.
//!
//! [`Action::McpTool`]: crate::action::Action::McpTool

use super::{EvalContext, file_atoms, read};
use crate::action::AtomicAction;
use crate::host::{self, web};
use crate::shell::Unparsed;

/// The atoms of `url`, named in a tool's arguments, added to `atoms`; `what`
/// names the arguments in a reason (`mcp`). Returns why it cannot be checked.
pub(super) fn named(
    url: &str,
    what: &str,
    ctx: &EvalContext,
    atoms: &mut Vec<AtomicAction>,
) -> Option<Unparsed> {
    match web::target(url) {
        web::Target::Hosts(hosts) => {
            atoms.extend(hosts.into_iter().map(|host| AtomicAction::Net { host }));
            None
        }
        web::Target::File { path, host } => {
            atoms.extend(host.map(|host| AtomicAction::Net { host }));
            match path {
                Some(path) => {
                    atoms.extend(file_atoms(&path, ctx, read));
                    None
                }
                None => Some(Unparsed {
                    reason: format!("file URL without an absolute path in {what} argument `{url}`"),
                    asks: true,
                }),
            }
        }
        web::Target::Blank => None,
        web::Target::Local(scheme) => Some(Unparsed {
            reason: format!(
                "a `{scheme}:` URL in {what} argument names no network address: it runs code \
                 or shows content or browser pages no rule can name"
            ),
            asks: true,
        }),
        web::Target::Unreadable => Some(Unparsed {
            reason: format!("no host in {what} argument `{url}`"),
            asks: false,
        }),
    }
}

/// The atoms of `url`, the one page a read-only call opens, added to `atoms`:
/// a `fetch` of each host when `as_fetch` (`mcp.browser_open`) and the URL is
/// a plain web page ([`web::page`]), as [`named`] otherwise; and the hosts of
/// the URLs inside it, `fetch` or `net` alike.
pub(super) fn opened(
    url: &str,
    as_fetch: bool,
    ctx: &EvalContext,
    atoms: &mut Vec<AtomicAction>,
) -> Option<Unparsed> {
    let url = web::with_scheme(url);
    let unparsed = match web::page(&url).filter(|_| as_fetch) {
        Some(hosts) => {
            atoms.extend(hosts.into_iter().map(|host| AtomicAction::Fetch { host }));
            None
        }
        None => named(&url, "mcp", ctx, atoms),
    };
    atoms.extend(web::embedded_hosts(&url).into_iter().map(|host| {
        if as_fetch && host::fetchable(&host) {
            AtomicAction::Fetch { host }
        } else {
            AtomicAction::Net { host }
        }
    }));
    unparsed
}

#[cfg(test)]
mod tests {
    use super::{named, opened};
    use crate::action::AtomicAction;
    use crate::engine::EvalContext;

    fn ctx() -> EvalContext {
        EvalContext {
            home: "/Users/me".into(),
            project: Some("/p".into()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: "/p".into(),
            case_insensitive_paths: false,
        }
    }

    fn fetch(host: &str) -> AtomicAction {
        AtomicAction::Fetch { host: host.into() }
    }

    fn net(host: &str) -> AtomicAction {
        AtomicAction::Net { host: host.into() }
    }

    fn open(url: &str, as_fetch: bool) -> (Vec<AtomicAction>, Option<bool>) {
        let mut atoms = Vec::new();
        let why = opened(url, as_fetch, &ctx(), &mut atoms);
        (atoms, why.map(|u| u.asks))
    }

    #[test]
    fn a_plain_page_is_a_fetch_and_anything_else_is_not() {
        assert_eq!(
            open("https://docs.rs/serde", true),
            (vec![fetch("docs.rs")], None)
        );
        assert_eq!(open("docs.rs/serde", true), (vec![fetch("docs.rs")], None));
        assert_eq!(
            open("https://docs.rs/serde", false),
            (vec![net("docs.rs")], None)
        );
        assert_eq!(
            open("http://localhost:3000/", true),
            (vec![net("localhost")], None)
        );
        assert_eq!(
            open("https://github.com@evil.com/", true),
            (vec![net("evil.com")], None)
        );
        assert_eq!(
            open("https://docs.rs/r?next=http://169.254.169.254/", true),
            (vec![fetch("docs.rs"), net("169.254.169.254")], None)
        );
        assert_eq!(
            open("https://docs.rs/r?next=https%3A%2F%2Fevil.com", true),
            (vec![fetch("docs.rs"), fetch("evil.com")], None)
        );
        assert_eq!(open("about:blank", true), (vec![], None));
        assert_eq!(open("javascript:alert(1)", true), (vec![], Some(true)));
        let (atoms, why) = open("file:///Users/me/.ssh/id_rsa", true);
        assert_eq!(
            atoms,
            [AtomicAction::FsRead {
                path: "/Users/me/.ssh/id_rsa".into()
            }]
        );
        assert_eq!(why, None);
    }

    #[test]
    fn a_named_url_is_judged_by_every_host_a_client_may_reach() {
        let mut atoms = Vec::new();
        assert!(named("https://evil.com\\@github.com/", "mcp", &ctx(), &mut atoms).is_none());
        assert_eq!(atoms, [net("github.com"), net("evil.com")]);
        let mut atoms = Vec::new();
        let why = named("file:relative", "mcp", &ctx(), &mut atoms).unwrap();
        assert!(why.asks, "{}", why.reason);
        let mut atoms = Vec::new();
        assert!(named("file://evil.com/share/x", "mcp", &ctx(), &mut atoms).is_none());
        assert_eq!(atoms[0], net("evil.com"));
    }
}
