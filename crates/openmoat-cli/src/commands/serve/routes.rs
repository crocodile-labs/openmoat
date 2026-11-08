//! The paths `openmoat serve` answers, each a read-only view built by the
//! command that prints it: `/` and `/api/status` (`openmoat status`),
//! `/show` (`openmoat show`), `/report` (`openmoat report`), `/why`
//! (`openmoat why`), each as a page and under `/api/` as the JSON the
//! command's `--format json` prints. Nothing here writes; there is no path
//! for any command that changes state.

use anyhow::Result;
use openmoat_hosts::Host;

use super::page;
use super::request::Request;
use super::response::Response;
use super::token::Token;
use crate::cli::{Format, ReportArgs, ShowArgs};

/// The most events one `/show?recent=` lists.
const MAX_RECENT: usize = 1000;

/// How many of the newest events the status page lists.
const STATUS_EVENTS: usize = 20;

/// How a view reads its parameters.
type Builder = fn(&Request) -> Result<View, Response>;

/// What a path asks for.
#[derive(Debug)]
pub enum Target {
    Style,
    View { view: View, api: bool },
}

#[derive(Debug)]
pub enum View {
    Status,
    Show(ShowArgs),
    Report(ReportArgs),
    Why(Option<String>),
}

/// The target of `req`, or 404 for a path that is none and 400 for a
/// parameter the view does not take.
pub fn route(req: &Request) -> Result<Target, Response> {
    let (api, path) = match req.path.strip_prefix("/api") {
        Some(rest) => (true, rest),
        None => (false, req.path.as_str()),
    };
    let (view, params): (Builder, &[&str]) = match path {
        "/style.css" if !api => {
            only(req, &[])?;
            return Ok(Target::Style);
        }
        "/" if !api => (|_| Ok(View::Status), &[]),
        "/status" => (|_| Ok(View::Status), &[]),
        "/show" => (show, &["id", "session", "since", "recent"]),
        "/report" => (report, &["since", "host"]),
        "/why" => (
            |r| Ok(View::Why(r.param("event").map(str::to_owned))),
            &["event"],
        ),
        _ => return Err(Response::text(404, "no such view")),
    };
    only(req, params)?;
    Ok(Target::View {
        view: view(req)?,
        api,
    })
}

/// 400 unless every parameter of `req` but the token is one of `allowed`.
fn only(req: &Request, allowed: &[&str]) -> Result<(), Response> {
    match req
        .query
        .iter()
        .find(|(name, _)| name != "token" && !allowed.contains(&name.as_str()))
    {
        Some((name, _)) => Err(Response::text(
            400,
            &format!("this view takes no `{}`", page::shown(name)),
        )),
        None => Ok(()),
    }
}

fn show(req: &Request) -> Result<View, Response> {
    let given = ["id", "session", "since"]
        .iter()
        .filter(|n| req.param(n).is_some())
        .count();
    if given > 1 {
        return Err(Response::text(400, "one of id, session or since"));
    }
    let recent = match req.param("recent") {
        Some(n) => n
            .parse::<usize>()
            .ok()
            .filter(|n| *n <= MAX_RECENT)
            .ok_or_else(|| Response::text(400, "recent is a number up to 1000"))?,
        None => 10,
    };
    Ok(View::Show(ShowArgs {
        id: req.param("id").map(str::to_owned),
        session: req.param("session").map(str::to_owned),
        since: req.param("since").map(str::to_owned),
        recent,
        format: Format::Json,
    }))
}

fn report(req: &Request) -> Result<View, Response> {
    let host = match req.param("host") {
        Some(id) => Some(
            id.parse::<Host>()
                .map_err(|_| Response::text(400, "no such host"))?,
        ),
        None => None,
    };
    Ok(View::Report(ReportArgs {
        since: req.param("since").unwrap_or("7d").to_owned(),
        host,
        format: Format::Json,
    }))
}

/// The response for `target`; an error the command would print is a 400
/// with its text.
pub fn answer(target: &Target, req: &Request, token: &Token) -> Response {
    match target {
        Target::Style => Response::new(200, "text/css; charset=utf-8", page::STYLE),
        Target::View { view, api } => match build(view, *api, req, token) {
            Ok(response) => response,
            Err(error) => Response::text(400, &crate::render::clean_lines(&format!("{error:#}"))),
        },
    }
}

fn build(view: &View, api: bool, req: &Request, token: &Token) -> Result<Response> {
    let (title, value, body) = match view {
        View::Status => {
            let value = super::super::status::json()?;
            let recent = if api {
                String::new()
            } else {
                let events = super::super::show::events(&recent(STATUS_EVENTS))?;
                format!("<h2>Latest decisions</h2>{}", page::events(&events, token))
            };
            let body = format!("{recent}<h2>Agents and checks</h2>{}", page::json(&value));
            ("status", value, body)
        }
        View::Show(args) => {
            let events = super::super::show::events(args)?;
            let body = if api {
                String::new()
            } else {
                page::events(&events, token)
            };
            ("decisions", serde_json::to_value(&events)?, body)
        }
        View::Report(args) => {
            let value = super::super::report::json(args)?;
            let body = page::json(&value);
            ("report", value, body)
        }
        View::Why(which) => {
            let value = super::super::why::json(which.as_deref())?;
            let body = page::json(&value);
            ("why", value, body)
        }
    };
    if api {
        let mut text = serde_json::to_string_pretty(&value)?;
        text.push('\n');
        return Ok(Response::new(200, "application/json", text));
    }
    let params: Vec<(&str, &str)> = req
        .query
        .iter()
        .filter(|(name, _)| name != "token")
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let path = if req.path == "/" {
        "/status"
    } else {
        req.path.as_str()
    };
    let json = page::href(&format!("/api{path}"), &params, token);
    let html = page::page(title, &body, &json, token);
    Ok(Response::new(200, "text/html; charset=utf-8", html))
}

fn recent(n: usize) -> ShowArgs {
    ShowArgs {
        id: None,
        session: None,
        since: None,
        recent: n,
        format: Format::Json,
    }
}
