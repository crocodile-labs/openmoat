//! `moat doctor --format json`: every check as one document, for tools that
//! show them (the `MoatBar` app). The same rows and exit code as the text output.

use anyhow::Result;
use openmoat_hosts::Host;
use serde::Serialize;

use super::Area;
use crate::exit::Code;
use crate::render;

/// How a row reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    /// `✔`: fine.
    Ok,
    /// `✗`: a problem; the exit code is not 0.
    Problem,
    /// `!`: needs a look, the exit code stays 0.
    Warning,
    /// `·`: information.
    Note,
}

/// One row: the text output's line, split into its label and the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Row {
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    area: Option<Area>,
    /// The left column (`policy`, `lock`, `Claude Code`), without its padding.
    name: String,
    /// The rest of the line.
    detail: String,
}

impl Row {
    /// The text output pads a label to a column, then the detail follows after
    /// at least two spaces; a line without such a gap is all detail. An agent's
    /// name as long as the column (`GitHub Copilot CLI`) is followed by one
    /// space only, so a line that starts with one is split after it.
    pub(super) fn new(status: Status, area: Option<Area>, text: &str) -> Self {
        let agent = Host::EVERY
            .iter()
            .map(|host| host.display_name())
            .find(|name| {
                text.strip_prefix(name)
                    .is_some_and(|rest| rest.starts_with(' '))
            });
        let (name, detail) = match (agent, text.find("  ")) {
            (Some(name), _) => (name, text[name.len()..].trim()),
            (None, Some(at)) => (text[..at].trim(), text[at..].trim()),
            (None, None) => ("", text.trim()),
        };
        Self {
            status,
            area,
            name: name.to_owned(),
            detail: detail.to_owned(),
        }
    }
}

#[derive(Serialize)]
struct Document<'a> {
    healthy: bool,
    problems: usize,
    checks: &'a [Row],
}

/// Print the document; the exit code is the text output's.
pub(super) fn finish(rows: &[Row], problems: usize) -> Result<Code> {
    render::json(&Document {
        healthy: problems == 0,
        problems,
        checks: rows,
    })?;
    Ok(if problems == 0 { Code::Ok } else { Code::Usage })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_splits_its_label_from_the_detail() {
        let row = Row::new(
            Status::Ok,
            Some(Area::Policy),
            "policy           /home/u/.moat/policy.yaml",
        );
        assert_eq!(
            (row.name.as_str(), row.detail.as_str()),
            ("policy", "/home/u/.moat/policy.yaml")
        );
        let row = Row::new(
            Status::Note,
            None,
            "Claude Code      protection: hook + sandbox",
        );
        assert_eq!(row.name, "Claude Code");
        // every agent's name, however long, is the label of its line
        for host in Host::EVERY {
            let name = host.display_name();
            let text = format!("{name:<16} protection: hook only");
            let row = Row::new(Status::Note, None, &text);
            assert_eq!(
                (row.name.as_str(), row.detail.as_str()),
                (name, "protection: hook only"),
                "{text}"
            );
        }
        let row = Row::new(Status::Warning, None, "healthy");
        assert_eq!((row.name.as_str(), row.detail.as_str()), ("", "healthy"));
    }

    #[test]
    fn the_document_names_each_status() {
        let rows = [
            Row::new(Status::Ok, Some(Area::Lock), "lock             intact"),
            Row::new(
                Status::Problem,
                Some(Area::Hook),
                "Codex            hook missing",
            ),
        ];
        let value = serde_json::to_value(Document {
            healthy: false,
            problems: 1,
            checks: &rows,
        })
        .unwrap();
        assert_eq!(value["checks"][0]["status"], "ok");
        assert_eq!(value["checks"][0]["area"], "lock");
        assert_eq!(value["checks"][1]["status"], "problem");
        assert_eq!(value["checks"][1]["detail"], "hook missing");
        assert_eq!(value["healthy"], false);
    }
}
