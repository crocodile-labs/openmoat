//! What `openmoat doctor`'s checks report: each check's row for `--format
//! json` and the bug-report bundle, the problems that set the exit code, and
//! where the row goes in the text output (`human.rs`).

use super::Area;
use super::human::{self, Place, Placed};
use super::json::{self, Status};
use crate::protection::Protection;
use crate::render::Deferred;
use crate::report::Row;

pub(super) struct Report {
    pub problems: Vec<(Area, String)>,
    /// What `--accept` asks and answers, and the text output once written.
    pub out: Deferred,
    /// Every row in order, for `--format json`.
    pub rows: Vec<json::Row>,
    /// The text output's rows, placed.
    pub human: Vec<Placed>,
    /// Each agent's protection level, for the `Agents` section.
    pub agents: Vec<Protection>,
}

impl Report {
    pub fn new(out: Deferred) -> Self {
        Self {
            problems: Vec::new(),
            out,
            rows: Vec::new(),
            human: Vec::new(),
            agents: Vec::new(),
        }
    }

    /// A check that passed (`ok`) or a problem, which makes the exit code 64.
    pub fn line(&mut self, area: Area, ok: bool, text: String) {
        let status = if ok { Status::Ok } else { Status::Problem };
        self.push(status, Some(area), &text, None, None);
        self.problem(area, ok, text);
    }

    /// [`Self::line`], shown as `row` in `place` in the text output.
    pub fn line_as(&mut self, area: Area, ok: bool, text: String, place: Place, row: Row) {
        let status = if ok { Status::Ok } else { Status::Problem };
        self.push(status, Some(area), &text, Some(place), Some(row));
        self.problem(area, ok, text);
    }

    /// Count a check that did not pass (`ok` false) among the problems.
    fn problem(&mut self, area: Area, ok: bool, text: String) {
        if !ok {
            self.problems.push((area, text));
        }
    }

    pub fn note(&mut self, text: &str) {
        self.push(Status::Note, None, text, None, None);
    }

    /// [`Self::note`], shown in `place`.
    pub fn note_at(&mut self, text: &str, place: Place) {
        self.push(Status::Note, None, text, Some(place), None);
    }

    /// A row that needs attention without being a problem: the exit code stays 0.
    pub fn warn(&mut self, text: &str) {
        self.push(Status::Warning, None, text, None, None);
    }

    /// [`Self::warn`], shown in `place`.
    pub fn warn_at(&mut self, text: &str, place: Place) {
        self.push(Status::Warning, None, text, Some(place), None);
    }

    /// [`Self::warn`], shown as `row` in the text output.
    pub fn warn_as(&mut self, text: &str, row: Row) {
        self.push(
            Status::Warning,
            None,
            text,
            Some(Place::Attention),
            Some(row),
        );
    }

    /// A row of the text output only, in `place`.
    pub fn human(&mut self, place: Place, row: Row) {
        self.human.push(Placed { place, row });
    }

    fn push(
        &mut self,
        status: Status,
        area: Option<Area>,
        text: &str,
        place: Option<Place>,
        row: Option<Row>,
    ) {
        let json = json::Row::new(status, area, text);
        let place = place.unwrap_or_else(|| human::default_place(status, area, &json.name));
        let row = row.unwrap_or_else(|| human::default_row(status, &json, place));
        self.human.push(Placed { place, row });
        // With `--verbose` every check is listed as it was found.
        if place != Place::Details {
            let details = human::default_row(status, &json, Place::Details);
            self.human.push(Placed {
                place: Place::Details,
                row: details,
            });
        }
        self.rows.push(json);
    }
}
