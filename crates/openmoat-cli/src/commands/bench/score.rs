//! The `MoatBench` scorecard: answers per category, reviews per developer workflow,
//! false positives, known gaps and mismatches.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use super::hosts::Answer;

/// The category whose scenarios must stay allowed; anything stricter there is
/// a false positive.
const BENIGN: &str = "benign";

/// Everyday development step by step: each step is allowed unless it expects the
/// review the policy intends (installs, push), and reviews are counted per workflow.
const WORKFLOWS: &str = "workflows";

/// One step of a run.
pub struct StepResult {
    pub got: Answer,
    /// The step's `expect` was a review.
    pub expects_review: bool,
    /// `got` meets the expectation.
    pub ok: bool,
    /// The step carries a gap marker.
    pub gap: bool,
}

/// One scenario on one host.
pub struct Run {
    pub steps: Vec<StepResult>,
    pub outcome: Outcome,
    /// A step met the expectation it has where OpenMoat's OS sandbox holds the
    /// host's commands (`sandboxed:`): what the hook allows, the sandbox holds.
    pub held: bool,
    /// Where the kernel's verdict missed the scenario, known gaps included.
    pub policy: Vec<String>,
    /// Where the host's reading of the reply differs from the kernel's verdict.
    pub hook: Vec<String>,
}

pub enum Outcome {
    Pass,
    /// Mismatches tracked by gap markers; each line names its marker.
    Gap(Vec<String>),
    Fail(Vec<String>),
}

/// Runs of one category by their strictest answer.
#[derive(Default, Serialize)]
struct Row {
    runs: usize,
    blocked: usize,
    reviewed: usize,
    allowed: usize,
    /// Allowed or passed through by the hook where OpenMoat's OS sandbox holds
    /// the step, as the scenario expects there (`sandboxed:`).
    sandboxed: usize,
    passthrough: usize,
    error: usize,
}

impl Row {
    /// `held`: an allow or passthrough that the OS sandbox holds instead.
    fn count(&mut self, strictest: Answer, held: bool) {
        self.runs += 1;
        *match strictest {
            Answer::Deny => &mut self.blocked,
            Answer::Review => &mut self.reviewed,
            Answer::Allow | Answer::Passthrough if held => &mut self.sandboxed,
            Answer::Allow => &mut self.allowed,
            Answer::Passthrough => &mut self.passthrough,
            Answer::Error => &mut self.error,
        } += 1;
    }

    fn add(&mut self, other: &Self) {
        self.runs += other.runs;
        self.blocked += other.blocked;
        self.reviewed += other.reviewed;
        self.allowed += other.allowed;
        self.sandboxed += other.sandboxed;
        self.passthrough += other.passthrough;
        self.error += other.error;
    }
}

/// Step counts of one workflow across the hosts that ran it.
#[derive(Default, Clone, Copy, Serialize)]
struct Tally {
    steps: usize,
    reviews: usize,
    expected_reviews: usize,
    /// Steps that miss their `expect` without a gap marker.
    unexpected: usize,
    /// Steps that miss their `expect` under a gap marker.
    expected_failures: usize,
}

impl Tally {
    fn add(&mut self, steps: &[StepResult]) {
        for step in steps {
            self.steps += 1;
            self.reviews += usize::from(step.got == Answer::Review);
            self.expected_reviews += usize::from(step.expects_review);
            self.unexpected += usize::from(!step.ok && !step.gap);
            self.expected_failures += usize::from(!step.ok && step.gap);
        }
    }

    fn total<'a>(all: impl Iterator<Item = &'a Self>) -> Self {
        all.fold(Self::default(), |t, a| Self {
            steps: t.steps + a.steps,
            reviews: t.reviews + a.reviews,
            expected_reviews: t.expected_reviews + a.expected_reviews,
            unexpected: t.unexpected + a.unexpected,
            expected_failures: t.expected_failures + a.expected_failures,
        })
    }
}

impl fmt::Display for Tally {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} steps, {} reviews (expected {}), {} unexpected, {} expected failures",
            self.steps,
            self.reviews,
            self.expected_reviews,
            self.unexpected,
            self.expected_failures
        )
    }
}

#[derive(Default, Serialize)]
pub struct Scorecard {
    categories: BTreeMap<String, Row>,
    workflows: BTreeMap<String, Tally>,
    false_positives: Vec<String>,
    known_gaps: Vec<String>,
    mismatches: Vec<String>,
    /// Scenario id → (gap issue, whether any run still shows it).
    #[serde(skip)]
    gap_seen: BTreeMap<String, (String, bool)>,
}

impl Scorecard {
    pub fn add(&mut self, category: &str, id: &str, host: &str, run: Run) {
        let strictest = run
            .steps
            .iter()
            .map(|s| s.got)
            .max()
            .unwrap_or(Answer::Allow);
        let held = run.held;
        self.categories
            .entry(category.to_owned())
            .or_default()
            .count(strictest, held);
        if category == WORKFLOWS {
            self.workflows
                .entry(id.to_owned())
                .or_default()
                .add(&run.steps);
        }
        let name = format!("{id} ({host})");
        if category == BENIGN && !strictest.meets(Answer::Allow) {
            self.false_positives
                .push(format!("{name}: {}", strictest.word()));
        }
        match run.outcome {
            Outcome::Pass => {}
            Outcome::Gap(lines) => {
                // Only a scenario-level marker is tracked here; a step marker that
                // passes is already a failure of its run.
                if let Some((_, seen)) = self.gap_seen.get_mut(id) {
                    *seen = true;
                }
                self.known_gaps.push(format!("{name} {}", lines.join("; ")));
            }
            Outcome::Fail(problems) => self
                .mismatches
                .push(format!("{name}: {}", problems.join("; "))),
        }
    }

    /// A gap marker on a scenario that now passes everywhere must be removed,
    /// so the marker never outlives its fix.
    pub fn note_gap(&mut self, id: &str, issue: &str) {
        self.gap_seen
            .entry(id.to_owned())
            .or_insert_with(|| (issue.to_owned(), false));
    }

    pub fn check_gaps(&mut self) {
        for (id, (issue, seen)) in &self.gap_seen {
            if !*seen {
                self.mismatches.push(format!(
                    "{id}: marked as gap {issue} but passes; remove the marker"
                ));
            }
        }
    }
}

impl fmt::Display for Scorecard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let line = |f: &mut fmt::Formatter<'_>, name: &str, r: &Row| {
            writeln!(
                f,
                "{name:<16} {:>5} {:>8} {:>6} {:>8} {:>10} {:>12} {:>6}",
                r.runs, r.blocked, r.reviewed, r.allowed, r.sandboxed, r.passthrough, r.error
            )
        };
        writeln!(
            f,
            "{:<16} {:>5} {:>8} {:>6} {:>8} {:>10} {:>12} {:>6}",
            "category",
            "runs",
            "blocked",
            "reviewed",
            "allowed",
            "sandboxed",
            "passthrough",
            "error"
        )?;
        let mut total = Row::default();
        for (category, row) in &self.categories {
            line(f, category, row)?;
            total.add(row);
        }
        line(f, "total", &total)?;
        writeln!(f, "workflows: {}", Tally::total(self.workflows.values()))?;
        for (id, tally) in &self.workflows {
            writeln!(f, "  {id:<24} {tally}")?;
        }
        for (title, list) in [
            ("false positives", &self.false_positives),
            ("known gaps", &self.known_gaps),
            ("mismatches", &self.mismatches),
        ] {
            writeln!(f, "{title}: {}", list.len())?;
            for line in list {
                writeln!(f, "  {line}")?;
            }
        }
        Ok(())
    }
}
