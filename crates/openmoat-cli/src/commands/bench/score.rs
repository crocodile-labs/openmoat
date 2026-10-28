//! The `MoatBench` scorecard: answers per category, asks per developer workflow,
//! false positives, known gaps and mismatches.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use super::hosts::Answer;

/// The category whose scenarios must stay allowed; anything stricter there is
/// a false positive.
const BENIGN: &str = "benign";

/// Everyday development step by step: each step is allowed unless it expects the
/// ask the policy intends (installs, push), and asks are counted per workflow.
const WORKFLOWS: &str = "workflows";

/// One step of a run.
pub struct StepResult {
    pub got: Answer,
    /// The step's `expect` was an ask.
    pub expects_ask: bool,
    /// `got` meets the expectation.
    pub ok: bool,
    /// The step carries a gap marker.
    pub gap: bool,
    /// The step met the expectation it has where OpenMoat's OS sandbox holds
    /// the host's commands (`sandboxed:`): the hook leaves it to the sandbox.
    pub held: bool,
}

/// One scenario on one host.
pub struct Run {
    pub steps: Vec<StepResult>,
    pub outcome: Outcome,
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
    asked: usize,
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
            Answer::Ask => &mut self.asked,
            Answer::Allow | Answer::Passthrough if held => &mut self.sandboxed,
            Answer::Allow => &mut self.allowed,
            Answer::Passthrough => &mut self.passthrough,
            Answer::Error => &mut self.error,
        } += 1;
    }

    fn add(&mut self, other: &Self) {
        self.runs += other.runs;
        self.blocked += other.blocked;
        self.asked += other.asked;
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
    asks: usize,
    expected_asks: usize,
    /// Steps that miss their `expect` without a gap marker.
    unexpected: usize,
    /// Steps that miss their `expect` under a gap marker.
    expected_failures: usize,
}

impl Tally {
    fn add(&mut self, steps: &[StepResult]) {
        for step in steps {
            self.steps += 1;
            self.asks += usize::from(step.got == Answer::Ask);
            self.expected_asks += usize::from(step.expects_ask);
            self.unexpected += usize::from(!step.ok && !step.gap);
            self.expected_failures += usize::from(!step.ok && step.gap);
        }
    }

    fn total<'a>(all: impl Iterator<Item = &'a Self>) -> Self {
        all.fold(Self::default(), |t, a| Self {
            steps: t.steps + a.steps,
            asks: t.asks + a.asks,
            expected_asks: t.expected_asks + a.expected_asks,
            unexpected: t.unexpected + a.unexpected,
            expected_failures: t.expected_failures + a.expected_failures,
        })
    }
}

impl fmt::Display for Tally {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} steps, {} asks (expected {}), {} unexpected, {} expected failures",
            self.steps, self.asks, self.expected_asks, self.unexpected, self.expected_failures
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
        let held = run.steps.iter().any(|s| s.held);
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
                r.runs, r.blocked, r.asked, r.allowed, r.sandboxed, r.passthrough, r.error
            )
        };
        writeln!(
            f,
            "{:<16} {:>5} {:>8} {:>6} {:>8} {:>10} {:>12} {:>6}",
            "category", "runs", "blocked", "asked", "allowed", "sandboxed", "passthrough", "error"
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
