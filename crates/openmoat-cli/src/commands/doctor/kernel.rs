//! `openmoat doctor`'s rows about what the kernel gives `openmoat run` here:
//! the Landlock ABI ladder (ADR-082) and the protection score of each tier this
//! system can start, the hook alone last (ADR-108).

use super::Area;
use super::human::Place;
use super::rows::Report;
use crate::report::{Mark, Row};
use crate::sandbox::landlock::abi::{self, Kernel};

/// The Landlock rows (Linux) and every tier's score.
pub(super) fn rows(report: &mut Report, verbose: bool) {
    if let Some(kernel) = crate::commands::run::landlock() {
        landlock(report, &kernel, verbose);
    }
    // A tier short of its whole score is a note, not a warning: the person's
    // system decides it, and `sandbox.strict: true` is how to refuse it.
    for tier in crate::commands::run::score::tiers() {
        let text = tier.line();
        if tier.warns() {
            report.note(&text);
        } else {
            report.line(Area::Sandbox, true, text);
        }
    }
}

/// The kernel's Landlock ABI and what `openmoat run` applies from it (ADR-082):
/// a warning below the floor, where `openmoat run` refuses; each step of the
/// ladder with `verbose`.
fn landlock(report: &mut Report, kernel: &Kernel, verbose: bool) {
    let text = format!("landlock         {}", abi::summary(kernel));
    if kernel.meets_floor() {
        report.line(Area::Sandbox, true, text);
    } else {
        report.warn(&text);
    }
    if verbose {
        for line in abi::lines(kernel) {
            report.human(Place::Details, Row::new(Mark::Info, "Landlock", line));
        }
    }
}
