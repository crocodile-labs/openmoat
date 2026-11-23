//! Whether an upgrade widens the policy (ADR-111): the installed policy and
//! the upgraded one decided over the same cases. An upgrade that widens, or
//! changes a setting the check does not rank, is shown case by case and
//! applied only with `--accept-widening`, still only by a person at a terminal.

use std::io::Write;

use anyhow::{Context as _, Result};
use openmoat_core::Policy;
use openmoat_core::widen::Report;

use crate::upgrade::Plan;

/// The comparison of the policy as it is with the policy upgraded; `None`
/// when the upgrade changes no rule.
pub(super) fn check(plan: &Plan) -> Result<Option<Report>> {
    if plan.applicable() == 0 {
        return Ok(None);
    }
    let old = Policy::parse(&plan.current).context("reading the installed policy")?;
    let new = Policy::parse(&plan.merge.text).context("reading the upgraded policy")?;
    crate::widen::compare(&old, &new, &[]).map(Some)
}

/// Whether the upgrade needs `--accept-widening`.
pub(super) fn needs_acceptance(report: &Report) -> bool {
    report.widens() || report.unchecked()
}

/// What the comparison found, under the summary of the changes.
pub(super) fn write(out: &mut impl Write, report: &Report) -> Result<()> {
    writeln!(out)?;
    if needs_acceptance(report) {
        writeln!(out, "This upgrade widens your policy:")?;
        crate::widen::write_widenings(out, report, false)?;
    } else {
        writeln!(out, "✔ Nothing in this upgrade moves a call toward allow")?;
    }
    writeln!(out, "  {}", crate::widen::summary(report))?;
    Ok(())
}

/// Whether a widening upgrade is refused for want of `--accept-widening`;
/// says so when it is.
pub(super) fn refused(out: &mut impl Write, report: &Report, accepted: bool) -> Result<bool> {
    let refused = needs_acceptance(report) && !accepted;
    if refused {
        writeln!(
            out,
            "\nthe policy was not changed: this upgrade widens it (listed above); read the \
             cases, then run `openmoat policy upgrade --accept-widening` to apply it"
        )?;
    }
    Ok(refused)
}
