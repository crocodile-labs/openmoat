//! `openmoat policy check-diff` (ADR-050): what a change (a pull request, a
//! branch, any unified diff) does that the policy protects, before it is merged.
//!
//! Exit codes follow `policy check` (ADR-004): 0 nothing found, 2 something
//! the policy denies, 3 something only for review, 64 the change or a policy
//! could not be read.

mod gate;
mod output;
mod parse;
mod source;

use anyhow::Result;

use crate::cli::{CheckDiffArgs, DiffFormat};
use crate::exit::Code;
use gate::{Gate, Level};
use output::Report;

pub fn run(args: &CheckDiffArgs) -> Result<Code> {
    let input = match &args.base {
        Some(base) => source::from_git(
            base,
            args.head.as_deref().unwrap_or("HEAD"),
            args.policy.as_deref(),
        )?,
        None => source::from_stdin(args.policy.as_deref())?,
    };
    let gate = Gate::new(&input.policy, &input.policy_files)?;
    let mut findings = gate.check(&input.files);
    findings.extend(input.unchecked);
    let report = Report::new(
        &findings,
        input.files.len(),
        &input.policy_source,
        input.repo_policy.as_deref(),
    );
    output::write(args.format.unwrap_or_else(default_format), &report)?;
    Ok(match output::worst(&findings) {
        Some(Level::Deny) => Code::Deny,
        Some(Level::Review) => Code::Review,
        None => Code::Ok,
    })
}

/// Workflow annotations when GitHub Actions runs the check, text otherwise.
fn default_format() -> DiffFormat {
    if std::env::var_os("GITHUB_ACTIONS").is_some_and(|v| v == "true") {
        DiffFormat::Github
    } else {
        DiffFormat::Text
    }
}

#[cfg(test)]
mod tests;
