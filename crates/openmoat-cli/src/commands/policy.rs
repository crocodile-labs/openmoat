//! `moat policy lint`, `moat policy check` and `moat policy compile`.

use std::io::{self, Write as _};
use std::path::PathBuf;

use anyhow::Result;
use openmoat_core::ir::{self, Access, Enforcement};
use openmoat_core::{Action, CompiledPolicy, Decision, NoResolver, Policy, ProgramResolver};

use crate::cli::{ActionKind, CheckArgs, CompileArgs, Format, LintArgs};
use crate::context;
use crate::environment::Snapshot;
use crate::exit::Code;
use crate::home::Home;
use crate::integrity;
use crate::realpath::FsPathResolver;
use crate::render;

mod upgrade;

pub use upgrade::run as upgrade;

pub fn lint(args: &LintArgs) -> Result<Code> {
    let (policy, path) = load(args.file.clone())?;
    let warnings = openmoat_core::lint::warnings(&policy);
    let mut out = io::stdout().lock();
    for warning in &warnings {
        writeln!(out, "warning: {warning}")?;
    }
    let (deny, allow, ask) = policy.rule_count();
    let suffix = match warnings.len() {
        0 => String::new(),
        1 => ", 1 warning".to_owned(),
        n => format!(", {n} warnings"),
    };
    writeln!(
        out,
        "ok: {} ({deny} deny, {allow} allow, {ask} ask groups{suffix})",
        path.display()
    )?;
    Ok(Code::Ok)
}

pub fn check(args: &CheckArgs) -> Result<Code> {
    // The installed policy decides nothing while the lock is broken: report the
    // `kernel-integrity` deny `guard` would answer instead of the policy's verdict.
    if args.policy.is_none()
        && let Some(decision) = integrity::violation(&Home::locate()?)?
    {
        return report(&decision, args.format);
    }
    let home = Home::locate()?;
    let ctx = context::eval_context(&home, args.cwd.as_deref(), args.project.as_deref())?;
    // The installed policy decides with the project's repository policy, as in `guard`.
    let policy = match &args.policy {
        Some(path) => context::load_policy(path)?,
        None => crate::repo::effective_policy(&home, &ctx)?,
    };
    // Decide the way `guard` would: symlinks resolved on this machine, and
    // programs resolved through the installation snapshot when one exists.
    let snapshot = Snapshot::load(&home.environment_path()).ok();
    let programs: &dyn ProgramResolver = match &snapshot {
        Some(snapshot) => snapshot,
        None => &NoResolver,
    };
    let decision = CompiledPolicy::compile(&policy, &ctx)?.decide_with(
        &to_action(args.kind, &args.action),
        programs,
        &FsPathResolver,
    );
    report(&decision, args.format)
}

pub fn compile(args: &CompileArgs) -> Result<Code> {
    let (policy, _) = load(args.policy.clone())?;
    let ctx = context::eval_context(
        &Home::locate()?,
        args.cwd.as_deref(),
        args.project.as_deref(),
    )?;
    let ir = ir::lower(&policy, &ctx)?;
    match args.format {
        Format::Json => render::json(&ir)?,
        Format::Text => compile_text(&ir)?,
    }
    Ok(Code::Ok)
}

fn compile_text(ir: &Enforcement) -> Result<()> {
    let mut out = io::stdout().lock();
    let case = if ir.fs.case_insensitive {
        "case-insensitive"
    } else {
        "case-sensitive"
    };
    writeln!(out, "filesystem ({case} paths)")?;
    access_text(&mut out, "fs.read", &ir.fs.read)?;
    access_text(&mut out, "fs.write", &ir.fs.write)?;
    writeln!(out, "egress")?;
    access_text(&mut out, "net", &ir.egress.net)?;
    access_text(&mut out, "fetch", &ir.egress.fetch)?;
    writeln!(
        out,
        "decide-only (the hook applies these; OS layers cannot see them)"
    )?;
    for d in &ir.decide_only {
        writeln!(out, "  {}: {}", d.kind, d.rules.join(", "))?;
    }
    writeln!(
        out,
        "losses ({}; OS layers deny where the hook would not)",
        ir.losses.len()
    )?;
    for loss in &ir.losses {
        writeln!(out, "  {loss}")?;
    }
    writeln!(
        out,
        "allowances ({}; OS layers allow where the hook would not, ADR-021)",
        ir.allowances.len()
    )?;
    for allowance in &ir.allowances {
        writeln!(out, "  {allowance}")?;
        writeln!(out, "    {}", allowance.patterns.join(" "))?;
    }
    Ok(())
}

fn access_text(out: &mut impl io::Write, kind: &str, access: &Access) -> Result<()> {
    writeln!(out, "  {kind}: default {}", effect(access.default))?;
    for (label, rules) in [("deny", &access.deny), ("allow", &access.allow)] {
        for rule in rules {
            writeln!(
                out,
                "    {label} {} ({}): {}",
                rule.id,
                rule.list,
                rule.patterns.join(" ")
            )?;
        }
    }
    Ok(())
}

fn effect(effect: ir::Effect) -> &'static str {
    match effect {
        ir::Effect::Allow => "allow",
        ir::Effect::Deny => "deny",
    }
}

fn report(decision: &Decision, format: Format) -> Result<Code> {
    match format {
        Format::Text => render::decision_text(decision)?,
        Format::Json => render::decision_json(decision)?,
    }
    Ok(decision.verdict.into())
}

fn load(explicit: Option<PathBuf>) -> Result<(Policy, PathBuf)> {
    if let Some(path) = explicit {
        return Ok((context::load_policy(&path)?, path));
    }
    let home = Home::locate()?;
    Ok((home.load_policy()?, home.policy_path()))
}

fn to_action(kind: ActionKind, value: &str) -> Action {
    let value = value.to_owned();
    match kind {
        ActionKind::Shell => Action::Shell { command: value },
        ActionKind::FsRead => Action::FsRead { path: value },
        ActionKind::FsWrite => Action::FsWrite { path: value },
        ActionKind::Net => Action::Net { url: value },
        ActionKind::Fetch => Action::Fetch { url: value },
        ActionKind::Mcp => Action::mcp(value),
    }
}
