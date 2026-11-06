//! `openmoat why`: one decision in full (ADR-059): the call, the rules that
//! decided it and where they are, how the policy decides each part of the
//! call now, the session's context, and how a person changes the outcome.
//! Reads the audit log and the policy files only.

use std::io;
use std::path::Path;

use anyhow::{Result, bail};
use openmoat_audit::{Event, EventId, Store};
use openmoat_core::{CompiledPolicy, Verdict};

use crate::cli::{Format, WhyArgs};
use crate::exit::Code;
use crate::home::Home;
use crate::realpath::FsPathResolver;
use crate::render;
use crate::report::Paths;

mod explain;
#[cfg(test)]
mod tests;

use explain::{Explanation, File, Files, Inputs, Part};

const MS_PER_DAY: i64 = 86_400_000;

pub fn run(args: &WhyArgs) -> Result<Code> {
    let home = Home::locate()?;
    let store = home.open_audit()?;
    let event = pick(&store, args.event.as_deref(), crate::time::now_ms())?;
    let paths = Paths::detect();
    let newest_review = store
        .latest_held()?
        .is_some_and(|e| e.id == event.id && e.verdict == Verdict::Review);
    let policy = home.load_policy().ok();
    let cwd = event.cwd.as_deref().map(Path::new);
    let ctx = crate::context::eval_context(&home, cwd, None);
    let repository = ctx
        .as_ref()
        .ok()
        .and_then(|ctx| ctx.project.as_deref())
        .and_then(|root| crate::repo::find(&home, Path::new(root)).ok().flatten())
        .map(|found| File {
            shown: paths.path(&found.path),
            text: found.text,
        });
    let read = |path: &Path| {
        std::fs::read_to_string(path).ok().map(|text| File {
            shown: paths.path(path),
            text,
        })
    };
    let inputs = Inputs {
        policy: policy.as_ref(),
        files: Files {
            policy: read(&home.policy_path()),
            approved: read(&home.overlay_path()),
            repository,
        },
        now: ctx
            .map_err(|e| format!("{e:#}"))
            .and_then(|ctx| decided_now(&home, &ctx, &event)),
        newest_review,
        paths: &paths,
    };
    let explained = explain::explain(&event, &inputs);
    match args.format {
        Format::Json => render::json(&explained)?,
        Format::Text => write(&mut io::stdout().lock(), &explained)?,
    }
    Ok(Code::Ok)
}

/// The event `which` names: an id, a time today (UTC), or the newest deny or
/// review when it names none.
fn pick(store: &Store, which: Option<&str>, now_ms: i64) -> Result<Event> {
    let Some(which) = which.map(str::trim) else {
        return match store.latest_held()? {
            Some(event) => Ok(event),
            None => bail!("no call was denied or held for review yet"),
        };
    };
    if let Some((start, end)) = time_today(which, now_ms) {
        let events = store.between(start, end)?;
        let held = events
            .iter()
            .rev()
            .find(|e| matches!(e.verdict, Verdict::Deny | Verdict::Review));
        return match held.or(events.last()) {
            Some(event) => Ok(event.clone()),
            None => bail!("no call was decided at {which} today (UTC)"),
        };
    }
    let id: EventId = which.parse()?;
    match store.get(id)? {
        Some(event) => Ok(event),
        None => bail!("no event {id}"),
    }
}

/// The window `HH:MM` (that minute) or `HH:MM:SS` (that second) of today in
/// UTC names; `None` for any other text.
fn time_today(text: &str, now_ms: i64) -> Option<(i64, i64)> {
    let parts: Vec<i64> = text
        .split(':')
        .map(|p| p.parse().ok().filter(|_| p.len() == 2))
        .collect::<Option<_>>()?;
    let (h, m, s, span) = match parts[..] {
        [h, m] => (h, m, 0, 60_000),
        [h, m, s] => (h, m, s, 1_000),
        _ => return None,
    };
    if h > 23 || m > 59 || s > 59 {
        return None;
    }
    let start = now_ms.div_euclid(MS_PER_DAY) * MS_PER_DAY + ((h * 60 + m) * 60 + s) * 1_000;
    Some((start, start + span))
}

/// How the policy as it is now decides each part of the event's call, as
/// `guard` would split it, after the same lock check `openmoat policy check` makes.
fn decided_now(
    home: &Home,
    ctx: &openmoat_core::EvalContext,
    event: &Event,
) -> Result<Vec<Part>, String> {
    let Some(action) = &event.action else {
        return Err("the tool is not one OpenMoat decides".to_owned());
    };
    let decide = || -> Result<Vec<Part>> {
        let verified = crate::integrity::check(home)?;
        if verified.checked.deny.is_some() {
            bail!("OpenMoat's pinned files changed; `openmoat doctor` shows what");
        }
        let policy = crate::repo::effective_policy(&verified.home, ctx)?;
        let compiled = CompiledPolicy::compile(&policy, ctx)?;
        let (atoms, _) = compiled.atoms(action, &FsPathResolver);
        Ok(atoms
            .iter()
            .filter_map(|atom| {
                let decided = compiled.evaluate_atomic(atom)?;
                Some(Part {
                    what: atom.describe(),
                    verdict: decided.verdict,
                    rules: decided.rules,
                })
            })
            .collect())
    };
    decide().map_err(|e| format!("{e:#}"))
}

/// The explanation as text.
fn write(out: &mut impl io::Write, e: &Explanation) -> io::Result<()> {
    let heading = match e.verdict {
        Verdict::Deny => "OpenMoat blocked",
        Verdict::Review => "OpenMoat held this for review",
        Verdict::Allow => "OpenMoat allowed",
        _ => "OpenMoat left this to the agent",
    };
    let title = e.rules.iter().find_map(|r| r.title.as_deref());
    let what = title.map_or_else(|| e.call.clone(), str::to_owned);
    render::line(out, &format!("{heading}: {what}"))?;
    let rows = [
        (
            "event",
            format!(
                "{} · {} · {} · session {}",
                e.event, e.time, e.host, e.session
            ),
        ),
        ("call", e.call.clone()),
        ("answer", e.line.clone()),
    ];
    for (label, text) in rows {
        render::line(out, &format!("  {label:<7} {text}"))?;
    }
    writeln!(out, "\nRules that decided it")?;
    for rule in &e.rules {
        let head = rule
            .title
            .as_deref()
            .map(|t| format!("  {t}"))
            .unwrap_or_default();
        render::line(out, &format!("  {} {}{head}", e.verdict.as_str(), rule.id))?;
        let details = [
            ("why", rule.why.clone()),
            ("reason", rule.reason.clone()),
            (
                "from",
                Some(
                    rule.source
                        .as_ref()
                        .map_or_else(|| rule.origin.clone(), |s| format!("{}, {s}", rule.origin)),
                ),
            ),
        ];
        for (label, text) in details {
            if let Some(text) = text {
                render::line(out, &format!("      {label:<7} {text}"))?;
            }
        }
    }
    match (&e.decided_now, &e.decided_now_error) {
        (Some(parts), _) if !parts.is_empty() => {
            writeln!(out, "\nYour policy now decides each part of the call as")?;
            for part in parts {
                let rules = part.rules.join(", ");
                let text = format!("  {:<7} {}  ({rules})", part.verdict.as_str(), part.what);
                render::line(out, &text)?;
            }
        }
        (_, Some(why)) => render::line(out, &format!("\nNot decided again now: {why}"))?,
        _ => {}
    }
    section(out, "Context", &e.context)?;
    section(out, "How to change it", &e.change)?;
    if let Some(page) = &e.page {
        writeln!(out, "\nMore: {page}")?;
    }
    Ok(())
}

fn section(out: &mut impl io::Write, heading: &str, lines: &[String]) -> io::Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    writeln!(out, "\n{heading}")?;
    for line in lines {
        render::line(out, &format!("  · {line}"))?;
    }
    Ok(())
}
