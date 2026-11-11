//! `openmoat audit deliver status|test|flush` (ADR-081).

use std::io::{self, Write as _};
use std::time::Duration;

use anyhow::{Result, bail};
use openmoat_audit::EventId;
use openmoat_audit::delivery::{Delivered, Origin};
use serde::Serialize;

use crate::cli::{DeliverFlushArgs, DeliverStatusArgs, DeliverTestArgs, Format};
use crate::delivery::{self, Config, Ready, Sent, Sink, SinkRun, State};
use crate::exit::Code;
use crate::home::Home;
use crate::{render, time};

/// How long a person's `flush` may send for.
const FLUSH_BUDGET: Duration = Duration::from_mins(10);

/// Rule id of the record `test` sends.
const TEST_RULE: &str = "audit-delivery-test";

#[derive(Debug, Serialize)]
struct SinkStatus {
    id: String,
    kind: &'static str,
    url: String,
    /// The newest event the sink accepted; `None` before its first run.
    cursor: Option<EventId>,
    /// Events recorded after the cursor.
    behind: Option<u64>,
    delivered: u64,
    skipped: u64,
    pending_gaps: usize,
    failures: u32,
    next_attempt_ms: Option<i64>,
    paused: Option<String>,
    last_error: Option<String>,
    last_error_ms: Option<i64>,
    last_success_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
struct Status {
    configured: bool,
    /// Why nothing is sent, when the file exists but is not honoured.
    #[serde(skip_serializing_if = "Option::is_none")]
    refused: Option<String>,
    sinks: Vec<SinkStatus>,
}

pub fn status(args: &DeliverStatusArgs) -> Result<Code> {
    let home = Home::locate()?;
    let (status, code) = match delivery::load_pinned(&home) {
        Ok(None) => (
            Status {
                configured: false,
                refused: None,
                sinks: Vec::new(),
            },
            Code::Ok,
        ),
        Ok(Some((config, _))) => (
            Status {
                configured: true,
                refused: None,
                sinks: sink_statuses(&home, &config)?,
            },
            Code::Ok,
        ),
        Err(error) => (
            Status {
                configured: true,
                refused: Some(format!("{error:#}")),
                sinks: Vec::new(),
            },
            Code::Usage,
        ),
    };
    match args.format {
        Format::Json => render::json(&status)?,
        Format::Text => status_text(&home, &status)?,
    }
    Ok(code)
}

fn sink_statuses(home: &Home, config: &Config) -> Result<Vec<SinkStatus>> {
    let store = home.open_audit()?;
    let head = store.latest_id()?.unwrap_or(EventId(0));
    let now = time::now_ms();
    let mut out = Vec::new();
    for sink in &config.sinks {
        let state = State::load(&State::path(home, &sink.id))?;
        let behind = state
            .cursor
            .map(|c| store.count_between(c, head))
            .transpose()?;
        out.push(SinkStatus {
            id: sink.id.clone(),
            kind: sink.kind.id(),
            url: sink.url.clone(),
            cursor: state.cursor,
            behind,
            delivered: state.delivered,
            skipped: state.skipped,
            pending_gaps: state.gaps.len(),
            failures: state.failures,
            next_attempt_ms: (state.next_attempt_ms > now).then_some(state.next_attempt_ms),
            paused: state.paused,
            last_error: state.last_error,
            last_error_ms: state.last_error_ms,
            last_success_ms: state.last_success_ms,
        });
    }
    Ok(out)
}

fn status_text(home: &Home, status: &Status) -> Result<()> {
    let mut out = io::stdout().lock();
    let path = home.delivery_config_path();
    if !status.configured {
        writeln!(
            out,
            "audit delivery is off: no {} (docs/USAGE.md, \"Deliver the audit log\")",
            path.display()
        )?;
        return Ok(());
    }
    if let Some(why) = &status.refused {
        writeln!(out, "✗ nothing is sent: {why}")?;
        return Ok(());
    }
    for s in &status.sinks {
        let mark = if s.paused.is_some() || s.failures > 0 {
            "✗"
        } else {
            "✔"
        };
        writeln!(out, "{mark} {} ({}) → {}", s.id, s.kind, s.url)?;
        match s.behind {
            Some(behind) => writeln!(
                out,
                "   {} delivered, {behind} behind, {} skipped (backlog full or too large){}",
                s.delivered,
                s.skipped,
                if s.pending_gaps > 0 {
                    ", a gap still to report"
                } else {
                    ""
                }
            )?,
            None => writeln!(out, "   not started: the next hook call starts it")?,
        }
        if let Some(ms) = s.last_success_ms {
            writeln!(out, "   last accepted {}", time::timestamp(ms))?;
        }
        if let (Some(error), Some(ms)) = (&s.last_error, s.last_error_ms) {
            writeln!(out, "   last failure {}: {error}", time::timestamp(ms))?;
        }
        if let Some(why) = &s.paused {
            writeln!(
                out,
                "   paused ({why}): fix the sink, then run `openmoat audit deliver flush`"
            )?;
        } else if let Some(ms) = s.next_attempt_ms {
            writeln!(out, "   next try {}", time::timestamp(ms))?;
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct TestResult {
    sink: String,
    accepted: bool,
    answer: String,
}

pub fn test(args: &DeliverTestArgs) -> Result<Code> {
    let home = Home::locate()?;
    let Some((config, _)) = delivery::load_pinned(&home)? else {
        bail!(
            "no {}; nothing to test (docs/USAGE.md, \"Deliver the audit log\")",
            home.delivery_config_path().display()
        );
    };
    let sinks: Vec<&Sink> = config
        .sinks
        .iter()
        .filter(|s| args.sink.as_ref().is_none_or(|id| *id == s.id))
        .collect();
    if sinks.is_empty() {
        bail!("no sink is named `{}`", args.sink.as_deref().unwrap_or(""));
    }
    let user_home = crate::home::user_home()?.to_string_lossy().into_owned();
    let mut results = Vec::new();
    for sink in sinks {
        let origin = Origin {
            machine: &config.machine,
            version: env!("CARGO_PKG_VERSION"),
        };
        let now = time::now_ms();
        let sent = Ready::new(sink, &user_home)
            .and_then(|ready| ready.send(sink, origin, &[test_record(now)], &[], now));
        let (accepted, answer) = match sent {
            Ok(Sent::Accepted) => (true, "accepted".to_owned()),
            Ok(Sent::Retry { why, .. } | Sent::Refused { why }) => (false, why),
            Ok(Sent::TooLarge) => (false, "HTTP 413".to_owned()),
            // The collector's message is not shown: it may echo a header.
            Ok(Sent::Partial(rejected)) => (
                false,
                format!(
                    "accepted without {} log record(s) (OTLP partial success)",
                    rejected.count
                ),
            ),
            Err(error) => (false, format!("{error:#}")),
        };
        results.push(TestResult {
            sink: sink.id.clone(),
            accepted,
            answer,
        });
    }
    match args.format {
        Format::Json => render::json(&results)?,
        Format::Text => {
            let mut out = io::stdout().lock();
            for r in &results {
                let mark = if r.accepted { "✔" } else { "✗" };
                writeln!(out, "{mark} {}: {}", r.sink, r.answer)?;
            }
        }
    }
    Ok(if results.iter().all(|r| r.accepted) {
        Code::Ok
    } else {
        Code::Usage
    })
}

/// A record that is no agent's call, in the shape every delivered event has.
fn test_record(now_ms: i64) -> Delivered {
    Delivered {
        id: EventId(0),
        ts_ms: now_ms,
        host: delivery::DELIVERY_HOST.to_owned(),
        session_id: "test".to_owned(),
        call_id: None,
        cwd: None,
        tool: "deliver".to_owned(),
        action: serde_json::Value::Null,
        verdict: "allow".to_owned(),
        rules: vec![TEST_RULE.to_owned()],
        reasons: vec![
            "a test record from `openmoat audit deliver test`, not an agent's call".to_owned(),
        ],
        latency_us: 0,
        hash: String::new(),
        prev_hash: String::new(),
    }
}

#[derive(Debug, Serialize)]
struct FlushResult {
    sink: String,
    delivered: u64,
    skipped: u64,
    stopped: Option<String>,
}

pub fn flush(args: &DeliverFlushArgs) -> Result<Code> {
    let home = Home::locate()?;
    if args.background {
        // Started by the guard: nobody reads the result, and the next call
        // or `status` shows what happened.
        let _ = delivery::run(&home, false, delivery::BACKGROUND_BUDGET);
        return Ok(Code::Ok);
    }
    let Some(runs) = delivery::run(&home, true, FLUSH_BUDGET)? else {
        bail!("another delivery run is going; try again when it ends");
    };
    let results: Vec<FlushResult> = runs.into_iter().map(result).collect();
    match args.format {
        Format::Json => render::json(&results)?,
        Format::Text => {
            let mut out = io::stdout().lock();
            if results.is_empty() {
                writeln!(out, "audit delivery is off: nothing to send")?;
            }
            for r in &results {
                let mark = if r.stopped.is_none() { "✔" } else { "✗" };
                write!(out, "{mark} {}: {} delivered", r.sink, r.delivered)?;
                if r.skipped > 0 {
                    write!(out, ", {} skipped (backlog full or too large)", r.skipped)?;
                }
                match &r.stopped {
                    Some(why) => writeln!(out, "; stopped: {why}")?,
                    None => writeln!(out)?,
                }
            }
        }
    }
    Ok(if results.iter().all(|r| r.stopped.is_none()) {
        Code::Ok
    } else {
        Code::Usage
    })
}

fn result(run: SinkRun) -> FlushResult {
    FlushResult {
        sink: run.sink,
        delivered: run.delivered,
        skipped: run.skipped,
        stopped: run.stopped,
    }
}
