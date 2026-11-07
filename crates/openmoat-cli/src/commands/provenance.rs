//! `openmoat provenance` (ADR-056): which files and lines of commits agent
//! sessions wrote, from this machine's audit log; `--write-notes` keeps it
//! in git notes, `--verify` checks those notes against the log.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use openmoat_core::attribution::{CLOCK_SLACK_MS, Evidence, FileRecord, attribute};
use openmoat_core::{CompiledPolicy, DEFAULT_POLICY, Policy};
use serde::Serialize;

use crate::cli::{Format, ProvenanceArgs};
use crate::context::{self, CASE_INSENSITIVE_PATHS};
use crate::exit::Code;
use crate::home::Home;
use crate::provenance::NOTES_REF;
use crate::provenance::collect::{self, Root};
use crate::provenance::git::Reader;
use crate::provenance::notes::{self, Checked};
use crate::render::{self, Deferred};
use crate::time;

/// One commit's attribution.
#[derive(Debug, Serialize)]
pub struct Attributed {
    pub commit: String,
    pub files: Vec<FileRecord>,
    /// With `--write-notes`: whether a note was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noted: Option<bool>,
}

pub fn run(args: &ProvenanceArgs) -> Result<Code> {
    if args.write_notes {
        // An agent that could write notes could say what its own record is.
        crate::terminal::refuse_agent("openmoat provenance --write-notes")?;
        if !crate::terminal::interactive() {
            bail!(
                "`openmoat provenance --write-notes` must be run by a person in a terminal, \
                 not from a hook or script"
            );
        }
    }
    let git = Reader::here()?;
    let home = Home::locate()?;
    let store = home.open_audit()?;
    let commits = git.commits(args.range.as_deref())?;
    let facts = commits
        .iter()
        .rev()
        .map(|c| git.facts(c))
        .collect::<Result<Vec<_>>>()?;
    let policy = home
        .load_policy()
        .or_else(|_| Policy::parse(DEFAULT_POLICY).context("the default policy"))?;
    let ctx = context::eval_context(&home, Some(Path::new(&git.root)), None)?;
    let policy = CompiledPolicy::compile(&policy, &ctx)?;
    let real = std::fs::canonicalize(&git.root)
        .ok()
        .map(|p| context::path_string(&p));
    let root = Root::new(&git.root, real.as_deref(), CASE_INSENSITIVE_PATHS);
    let until = facts
        .iter()
        .map(|f| f.commit_ms)
        .max()
        .unwrap_or_default()
        .saturating_add(CLOCK_SLACK_MS);
    let writes = collect::writes(&store, &policy, &root, &facts, until)?;
    let mut attributed: Vec<Attributed> = facts
        .iter()
        .map(|f| Attributed {
            commit: f.commit.clone(),
            files: attribute(&f.as_commit(), &writes),
            noted: None,
        })
        .collect();
    if args.verify {
        return verify(&git, &store, &attributed, args.format);
    }
    if args.write_notes {
        for entry in attributed.iter_mut().filter(|a| !a.files.is_empty()) {
            let note = notes::build(&store, &entry.commit, entry.files.clone())?;
            git.write_note(&entry.commit, &notes::encode(&note)?)
                .with_context(|| format!("writing the note of {}", entry.commit))?;
            entry.noted = Some(true);
        }
    }
    if args.format == Format::Json {
        render::json(&attributed)?;
        return Ok(Code::Ok);
    }
    let mut out = Deferred::default();
    text(&mut out, &attributed)?;
    if args.write_notes {
        let written = attributed.iter().filter(|a| a.noted == Some(true)).count();
        writeln!(
            out,
            "✔ wrote {written} note(s) on {NOTES_REF}; nothing was pushed. Share them with \
             `git push <remote> {NOTES_REF}`"
        )?;
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// The attribution as text, one block per commit that has any.
pub fn text(out: &mut impl std::io::Write, attributed: &[Attributed]) -> std::io::Result<()> {
    let mut any = false;
    for entry in attributed.iter().filter(|a| !a.files.is_empty()) {
        any = true;
        writeln!(out, "{}", short(&entry.commit))?;
        for file in &entry.files {
            writeln!(out, "  {}", render::clean(&describe(file)))?;
        }
    }
    if !any {
        writeln!(
            out,
            "no agent writes recorded for {} commit(s): only what OpenMoat's hook saw on this \
             machine is known, so this does not show that a person wrote them",
            attributed.len()
        )?;
    }
    Ok(())
}

/// "src/a.rs: `<host>` session 1a2b… wrote the whole change (3 lines: 3-5), after
/// reading web content (fetch x.example) — event 1f, 2026-11-05 10:00".
pub fn describe(file: &FileRecord) -> String {
    let how = match file.evidence {
        Evidence::Lines => {
            let ranges: Vec<String> = file
                .lines
                .iter()
                .map(|r| {
                    if r.start == r.end {
                        r.start.to_string()
                    } else {
                        format!("{}-{}", r.start, r.end)
                    }
                })
                .collect();
            match file.line_count() {
                0 => "wrote the whole change".to_owned(),
                n => format!(
                    "wrote the whole change ({n} added lines: {})",
                    ranges.join(", ")
                ),
            }
        }
        Evidence::Content => "left the committed content".to_owned(),
        Evidence::Touched => {
            "wrote the file after the parent commit (it may have changed since)".to_owned()
        }
    };
    let after = file
        .untrusted
        .as_ref()
        .map(|u| format!(", after reading {} ({})", u.kind.describe(), u.source))
        .unwrap_or_default();
    format!(
        "{}: {} session {} {how}{after}; event {:x}, {}",
        file.path,
        file.host,
        file.session.get(..12).unwrap_or(&file.session),
        file.event,
        time::timestamp(file.ts_ms)
    )
}

/// Check every commit's note against the log; exit 64 when one does not match.
fn verify(
    git: &Reader,
    store: &openmoat_audit::Store,
    attributed: &[Attributed],
    format: Format,
) -> Result<Code> {
    let noted = git.noted()?;
    let chain = store.verify_chain()?;
    let mut checked = Vec::new();
    for entry in attributed {
        let Some(blob) = noted.get(&entry.commit) else {
            checked.push(Checked {
                commit: entry.commit.clone(),
                noted: false,
                problems: Vec::new(),
            });
            continue;
        };
        let problems = match git.note_text(blob).and_then(|t| notes::decode(&t)) {
            Ok(note) => notes::verify(store, &chain, &entry.commit, &note, &entry.files)?,
            Err(error) => vec![format!("{error:#}")],
        };
        checked.push(Checked {
            commit: entry.commit.clone(),
            noted: true,
            problems,
        });
    }
    let failed = checked.iter().any(|c| !c.problems.is_empty());
    if format == Format::Json {
        render::json(&checked)?;
    } else {
        let mut out = Deferred::default();
        verify_text(&mut out, &checked)?;
        out.finish()?;
    }
    Ok(if failed { Code::Usage } else { Code::Ok })
}

pub fn verify_text(out: &mut impl std::io::Write, checked: &[Checked]) -> std::io::Result<()> {
    for c in checked {
        match (c.noted, c.problems.as_slice()) {
            (false, _) => writeln!(out, "-  {} has no note", short(&c.commit))?,
            (true, []) => writeln!(
                out,
                "✔  {} note matches this machine's audit log",
                short(&c.commit)
            )?,
            (true, problems) => {
                writeln!(
                    out,
                    "✗ {} note does not match the audit log:",
                    short(&c.commit)
                )?;
                for problem in problems {
                    writeln!(out, "   {}", render::clean(problem))?;
                }
            }
        }
    }
    Ok(())
}

fn short(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

#[cfg(test)]
mod tests {
    use openmoat_core::UntrustedKind;
    use openmoat_core::attribution::{LineRange, Untrusted};

    use super::*;

    fn record(evidence: Evidence) -> FileRecord {
        FileRecord {
            path: "src/a.rs".to_owned(),
            host: "a-host".to_owned(),
            session: "0123456789abcdef".to_owned(),
            event: 31,
            ts_ms: 0,
            evidence,
            lines: vec![
                LineRange { start: 1, end: 4 },
                LineRange { start: 9, end: 9 },
            ],
            untrusted: Some(Untrusted {
                kind: UntrustedKind::Web,
                source: "fetch evil.example".to_owned(),
            }),
        }
    }

    #[test]
    fn a_file_line_names_the_session_the_lines_and_what_it_had_read() {
        let line = describe(&record(Evidence::Lines));
        assert!(
            line.starts_with(
                "src/a.rs: a-host session 0123456789ab wrote the whole change (5 added \
                 lines: 1-4, 9), after reading web content (fetch evil.example); event 1f, "
            ),
            "{line}"
        );
        assert!(describe(&record(Evidence::Touched)).contains("may have changed since"));
        assert!(describe(&record(Evidence::Content)).contains("left the committed content"));
    }

    #[test]
    fn no_record_is_not_called_a_person_s_work() {
        let mut out = Vec::new();
        text(&mut out, &[]).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("does not show that a person wrote them"),
            "{text}"
        );
    }

    #[test]
    fn a_failed_check_lists_each_problem() {
        let checked = [
            Checked {
                commit: "a".repeat(40),
                noted: true,
                problems: Vec::new(),
            },
            Checked {
                commit: "b".repeat(40),
                noted: true,
                problems: vec!["the note was edited\u{1b}[2J".to_owned()],
            },
            Checked {
                commit: "c".repeat(40),
                noted: false,
                problems: Vec::new(),
            },
        ];
        let mut out = Vec::new();
        verify_text(&mut out, &checked).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("✔  aaaaaaaaaaaa note matches"), "{text}");
        assert!(
            text.contains("✗ bbbbbbbbbbbb note does not match"),
            "{text}"
        );
        assert!(
            !text.contains('\u{1b}'),
            "terminal control characters are removed"
        );
        assert!(text.contains("cccccccccccc has no note"));
    }
}
