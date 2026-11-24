//! One cmdlet call as the POSIX command that does the same (`cmdlets.rs`).

use super::super::cmdlets::{Arg, Cmdlet, Does};
use super::super::lex::{Part, PsWord};
use super::{posix, quote};
use crate::action::AtomicAction;
use crate::shell::{ClassifyError, ShellContext, Sink};

/// A cmdlet's operands, bound to its parameters: each parameter with its
/// value, if it takes one. An operand with no parameter left binds to `""`.
struct Bound {
    named: Vec<(&'static str, Option<PsWord>)>,
}

impl Bound {
    fn new(cmdlet: &Cmdlet, args: &[&PsWord]) -> Self {
        let mut named = Vec::new();
        let mut positional = Vec::new();
        let mut i = 0;
        while let Some(word) = args.get(i) {
            i += 1;
            match word.literal().and_then(|l| cmdlet.parameter(&l)) {
                Some((name, Arg::Value, Some(value))) => named.push((name, Some(literal(value)))),
                Some((name, Arg::Value, None)) => {
                    named.push((name, args.get(i).map(|w| (*w).clone())));
                    i += 1;
                }
                Some((name, Arg::Switch, _)) => named.push((name, None)),
                None => positional.push((*word).clone()),
            }
        }
        let last = cmdlet.positional.len().saturating_sub(1);
        for (n, word) in positional.into_iter().enumerate() {
            let slot = cmdlet.positional.get(n.min(last)).copied().unwrap_or("");
            named.push((slot, Some(word)));
        }
        Self { named }
    }

    fn has(&self, name: &str) -> bool {
        self.named.iter().any(|(n, _)| *n == name)
    }

    fn values(&self, names: &[&str]) -> Vec<&PsWord> {
        self.named
            .iter()
            .filter(|(n, _)| names.contains(n))
            .filter_map(|(_, w)| w.as_ref())
            .collect()
    }

    fn value(&self, name: &str) -> Option<String> {
        self.values(&[name])
            .first()
            .and_then(|w| w.literal())
            .map(|v| v.to_ascii_lowercase())
    }

    fn posix(&self, names: &[&str]) -> Vec<String> {
        self.values(names).into_iter().map(posix).collect()
    }
}

fn literal(text: String) -> PsWord {
    PsWord {
        parts: vec![Part::Lit(text)],
        ..PsWord::default()
    }
}

const PATH: &[&str] = &["path", "literalpath"];

/// `env:`, `env:NAME`: PowerShell's environment drive, as `env` or `printenv NAME`.
fn env_drive(paths: &[&PsWord]) -> Option<String> {
    let lit = paths.first()?.literal()?;
    let (drive, name) = lit.split_once(':')?;
    if !drive.eq_ignore_ascii_case("env") {
        return None;
    }
    let name = name.trim_start_matches(['\\', '/']);
    Some(if name.is_empty() || name == "*" {
        "env".to_owned()
    } else {
        format!("printenv {}", quote(&name.to_ascii_uppercase()))
    })
}

/// The POSIX command for `cmdlet` called as `program` with `args`; `None`
/// when it runs nothing the policy names (it may have added atoms itself).
pub(super) fn cmdlet_line(
    cmdlet: &Cmdlet,
    program: &str,
    args: &[&PsWord],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<Option<String>, ClassifyError> {
    let b = Bound::new(cmdlet, args);
    let words = |head: &[&str], names: &[&str]| -> String {
        head.iter()
            .map(|h| (*h).to_owned())
            .chain(b.posix(names))
            .collect::<Vec<_>>()
            .join(" ")
    };
    if matches!(cmdlet.does, Does::Read | Does::List | Does::Stat)
        && let Some(line) = env_drive(&b.values(PATH))
    {
        return Ok(Some(line));
    }
    let recurse = b.has("recurse");
    let line = match cmdlet.does {
        Does::Read => words(&["cat"], PATH),
        Does::Write { append } => {
            let append = append || b.has("append");
            let tee = words(
                if append { &["tee", "-a"] } else { &["tee"] },
                &["path", "literalpath", "filepath"],
            );
            match b.posix(&["value", "inputobject"]).as_slice() {
                [] => tee,
                values => format!("echo {} | {tee}", values.join(" ")),
            }
        }
        Does::Remove => {
            let flags = match (recurse, b.has("force")) {
                (true, true) => "-rf",
                (true, false) => "-r",
                (false, true) => "-f",
                (false, false) => "--",
            };
            words(&["rm", flags], PATH)
        }
        Does::Copy => words(
            if recurse { &["cp", "-r"] } else { &["cp"] },
            &["path", "literalpath", "destination"],
        ),
        Does::Move => words(&["mv"], &["path", "literalpath", "destination"]),
        Does::Rename => words(&["mv"], &["path", "literalpath", "newname"]),
        Does::List => words(if recurse { &["ls", "-R"] } else { &["ls"] }, PATH),
        Does::Stat => words(&["ls", "-d"], PATH),
        Does::Cd => words(&["cd"], PATH),
        Does::NewItem => new_item(&b, program),
        Does::Fetch => fetch(&b),
        Does::Transfer => words(&["curl", "-o"], &["destination", "source"]),
        Does::Print => words(&["echo"], &["inputobject", "object", ""]),
        Does::Search => words(&["grep", "-e"], &["pattern", "path", "literalpath"]),
        Does::Hash => words(&["sha256sum"], PATH),
        Does::Expand => {
            let dest = b.posix(&["destinationpath"]).join(" ");
            let dest = if dest.is_empty() {
                String::new()
            } else {
                format!(" -d {dest}")
            };
            format!("{}{dest}", words(&["unzip", "-o"], PATH))
        }
        Does::Compress => words(&["zip", "-r"], &["destinationpath", "path", "literalpath"]),
        Does::Start => return Ok(start(&b)),
        Does::Evaluate => return Ok(evaluate(&b, ctx, sink, depth)),
        Does::ExecutionPolicy => {
            execution_policy(&b, sink)?;
            return Ok(None);
        }
        Does::Source => match b.values(&["name"]).first() {
            Some(w) if w.literal().is_some_and(|l| l.contains(['/', '\\', '.'])) => {
                format!(". {}", posix(w))
            }
            _ => return Ok(None),
        },
    };
    Ok(Some(line))
}

fn new_item(b: &Bound, program: &str) -> String {
    let kind = b.value("itemtype").unwrap_or_default();
    let mut paths = b.posix(&["path"]);
    if let Some(name) = b.posix(&["name"]).first() {
        paths = match paths.first() {
            Some(dir) => vec![format!("{dir}/{name}")],
            None => vec![name.clone()],
        };
    }
    let paths = paths.join(" ");
    let directory =
        kind.starts_with('d') || matches!(program.to_ascii_lowercase().as_str(), "mkdir" | "md");
    if directory {
        return format!("mkdir -p {paths}");
    }
    if matches!(kind.as_str(), "symboliclink" | "hardlink" | "junction") {
        let target = b.posix(&["target", "value"]).join(" ");
        return format!("ln -s {target} {paths}");
    }
    match b.posix(&["value"]).as_slice() {
        [] => format!("touch {paths}"),
        values => format!("echo {} | tee {paths}", values.join(" ")),
    }
}

fn fetch(b: &Bound) -> String {
    let mut out = vec!["curl".to_owned()];
    if let Some(method) = b.posix(&["method"]).first() {
        out.extend(["-X".to_owned(), method.clone()]);
    }
    for body in b.posix(&["body"]) {
        out.extend(["--data-binary".to_owned(), body]);
    }
    for file in b.posix(&["infile"]) {
        out.extend(["-T".to_owned(), file]);
    }
    for file in b.posix(&["outfile"]) {
        out.extend(["-o".to_owned(), file]);
    }
    out.extend(b.posix(&["uri"]));
    out.join(" ")
}

/// `Start-Process FILE -ArgumentList ARGS [-Verb RunAs]`: `[sudo] FILE ARGS`.
/// A single literal argument list is split at white space, as the process
/// gets it as one command line.
fn start(b: &Bound) -> Option<String> {
    let file = b.values(&["filepath"]).first().map(|w| posix(w))?;
    let mut out = Vec::new();
    if b.value("verb").as_deref() == Some("runas") {
        out.push("sudo".to_owned());
    }
    out.push(file);
    for arg in b.values(&["argumentlist"]) {
        match arg.literal() {
            Some(text) => out.extend(text.split_whitespace().map(super::literal)),
            None => out.push(posix(arg)),
        }
    }
    Some(out.join(" "))
}

/// `iex 'text'`: the text is read as PowerShell too (the line is already held
/// as opaque code); `… | iex` runs its input, as `… | sh` does.
fn evaluate(b: &Bound, ctx: &ShellContext<'_>, sink: &mut Sink, depth: u8) -> Option<String> {
    match b.values(&["command"]).first() {
        None => Some("sh".to_owned()),
        Some(word) => {
            if let Some(text) = word.literal()
                && let Err(e) = super::super::classify_into(&text, ctx, sink, depth + 1)
            {
                sink.skip(e);
            }
            None
        }
    }
}

/// `Set-ExecutionPolicy POLICY [-Scope SCOPE]`: `@execution-policy POLICY SCOPE`,
/// which `persistence` holds; `-Scope Process` lasts only as long as the process.
fn execution_policy(b: &Bound, sink: &mut Sink) -> Result<(), ClassifyError> {
    let scope = b
        .value("scope")
        .unwrap_or_else(|| "localmachine".to_owned());
    if scope == "process" {
        return Ok(());
    }
    let policy = b
        .value("executionpolicy")
        .unwrap_or_else(|| "unknown".to_owned());
    sink.push(AtomicAction::Shell {
        argv: vec!["@execution-policy".to_owned(), policy, scope],
    })
}
