//! `moat edit`: change the policy in the person's editor. The draft is linted
//! and its diff shown, and nothing is written or re-pinned until the person agrees.

use std::fs;
use std::io::{self, BufRead as _, Write as _};
use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, bail, ensure};
use similar::{Algorithm, udiff::unified_diff};

use crate::context::read_policy;
use crate::exit::Code;
use crate::home::{Home, write_private};
use crate::integrity::{self, HookPins};
use crate::render::Deferred;

/// The editor when neither `VISUAL` nor `EDITOR` is set.
const FALLBACK_EDITOR: &str = if cfg!(windows) { "notepad" } else { "vi" };

pub fn run() -> Result<Code> {
    if !crate::terminal::interactive() {
        bail!("`moat edit` must be run by a person in a terminal, not from a hook or script");
    }
    let home = Home::locate()?;
    let path = home.policy_path();
    if !path.is_file() {
        bail!("no policy at {}; run `moat init`", path.display());
    }
    // Applying re-pins every pinned file, so editing over drift would accept it unseen.
    integrity::refuse_drift(&home, "edit the policy")?;
    let before = read_policy(&path)?;
    // In the state directory, which `kernel-self` keeps agents from writing, so
    // the draft cannot be changed behind the person's back while it is open.
    let draft = home.root().join("policy.edit.yaml");
    write_private(&draft, before.as_bytes())?;
    let result = edit(&home, &draft, &before);
    let _ = fs::remove_file(&draft);
    result
}

fn edit(home: &Home, draft: &Path, before: &str) -> Result<Code> {
    let mut out = Deferred::default();
    loop {
        open_editor(draft)?;
        let after = read_policy(draft)?;
        if after == before {
            writeln!(out, "no changes; the policy was not touched")?;
            break;
        }
        let policy = match home.load_policy_at(draft) {
            Ok(policy) => policy,
            Err(error) => {
                writeln!(out, "the edited policy does not lint:\n  {error:#}")?;
                if confirm(&mut out, "Edit again? [y/N] ")? {
                    continue;
                }
                bail!("the policy was not changed");
            }
        };
        for warning in openmoat_core::lint::warnings(&policy) {
            writeln!(out, "warning: {warning}")?;
        }
        let diff = unified_diff(
            Algorithm::Myers,
            before,
            &after,
            3,
            Some(("policy.yaml (installed)", "policy.yaml (edited)")),
        );
        write!(out, "{diff}")?;
        if !confirm(&mut out, "Apply? [y/N] ")? {
            writeln!(out, "the policy was not changed")?;
            break;
        }
        apply(home, before, &after, &mut out)?;
        break;
    }
    out.finish()?;
    Ok(Code::Ok)
}

/// Keep the previous policy next to it, write the new one and re-pin.
pub(super) fn apply(home: &Home, before: &str, after: &str, out: &mut Deferred) -> Result<()> {
    // A pinned file changed while the editor was open would be accepted unseen.
    integrity::refuse_drift(home, "apply the edit")?;
    let path = home.policy_path();
    let backup = home.root().join("policy.yaml.bak");
    write_private(&backup, before.as_bytes())?;
    write_private(&path, after.as_bytes())?;
    let binary = crate::install::hook_binary()?;
    let lock = integrity::repin(home, &binary, HookPins::Keep)?;
    writeln!(out, "✔ {} updated", path.display())?;
    writeln!(out, "✔ lock re-pinned ({} files)", lock.entries.len())?;
    writeln!(
        out,
        "  undo: the previous policy is in {}; copy it back and run `moat doctor --accept`",
        backup.display()
    )?;
    Ok(())
}

/// Run `$VISUAL`, `$EDITOR` or the fallback on `draft` and wait for it. The
/// variable may carry arguments (`code --wait`), split on whitespace.
fn open_editor(draft: &Path) -> Result<()> {
    let editor = ["VISUAL", "EDITOR"]
        .into_iter()
        .find_map(|var| std::env::var(var).ok().filter(|v| !v.trim().is_empty()))
        .unwrap_or_else(|| FALLBACK_EDITOR.to_owned());
    let mut words = editor.split_whitespace();
    let program = words.next().context("the editor command is empty")?;
    let status = Command::new(program)
        .args(words)
        .arg(draft)
        .status()
        .with_context(|| format!("starting the editor `{editor}`; set $VISUAL or $EDITOR"))?;
    ensure!(
        status.success(),
        "the editor `{editor}` exited with {status}; the policy was not changed"
    );
    Ok(())
}

/// Ask a yes/no question; anything but `y` or `yes`, end of input included, is no.
pub(super) fn confirm(out: &mut Deferred, question: &str) -> Result<bool> {
    Ok(matches!(answer(out, question)?.as_str(), "y" | "yes"))
}

/// Ask `question` and return the answer, trimmed and in lower case; empty at
/// the end of input.
pub(super) fn answer(out: &mut Deferred, question: &str) -> Result<String> {
    write!(out, "{question}")?;
    out.flush()?;
    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        .context("reading the answer")?;
    Ok(answer.trim().to_ascii_lowercase())
}
