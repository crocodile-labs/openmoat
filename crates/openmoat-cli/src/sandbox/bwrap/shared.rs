//! Placeholders two sessions in one project share (ADR-090).
//!
//! A session creates a placeholder only where nothing stands, so a second
//! `openmoat run` started in the same project while the first runs finds the
//! first one's placeholder and covers it with a mount of its own, which rests
//! on that folder or file. Removing it when the first session ends would take
//! the second one's cover away (an emptied `.claude/hooks` removed under a
//! read-only mount detaches the mount), and its agent could then create the
//! folder and plant a hook. So each session holds a lock on its project, shared,
//! from before it looks at the project until it ends, and records there what it
//! created; the placeholders are removed only by a session that can take the
//! lock alone, which is the last one, and then all of the recorded ones are.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read as _, Seek as _, Write as _};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};

use super::Placeholder;

/// The folder under the state directory that holds one lock file per project.
const DIR: &str = "run-projects";

/// A session's shared hold on its project's placeholders.
#[derive(Debug)]
pub struct Shared {
    file: File,
}

impl Shared {
    /// Take the project `project`'s lock in the state directory `state`,
    /// shared, waiting while a session that ends removes its placeholders.
    pub fn take(state: &Path, project: &str) -> Result<Self> {
        let dir = state.join(DIR);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut name = String::new();
        for byte in Sha256::digest(project.as_bytes()) {
            let _ = write!(name, "{byte:02x}");
        }
        let path = dir.join(name);
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        file.lock_shared()
            .with_context(|| format!("locking {}", path.display()))?;
        Ok(Self { file })
    }

    /// Record `placeholder`, which this session created, for whichever session
    /// ends last to remove.
    pub fn record(&mut self, placeholder: &Placeholder) -> Result<()> {
        if placeholder.path.contains(['\n', '\t']) {
            bail!(
                "{:?}: a placeholder path cannot hold a tab or a newline",
                placeholder.path
            );
        }
        let kind = if placeholder.dir { "d" } else { "f" };
        let line = format!("{kind}\t{}\t{}\n", placeholder.contents, placeholder.path);
        self.file.write_all(line.as_bytes())?;
        Ok(())
    }

    /// End this session's hold. Where no other session holds the project, give
    /// `remove` every recorded placeholder, under the lock alone, and forget
    /// them; otherwise leave them to the last session.
    pub fn finish(self, remove: impl Fn(&Placeholder)) {
        let Self { mut file } = self;
        let _ = file.unlock();
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock | TryLockError::Error(_)) => return,
        }
        let mut text = String::new();
        if file
            .rewind()
            .and_then(|()| file.read_to_string(&mut text))
            .is_ok()
        {
            // innermost first: the reverse of the order they were made in
            for placeholder in text.lines().rev().filter_map(parse) {
                remove(&placeholder);
            }
        }
        let _ = file.set_len(0);
        let _ = file.unlock();
    }
}

/// A line [`Shared::record`] wrote.
fn parse(line: &str) -> Option<Placeholder> {
    let mut parts = line.splitn(3, '\t');
    let dir = match parts.next()? {
        "d" => true,
        "f" => false,
        _ => return None,
    };
    let contents = match parts.next()? {
        "{}" => "{}",
        "" => "",
        _ => return None,
    };
    let path = parts.next()?.to_owned();
    Some(Placeholder {
        path,
        dir,
        contents,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    fn folder(path: &str) -> Placeholder {
        Placeholder {
            path: path.to_owned(),
            dir: true,
            contents: "",
        }
    }

    /// Two sessions in one project: the first to end removes nothing while
    /// the second still runs, and the second removes what both made.
    #[test]
    fn only_the_last_session_in_a_project_removes_the_placeholders() {
        let state = tempfile::tempdir().unwrap();
        let removed = RefCell::new(Vec::new());
        let remove = |p: &Placeholder| removed.borrow_mut().push(p.path.clone());
        let mut first = Shared::take(state.path(), "/work/p").unwrap();
        first.record(&folder("/work/p/.claude/hooks")).unwrap();
        let json = Placeholder {
            path: "/work/p/.gemini/settings.json".into(),
            dir: false,
            contents: "{}",
        };
        first.record(&json).unwrap();
        let second = Shared::take(state.path(), "/work/p").unwrap();
        // another project's session does not hold this one
        let elsewhere = Shared::take(state.path(), "/work/q").unwrap();
        first.finish(remove);
        assert!(removed.borrow().is_empty(), "the second session still runs");
        second.finish(remove);
        assert_eq!(
            *removed.borrow(),
            ["/work/p/.gemini/settings.json", "/work/p/.claude/hooks"]
        );
        // recorded once, removed once
        let again = Shared::take(state.path(), "/work/p").unwrap();
        again.finish(remove);
        assert_eq!(removed.borrow().len(), 2);
        elsewhere.finish(remove);
        assert_eq!(removed.borrow().len(), 2);
    }

    #[test]
    fn a_session_alone_removes_its_placeholders_and_odd_lines_are_skipped() {
        let state = tempfile::tempdir().unwrap();
        let removed = RefCell::new(Vec::new());
        let mut only = Shared::take(state.path(), "/w").unwrap();
        only.record(&folder("/w/.github/hooks")).unwrap();
        assert!(only.record(&folder("/w/a\nb")).is_err());
        only.file.write_all(b"x\tjunk\t/w/other\n").unwrap();
        only.finish(|p| removed.borrow_mut().push((p.path.clone(), p.dir)));
        assert_eq!(*removed.borrow(), [("/w/.github/hooks".to_owned(), true)]);
    }
}
