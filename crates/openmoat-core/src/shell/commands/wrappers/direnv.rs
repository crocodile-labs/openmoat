//! `direnv exec DIR COMMAND [ARGS…]`, as direnv's `cmd_exec.go` reads it: the
//! word after `exec` is the directory as written (direnv takes no option
//! there, so `--` or `-x` would be the directory), and the command runs with
//! the environment of the first `.envrc` (or `.env`) found from it upwards.
//! When that word is a file instead, the file itself is the command and its
//! directory the one searched.
//!
//! Both readings are classified unless the word is plainly a directory, so a
//! command is never hidden behind a word taken for the directory
//! (`direnv exec /bin/rm -rf ~`). The directory is a read. What `.envrc` runs
//! is not classified: direnv runs only one a person approved with
//! `direnv allow`, and writing one is a `secrets-paths` deny (docs/LIMITS.md).

/// The directory (or file) word of `direnv exec`.
pub(super) fn dir(argv: &[String]) -> Option<&str> {
    exec(argv).then(|| argv.get(2).map(String::as_str))?
}

/// The command `direnv exec DIR COMMAND…` runs.
pub(super) fn command(argv: &[String]) -> Option<&[String]> {
    argv.get(3..).filter(|rest| exec(argv) && !rest.is_empty())
}

/// The command when the word after `exec` is a file (`direnv exec ./run.sh
/// args`), unless it is plainly a directory.
pub(super) fn file_command(argv: &[String]) -> Option<&[String]> {
    let word = dir(argv)?;
    let plainly_dir = matches!(word, "." | ".." | "~" | "/")
        || word.ends_with(['/', '\\'])
        || word.ends_with("/.")
        || word.ends_with("/..");
    (!plainly_dir).then(|| &argv[2..])
}

fn exec(argv: &[String]) -> bool {
    argv.get(1).is_some_and(|w| w == "exec")
}
