//! Which plain arguments of a command name files.
//!
//! `paths::looks_like_path` only recognises words that are paths whatever the
//! program (`/x`, `./x`, `~/x`, `.env`). A relative word such as `s/id_rsa` or
//! `notes.txt` is a file too when the program reads or writes its operands,
//! and it has to become an `fs` atom: a symlink `s` → `~/.ssh` in the project
//! is only seen once the path is resolved (ADR-009). Being a path inside the
//! project costs nothing, since `project-fs` allows it.

use super::tables::{EDITORS, FILE_OPERANDS, NO_FILE_OPERANDS, WRITE_ALL_PATHS, WRITE_LAST_PATH};

/// The file `word` names as an argument of `program`, if any.
///
/// - Any program: a word containing `/` (`s/id_rsa`, `src/main.rs`), or the
///   value of `--opt=VALUE` / `NAME=VALUE` when it contains `/`.
/// - Programs whose operands are files ([`FILE_OPERANDS`] and the write
///   tables): every other operand, including plain names (`cat s`).
///
/// Words that are options (before `--`), URLs or remote specs (`host:dir`,
/// `user@host:dir`) are not files; nor is anything given to a program that
/// only prints its arguments ([`NO_FILE_OPERANDS`]).
pub(super) fn file_operand<'w>(
    word: &'w str,
    program: &str,
    options_ended: bool,
) -> Option<&'w str> {
    if word.is_empty() || NO_FILE_OPERANDS.contains(&program) {
        return None;
    }
    let value = value_of(word);
    if value.is_some() || (!options_ended && word.starts_with('-')) {
        return value.filter(|v| v.contains('/') && is_local(v));
    }
    let file_program = FILE_OPERANDS.contains(&program)
        || WRITE_ALL_PATHS.contains(&program)
        || WRITE_LAST_PATH.contains(&program);
    ((file_program || word.contains('/')) && is_local(word)).then_some(word)
}

/// Whether `program` saves back the `file` it opens: an editor ([`EDITORS`])
/// given a file. A folder it browses (`code .`, `vim ~`, a word ending in `/`)
/// is no file it writes.
pub(super) fn editor_saves(program: &str, file: &str) -> bool {
    EDITORS.contains(&program) && !matches!(file, "." | ".." | "~" | "/") && !file.ends_with('/')
}

/// `VALUE` of `--opt=VALUE` or `NAME=VALUE`, when the `=` comes before any `/`.
fn value_of(word: &str) -> Option<&str> {
    let (key, value) = word.split_once('=')?;
    (!key.is_empty() && !key.contains('/')).then_some(value)
}

/// Not a URL and not a remote spec: a `:` before the first `/` names a host
/// (`scp key host:/tmp`, `rsync -a src user@host:dst`).
fn is_local(word: &str) -> bool {
    let head = word.split('/').next().unwrap_or(word);
    !word.contains("://") && !head.contains(':') && !word.is_empty()
}

#[cfg(test)]
mod tests {
    use super::file_operand;

    #[test]
    fn slash_words_are_files_for_any_program() {
        assert_eq!(file_operand("s/id_rsa", "base64", false), Some("s/id_rsa"));
        assert_eq!(file_operand("--in=s/k", "openssl", false), Some("s/k"));
        assert_eq!(file_operand("-", "cat", true), Some("-"));
        for (word, program) in [
            ("status", "git"),
            ("left-pad", "npm"),
            ("--short", "git"),
            ("-n", "head"),
            ("https://x.example/a", "curl"),
            ("host:/tmp", "scp"),
            ("me@host:dst/x", "rsync"),
            ("s/id_rsa", "echo"),
            ("CC=clang", "make"),
            ("--color=auto", "ls"),
        ] {
            assert_eq!(file_operand(word, program, false), None, "{program} {word}");
        }
    }

    #[test]
    fn plain_operands_of_file_programs_are_files() {
        for program in [
            "cat", "head", "tail", "less", "grep", "rg", "cp", "mv", "rm", "tee", "ls",
        ] {
            assert_eq!(file_operand("s", program, false), Some("s"), "{program}");
        }
        assert_eq!(file_operand("--", "cat", false), None);
    }

    #[test]
    fn editors_save_the_files_they_open_not_folders() {
        use super::editor_saves;
        for (program, file) in [("vim", "~/.zshrc"), ("nano", "x"), ("code", "src/a.rs")] {
            assert!(editor_saves(program, file), "{program} {file}");
        }
        for (program, file) in [
            ("code", "."),
            ("vim", "~"),
            ("nvim", "/"),
            ("emacs", "src/"),
            ("cat", "x"),
            ("open", "x"),
        ] {
            assert!(!editor_saves(program, file), "{program} {file}");
        }
    }
}
