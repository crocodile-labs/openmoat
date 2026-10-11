//! Database shells (`sqlite3`, `duckdb`) open the database file they are given
//! read-write and create it when it is missing, so `sqlite3 FILE 'delete …'`
//! writes `FILE`. Their SQL and dot-commands open, attach and write more files
//! (`attach '…'`, `.open`, `.output`, `.backup`, `vacuum into '…'`), so every
//! word of that text that looks like a path is a write too, whether it comes as
//! an argument, a `-cmd` value or stdin the line shows. Only `-readonly` opens
//! the database, and what it attaches, read-only; those files are then reads.
//! A dot-command such as `.shell` runs programs either way, which is why no
//! default rule allows these tools.

use super::{ClassifyError, ShellContext, Sink};
use crate::paths;

const DATABASE_SHELLS: &[&str] = &["sqlite3", "sqlite", "duckdb"];

/// Options whose value is the next word and is SQL or dot-commands.
const SQL_VALUED: &[&str] = &["cmd", "c", "s"];

/// Options whose value is the next word and is neither SQL nor a database.
const OTHER_VALUED: &[&str] = &[
    "separator",
    "newline",
    "nullvalue",
    "vfs",
    "maxsize",
    "mmap",
    "escape",
    "pagecache",
    "lookaside",
    "heap",
];

/// Database names that are not files.
const NOT_FILES: &[&str] = &["", ":memory:"];

/// Classify a database shell's arguments and the stdin text the line shows.
/// Returns the argv indices it took care of; empty for any other program.
pub(super) fn classify<'a>(
    argv: &[String],
    program: &str,
    stdin: impl Iterator<Item = &'a str>,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<Vec<usize>, ClassifyError> {
    if !DATABASE_SHELLS.contains(&program) {
        return Ok(Vec::new());
    }
    let read_only = argv[1..].iter().any(|a| option_name(a) == Some("readonly"));
    let open = |path: &str, sink: &mut Sink| {
        if read_only {
            sink.read(ctx, path)
        } else {
            sink.write(ctx, path)
        }
    };
    let mut database_seen = false;
    let mut i = 1;
    while let Some(arg) = argv.get(i) {
        i += 1;
        match option_name(arg) {
            Some(name) if SQL_VALUED.contains(&name) || OTHER_VALUED.contains(&name) => {
                if let Some(value) = argv.get(i).filter(|_| SQL_VALUED.contains(&name)) {
                    for path in sql_paths(value) {
                        open(path, sink)?;
                    }
                }
                i += 1;
            }
            Some("init") => {
                if let Some(file) = argv.get(i) {
                    sink.read(ctx, file)?;
                }
                i += 1;
            }
            Some(_) => {}
            None if !database_seen => {
                database_seen = true;
                let file = file_of(arg);
                if !NOT_FILES.contains(&file) {
                    open(file, sink)?;
                }
            }
            None => {
                for path in sql_paths(arg) {
                    open(path, sink)?;
                }
            }
        }
    }
    for text in stdin {
        for path in sql_paths(text) {
            open(path, sink)?;
        }
    }
    Ok((1..argv.len()).collect())
}

/// `name` of `-name` or `--name`.
fn option_name(arg: &str) -> Option<&str> {
    let name = arg.strip_prefix('-')?;
    Some(name.strip_prefix('-').unwrap_or(name)).filter(|n| !n.is_empty())
}

/// The file of a database operand: a `file:` URI loses its scheme and query.
fn file_of(arg: &str) -> &str {
    arg.strip_prefix("file:")
        .map_or(arg, |uri| uri.split('?').next().unwrap_or(uri))
}

/// Words of SQL or dot-command text that look like paths. A lone `/` is
/// division, not the root. A dot-command's own name (`.output`) cannot be told
/// from a hidden file (`.env`), so it counts as one: a file in the directory the
/// command runs in.
fn sql_paths(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| c.is_whitespace() || "'\";,()=".contains(c))
        .map(file_of)
        .filter(|word| *word != "/" && paths::looks_like_path(word))
}

#[cfg(test)]
mod tests {
    use super::{file_of, option_name, sql_paths};

    #[test]
    fn options_take_one_or_two_dashes() {
        assert_eq!(option_name("-readonly"), Some("readonly"));
        assert_eq!(option_name("--readonly"), Some("readonly"));
        assert_eq!(option_name("audit.db"), None);
        assert_eq!(option_name("-"), None);
    }

    #[test]
    fn uris_name_their_file() {
        assert_eq!(file_of("file:~/.moat/audit.db?mode=ro"), "~/.moat/audit.db");
        assert_eq!(file_of("audit.db"), "audit.db");
    }

    #[test]
    fn sql_names_the_files_it_opens() {
        let sql = "attach '~/.moat/audit.db' as a; select 6 / 2; .output /tmp/out";
        assert_eq!(
            sql_paths(sql).collect::<Vec<_>>(),
            ["~/.moat/audit.db", ".output", "/tmp/out"]
        );
        assert_eq!(sql_paths("select count(*) from events").count(), 0);
    }
}
