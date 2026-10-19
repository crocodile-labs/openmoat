//! What `xargs` runs when the command line shows its input.
//!
//! `xargs cat <<< ~/.ssh/id_rsa` runs `cat ~/.ssh/id_rsa`: the words of a
//! here-string, a here-document or text piped from `echo`, `printf` or a bare
//! `cat <<EOF` are the arguments of the command xargs runs, like
//! `echo x | xargs cat`. Each command is built the way xargs builds it: the
//! words appended, with `-n`/`-L` one input item per command too, and with
//! `-I R` each input line in place of `R`. Input that the line does not show
//! (`xargs -a FILE`, `cat list | xargs`, `xargs < list`) is not modelled.

use super::super::SimpleCommand;
use super::super::piped::Piped;
use crate::shell::ClassifyError;

/// Most input items or lines turned into commands of their own.
const MAX_RUNS: usize = 256;

/// How xargs was asked to read and use its input.
#[derive(Default)]
struct Options {
    /// `-I R`, `-i[R]`, `--replace[=R]`, BSD `-J R`: each line replaces `R`.
    replace: Option<String>,
    /// `-0`/`--null` or `-d D`: items end at that character, not at blanks.
    delimiter: Option<char>,
    /// `-n`, `-L`, `-l`, `--max-args`, `--max-lines`: fewer items per command.
    batches: bool,
    /// `-a FILE`/`--arg-file`: the input is not stdin.
    from_file: bool,
}

/// The commands `xargs` (`argv`) runs with `inner` as its command, when its
/// stdin is text on the command line; empty when it is not.
pub(super) fn runs(
    cmd: &SimpleCommand,
    argv: &[String],
    inner: &[String],
) -> Result<Vec<Vec<String>>, ClassifyError> {
    let options = parse(argv, inner.len());
    if options.from_file || cmd.piped.iter().any(Piped::is_hidden) {
        return Ok(Vec::new());
    }
    let input: Vec<&str> = cmd
        .stdin_texts()
        .chain(cmd.piped.iter().filter_map(Piped::text))
        .collect();
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let input = input.join("\n");
    if let Some(replace) = &options.replace {
        let lines: Vec<&str> = input
            .lines()
            .map(str::trim_start)
            .filter(|l| !l.is_empty())
            .collect();
        if lines.len() > MAX_RUNS {
            return Err(ClassifyError::TooManyActions);
        }
        return Ok(lines
            .iter()
            .map(|line| {
                inner
                    .iter()
                    .map(|a| a.replace(replace.as_str(), line))
                    .collect()
            })
            .collect());
    }
    let items = items(&input, options.delimiter);
    let all = inner.iter().cloned().chain(items.iter().cloned()).collect();
    let mut runs = vec![all];
    if options.batches {
        if items.len() > MAX_RUNS {
            return Err(ClassifyError::TooManyActions);
        }
        runs.extend(items.iter().map(|item| {
            let mut run = inner.to_vec();
            run.push(item.clone());
            run
        }));
    }
    Ok(runs)
}

/// The options before the command, which starts `inner_len` words from the end.
fn parse(argv: &[String], inner_len: usize) -> Options {
    let mut options = Options::default();
    let end = argv.len().saturating_sub(inner_len);
    let mut words = argv.get(1..end).unwrap_or_default().iter();
    while let Some(arg) = words.next() {
        let mut value = |attached: &str| {
            if attached.is_empty() {
                words.next().cloned().unwrap_or_default()
            } else {
                attached.to_owned()
            }
        };
        if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = long.split_once('=').unwrap_or((long, ""));
            match name {
                "replace" => {
                    options.replace = Some(
                        Some(attached)
                            .filter(|a| !a.is_empty())
                            .unwrap_or("{}")
                            .to_owned(),
                    );
                }
                "null" => options.delimiter = Some('\0'),
                "delimiter" => options.delimiter = delimiter(&value(attached)),
                "max-args" | "max-lines" => options.batches = true,
                "arg-file" => options.from_file = true,
                _ => {}
            }
            continue;
        }
        let Some(cluster) = arg.strip_prefix('-') else {
            continue;
        };
        for (pos, c) in cluster.char_indices() {
            let rest = &cluster[pos + c.len_utf8()..];
            match c {
                '0' => options.delimiter = Some('\0'),
                'I' | 'J' => options.replace = Some(value(rest)),
                'i' => options.replace = Some(if rest.is_empty() { "{}" } else { rest }.to_owned()),
                'd' => options.delimiter = delimiter(&value(rest)),
                'n' | 'L' | 'l' => options.batches = true,
                'a' => options.from_file = true,
                _ => continue,
            }
            // every option but `-0` takes the rest of the word (or the next one)
            if c != '0' {
                break;
            }
        }
    }
    options
}

/// The character of `-d D`: GNU xargs reads `\n`, `\t` and `\0` as escapes.
fn delimiter(value: &str) -> Option<char> {
    match value {
        "\\n" => Some('\n'),
        "\\t" => Some('\t'),
        "\\0" => Some('\0'),
        _ => value.chars().next(),
    }
}

/// The input items: split at `delimiter`, or at blanks with xargs' quotes
/// taken off (`'a b'` is one item).
fn items(input: &str, delimiter: Option<char>) -> Vec<String> {
    if let Some(d) = delimiter {
        return input
            .split(d)
            .filter(|i| !i.is_empty())
            .map(str::to_owned)
            .collect();
    }
    let mut items = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '\'' | '"') => quote = Some(c),
            (None, '\\') => current.extend(chars.next()),
            (None, c) if c.is_whitespace() => {
                if !current.is_empty() {
                    items.push(std::mem::take(&mut current));
                }
            }
            (_, c) => current.push(c),
        }
    }
    if !current.is_empty() {
        items.push(current);
    }
    items
}

#[cfg(test)]
mod tests {
    use super::{items, parse};

    fn argv(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn options_are_read_as_xargs_reads_them() {
        let o = parse(&argv("xargs -I {} cp {} x"), 3);
        assert_eq!(o.replace.as_deref(), Some("{}"));
        let o = parse(&argv("xargs -I% cp % x"), 3);
        assert_eq!(o.replace.as_deref(), Some("%"));
        let o = parse(&argv("xargs -i cp {} x"), 3);
        assert_eq!(o.replace.as_deref(), Some("{}"));
        let o = parse(&argv("xargs --replace=@ cp @ x"), 3);
        assert_eq!(o.replace.as_deref(), Some("@"));
        let o = parse(&argv("xargs -0n1 sh -c"), 2);
        assert!(o.batches && o.delimiter == Some('\0'));
        assert!(parse(&argv("xargs -a list cat"), 1).from_file);
        let o = parse(&argv("xargs -t cat"), 1);
        assert!(o.replace.is_none() && !o.batches && !o.from_file);
    }

    #[test]
    fn items_split_at_blanks_outside_quotes() {
        assert_eq!(
            items("a 'b c'\n\"d\" e\\ f", None),
            ["a", "b c", "d", "e f"]
        );
        assert_eq!(items("a b\nc d\n", Some('\n')), ["a b", "c d"]);
    }
}
