//! Files `curl` and `wget` send: each becomes an `fs.read`.
//!
//! `curl -F 'f=@FILE'` uploads `FILE` and `-F 'f=<FILE'` sends its contents as a
//! field; `-T FILE` (`--upload-file`) uploads it; `-d @FILE` and the other data
//! options, and `--data-urlencode name@FILE`, send it as the request body; `-K
//! FILE` (`--config`) reads more options from it. `wget --post-file=FILE` and
//! `--body-file=FILE` send it, and `-i FILE` reads the URLs to fetch from it.
//! `--form-string` sends its value as text, never a file. The generic argument
//! scan sees none of these when the file has a plain name or follows `name=`.

use super::{ClassifyError, ShellContext, Sink};

/// What an option's value holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Value {
    /// `name=@file;type=…` or `name=<file`.
    Form,
    /// A file name.
    File,
    /// `@file`, or data.
    Data,
    /// `@file` or `name@file`, or data.
    Urlencode,
}

/// curl options that carry a file (short spelling or `""`, long spelling).
const CURL: &[(&str, &str, Value)] = &[
    ("F", "--form", Value::Form),
    ("T", "--upload-file", Value::File),
    ("K", "--config", Value::File),
    ("d", "--data", Value::Data),
    ("", "--data-binary", Value::Data),
    ("", "--data-ascii", Value::Data),
    ("", "--json", Value::Data),
    ("", "--data-urlencode", Value::Urlencode),
];

/// curl short options that take a value: the rest of the word, or the next word.
const CURL_VALUED: &str = "AbcCdDeEFHKmoPQrtTuUwxXyYz";

const WGET: &[(&str, &str, Value)] = &[
    ("", "--post-file", Value::File),
    ("", "--body-file", Value::File),
    ("i", "--input-file", Value::File),
];

/// wget short options that take a value.
const WGET_VALUED: &str = "aABDeiIlOoPQTtUwX";

pub(super) fn classify(
    argv: &[String],
    program: &str,
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
) -> Result<(), ClassifyError> {
    let (table, valued) = match program {
        "curl" => (CURL, CURL_VALUED),
        "wget" => (WGET, WGET_VALUED),
        _ => return Ok(()),
    };
    let mut i = 1;
    while let Some(arg) = argv.get(i) {
        i += 1;
        if arg == "--" {
            break;
        }
        let found = if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(n, v)| (n, Some(v)));
            table
                .iter()
                .find(|(_, l, _)| l.strip_prefix("--") == Some(name))
                .map(|&(_, _, kind)| (kind, attached))
        } else if let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) {
            short(cluster, table, valued)
        } else {
            None
        };
        let Some((kind, attached)) = found else {
            continue;
        };
        let value = if let Some(value) = attached {
            value
        } else {
            let Some(next) = argv.get(i) else { break };
            i += 1;
            next
        };
        for file in files(kind, value) {
            sink.read(ctx, file)?;
        }
    }
    Ok(())
}

/// The file option in a cluster of short options (`-sF x`, `-Fx`), with its
/// attached value; `None` when the cluster names none or a valued option comes first.
fn short<'a>(
    cluster: &'a str,
    table: &[(&str, &str, Value)],
    valued: &str,
) -> Option<(Value, Option<&'a str>)> {
    for (pos, c) in cluster.char_indices() {
        if !valued.contains(c) {
            continue;
        }
        let rest = &cluster[pos + c.len_utf8()..];
        let kind = table
            .iter()
            .find(|(s, _, _)| s.len() == 1 && s.starts_with(c))?
            .2;
        return Some((kind, Some(rest).filter(|r| !r.is_empty())));
    }
    None
}

/// The files an option's value names; `-` is standard input.
fn files(kind: Value, value: &str) -> Vec<&str> {
    let named: Vec<&str> = match kind {
        Value::File => vec![value],
        Value::Data => value.strip_prefix('@').into_iter().collect(),
        Value::Urlencode => {
            let at = value.find('@').filter(|&at| !value[..at].contains('='));
            at.map(|at| &value[at + 1..]).into_iter().collect()
        }
        Value::Form => form_files(value),
    };
    named
        .into_iter()
        .filter(|f| !f.is_empty() && *f != "-" && *f != ".")
        .collect()
}

/// `name=@file;type=…`, `name=<file`, `name=@"file;x"`: the file of a form
/// field, and each part of a comma-separated list, as curl splits them.
fn form_files(value: &str) -> Vec<&str> {
    let Some((_, content)) = value.split_once('=') else {
        return Vec::new();
    };
    let Some(file) = content.strip_prefix(['@', '<']) else {
        return Vec::new();
    };
    let file = match file.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or(quoted),
        None => file.split(';').next().unwrap_or(file),
    };
    let mut files = vec![file];
    if file.contains(',') {
        files.extend(file.split(','));
    }
    files
}

#[cfg(test)]
mod tests {
    use super::{CURL, CURL_VALUED, Value, files, short};

    #[test]
    fn form_and_data_values_name_their_files() {
        assert_eq!(files(Value::Form, "f=@~/.ssh/id_rsa"), ["~/.ssh/id_rsa"]);
        assert_eq!(files(Value::Form, "f=@id_rsa;type=text/plain"), ["id_rsa"]);
        assert_eq!(files(Value::Form, "f=<.env"), [".env"]);
        assert_eq!(files(Value::Form, "f=@\"a;b\";type=x"), ["a;b"]);
        assert_eq!(files(Value::Form, "f=@a,b"), ["a,b", "a", "b"]);
        assert!(files(Value::Form, "f=text").is_empty());
        assert!(files(Value::Form, "f=@-").is_empty());
        assert_eq!(files(Value::Data, "@body.json"), ["body.json"]);
        assert!(files(Value::Data, "a=1").is_empty());
        assert_eq!(files(Value::Urlencode, "key@.env"), [".env"]);
        assert_eq!(files(Value::Urlencode, "@.env"), [".env"]);
        assert!(files(Value::Urlencode, "q=a@b.com").is_empty());
    }

    #[test]
    fn short_clusters_find_the_file_option() {
        let found = |c| short(c, CURL, CURL_VALUED).map(|(k, v)| (k == Value::Form, v));
        assert_eq!(found("sF"), Some((true, None)));
        assert_eq!(found("Ff=@x"), Some((true, Some("f=@x"))));
        assert_eq!(found("sSL"), None);
        // `-o` takes the rest of the word as its value
        assert_eq!(found("oF"), None);
    }
}
