//! Code that runs what nobody reviewing the change can read: a script fetched
//! at run time, text decoded and run, a Python start-up file, a Dockerfile
//! `ADD` from a URL, a long encoded blob. Prose files are not read: a README
//! that tells people to `curl … | sh` runs nothing by itself.

use super::files::{File, Kind};
use super::{Change, Hit, Level, shown};
use super::{DECODE_EXEC, DOCKER_REMOTE_ADD, ENCODED_BLOB, PIPE_TO_SHELL, PYTHON_STARTUP};

/// Programs that download.
const FETCHERS: &[&str] = &[
    "curl",
    "wget",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
];
/// Programs that run the text they are given as code.
const RUNNERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "php",
    "iex",
    "invoke-expression",
    "source",
    "eval",
    "pwsh",
    "powershell",
];
/// A shell decoding text: `base64 -d`, `xxd -r`, `openssl enc -d`.
const SHELL_DECODERS: &[&str] = &[
    "base64 -d",
    "base64 --decode",
    "base64 -D",
    "xxd -r",
    "openssl enc -d",
    "openssl base64 -d",
    "frombase64string(",
];
/// Calls that run a string as code.
const EVALS: &[&str] = &[
    "exec(",
    "eval(",
    "new function(",
    "iex(",
    "invoke-expression",
];
/// Calls that decode or unpack text, in the languages above. `Buffer.from`
/// counts only with a `base64` or `hex` encoding on the line.
const DECODERS: &[&str] = &[
    "b64decode(",
    "a85decode(",
    "codecs.decode(",
    "bytes.fromhex(",
    "zlib.decompress(",
    "marshal.loads(",
    "atob(",
    "base64_decode(",
    "gzinflate(",
    "str_rot13(",
    "hex2bin(",
    "decode64(",
    "frombase64string(",
];
/// The shortest base64 run reported as a blob.
const BLOB_LEN: usize = 400;

pub(super) fn scan(file: &File, change: &Change<'_>, hits: &mut Vec<Hit>) {
    let mut startup = false;
    let mut blob = false;
    // Tests and fixtures hold attack samples as data; CI still runs tests, so
    // what would be denied elsewhere is held for review there.
    let (strict, sample) = if file.test {
        (
            Level::Review,
            " (in a test or fixture: check it is a sample and nothing runs it)",
        )
    } else {
        (Level::Deny, "")
    };
    for (line, text) in change.added {
        let line = *line;
        let lower = text.to_ascii_lowercase();
        if decode_exec(&lower) {
            hits.push(Hit::new(
                DECODE_EXEC,
                strict,
                line,
                format!(
                    "decodes text and runs it as code: what runs cannot be read in the change, \
                     as in malware that hides its payload{sample}"
                ),
            ));
        } else if let Some(fetcher) = pipe_to_shell(&lower) {
            hits.push(Hit::new(
                PIPE_TO_SHELL,
                Level::Review,
                line,
                format!(
                    "runs a script that `{fetcher}` downloads when it runs: whoever controls the \
                     address decides what runs, and the change does not show it"
                ),
            ));
        }
        if file.is(Kind::Pth) && !startup && is_import(text) {
            startup = true;
            hits.push(Hit::new(
                PYTHON_STARTUP,
                strict,
                line,
                format!(
                    "adds a .pth file with an `import` line: Python runs it on every start once \
                     the file is in a site directory, before any of the program's code{sample}"
                ),
            ));
        }
        if file.is(Kind::Dockerfile) && remote_add(&lower) {
            hits.push(Hit::new(
                DOCKER_REMOTE_ADD,
                Level::Review,
                line,
                format!(
                    "adds a file from a URL to the image without `--checksum`: the build takes \
                     whatever the address serves that day (`{}`)",
                    shown(text)
                ),
            ));
        }
        if file.is(Kind::Code)
            && !file.test
            && !blob
            && let Some(len) = base64_run(text)
        {
            blob = true;
            hits.push(Hit::new(
                ENCODED_BLOB,
                Level::Review,
                line,
                format!(
                    "adds {len} characters of base64 to source code: what it decodes to cannot be \
                     read in the change"
                ),
            ));
        }
    }
}

/// The words of `segment` after `sudo`, `env` and options.
fn command_word(segment: &str) -> &str {
    segment
        .split_whitespace()
        .find(|w| !matches!(*w, "sudo" | "env" | "-e" | "-E" | "exec") && !w.starts_with('-'))
        .unwrap_or_default()
        // `"… | sh"` in a JSON string, `$(… | bash)`, `` `… | sh` ``
        .trim_matches(['(', ')', '"', '\'', '`', ';', ','])
}

/// Where `word` first occurs in `text` with no letter, digit or `_` on either side.
fn first_word(text: &str, word: &str) -> Option<usize> {
    text.match_indices(word)
        .map(|(i, _)| i)
        .find(|&i| word_at(text, i, word.len()))
}

fn is_word(text: &str, word: &str) -> bool {
    first_word(text, word).is_some()
}

fn word_at(text: &str, at: usize, len: usize) -> bool {
    let edge = |c: Option<char>| !c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    edge(text[..at].chars().next_back()) && edge(text[at + len..].chars().next())
}

/// Where the last `|` of `lower` sits whose command runs its input as code
/// (`| sh`, `| sudo -E bash -s`; not `| python3 -c …` or `| python -m
/// json.tool`, which read a program of their own). One pass over the line.
fn last_runner_pipe(lower: &str) -> Option<usize> {
    let mut at = 0;
    let mut last = None;
    for (n, segment) in lower.split('|').enumerate() {
        if n > 0 {
            let word = command_word(segment);
            let name = word.rsplit('/').next().unwrap_or(word);
            let own_program = segment
                .split_whitespace()
                .skip_while(|w| !w.ends_with(name))
                .any(|w| matches!(w, "-c" | "-m" | "-e"));
            if RUNNERS.contains(&name) && !own_program {
                last = Some(at - 1);
            }
        }
        at += segment.len() + 1;
    }
    last
}

/// Where a program that runs its argument or stdin as code is first named.
fn first_runner(lower: &str, runners: &[&str]) -> Option<usize> {
    runners.iter().filter_map(|r| first_word(lower, r)).min()
}

/// The downloader whose output a shell runs: `curl … | sh`, `bash <(curl …)`,
/// `sh -c "$(curl …)"`, `eval "$(wget -qO- …)"`, `iwr … | iex`.
fn pipe_to_shell(lower: &str) -> Option<&'static str> {
    let pipe = last_runner_pipe(lower);
    let runner = first_runner(lower, RUNNERS);
    FETCHERS.iter().copied().find(|fetcher| {
        lower.match_indices(fetcher).any(|(i, _)| {
            if !word_at(lower, i, fetcher.len()) {
                return false;
            }
            let before = lower[..i].trim_end_matches(['"', '\'']);
            let substituted = before.ends_with("<(") || before.ends_with("$(");
            pipe.is_some_and(|p| p > i) || (substituted && runner.is_some_and(|r| r < i))
        })
    })
}

fn decode_exec(lower: &str) -> bool {
    let pipe = last_runner_pipe(lower);
    let wrapper = first_runner(
        lower,
        &["eval", "sh -c", "bash -c", "iex", "invoke-expression"],
    );
    let shell = SHELL_DECODERS.iter().any(|d| {
        lower
            .find(&d.to_ascii_lowercase())
            .is_some_and(|i| pipe.is_some_and(|p| p > i) || wrapper.is_some_and(|w| w < i))
    });
    let buffer = lower.contains("buffer.from(")
        && (lower.contains("base64") || lower.contains("'hex'") || lower.contains("\"hex\""));
    // an eval call before a decoder call on the line: `exec(base64.b64decode(…))`
    let first_eval = EVALS
        .iter()
        .filter_map(|e| {
            lower
                .match_indices(e)
                .map(|(i, _)| i)
                .find(|&i| !lower[..i].ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
        })
        .min();
    let last_decoder = DECODERS
        .iter()
        .chain(buffer.then_some(&"buffer.from("))
        .filter_map(|d| lower.rfind(d))
        .max();
    let call = matches!((first_eval, last_decoder), (Some(e), Some(d)) if e < d);
    shell || call || encoded_powershell(lower)
}

/// `powershell -EncodedCommand <base64>` with the base64 written out: a
/// command built at run time (`-EncodedCommand {}`, `$cmd`) is code the change shows.
fn encoded_powershell(lower: &str) -> bool {
    if !(is_word(lower, "powershell") || is_word(lower, "pwsh")) {
        return false;
    }
    let mut words = lower.split_whitespace();
    while let Some(word) = words.next() {
        let flag = matches!(word, "-enc" | "-encodedcommand" | "-e" | "-ec");
        let literal = |w: &str| {
            let w = w.trim_matches(['"', '\'']);
            w.len() >= 8
                && w.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        };
        if flag && words.clone().next().is_some_and(literal) {
            return true;
        }
    }
    false
}

fn is_import(text: &str) -> bool {
    let t = text.trim_start();
    t.starts_with("import ") || t.starts_with("import\t")
}

/// `ADD [--options] http…` without `--checksum=`.
fn remote_add(lower: &str) -> bool {
    let t = lower.trim_start();
    let Some(rest) = t.strip_prefix("add ").or_else(|| t.strip_prefix("add\t")) else {
        return false;
    };
    let source = rest.split_whitespace().find(|w| !w.starts_with("--"));
    source.is_some_and(|s| {
        ["http://", "https://", "git@", "ssh://"]
            .iter()
            .any(|p| s.starts_with(p))
    }) && !rest.contains("--checksum=")
}

/// The longest run of base64 in `text` of at least [`BLOB_LEN`] characters,
/// with upper and lower case letters and digits; not a `data:image/…` or
/// `data:font/…` URI, which a browser shows rather than runs.
fn base64_run(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut best = None;
    let mut start = 0;
    for end in 0..=bytes.len() {
        let b64 = bytes
            .get(end)
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
        if b64 {
            continue;
        }
        let run = bytes.get(start..end).unwrap_or_default();
        let candidate = run.len() >= BLOB_LEN
            && best.is_none_or(|b| run.len() > b)
            && run.iter().any(u8::is_ascii_lowercase)
            && run.iter().any(u8::is_ascii_uppercase)
            && run.iter().any(u8::is_ascii_digit);
        if candidate {
            // the 48 bytes before the run: `data:image/png;base64,`
            let from = start.saturating_sub(48);
            let lead = String::from_utf8_lossy(bytes.get(from..start).unwrap_or_default())
                .to_ascii_lowercase();
            let media = lead.ends_with(";base64,")
                && ["data:image/", "data:font/", "data:audio/", "data:video/"]
                    .iter()
                    .any(|m| lead.contains(m));
            if !media {
                best = Some(run.len());
            }
        }
        start = end + 1;
    }
    best
}
