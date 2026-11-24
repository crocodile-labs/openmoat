//! Command substitutions whose output is known text (ADR-116).
//!
//! `"$(printf %s rm)" -rf ~` and `` `echo cat` ~/.ssh/id_rsa `` run `rm` and
//! `cat`: the substitution only prints words of the line. Such a substitution
//! is `echo` (with `-n`, `-e` or `-E`) or `printf` with the format `%s` or a
//! plain format and no arguments, of words with no quoting but single quotes
//! and no expansion but a leading `~`. The line is classified a second time
//! with each one replaced by what it prints (`shell.rs`), so both sets of atoms
//! count and the fold never loosens a verdict. Anything else stays as written.

/// Characters a folded output may hold: they mean the same unquoted and
/// inside double quotes, so the replacement needs no quoting of its own.
fn safe(c: char) -> bool {
    c.is_ascii_alphanumeric() || "._/:@%+=,- _".contains(c)
}

/// `line` with every foldable substitution replaced by its output; `None`
/// when it has none.
pub(super) fn substitutions(line: &str) -> Option<String> {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    let mut folded = false;
    loop {
        let dollar = rest.find("$(").map(|at| (at, 2, ')'));
        let tick = rest.find('`').map(|at| (at, 1, '`'));
        let next = match (dollar, tick) {
            (Some(d), Some(t)) => Some(if d.0 < t.0 { d } else { t }),
            (d, t) => d.or(t),
        };
        let Some((at, open, close)) = next else {
            out.push_str(rest);
            break;
        };
        let body = &rest[at + open..];
        let Some(end) = body.find(close) else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..at]);
        match output(&body[..end]) {
            Some(text) => {
                out.push_str(&text);
                folded = true;
            }
            None => out.push_str(&rest[at..=at + open + end]),
        }
        rest = &body[end + 1..];
    }
    folded.then_some(out)
}

/// What `inner`, the text of a substitution, prints, when it is known.
fn output(inner: &str) -> Option<String> {
    if inner.contains(['(', ')', '$', '`', ';', '|', '&', '<', '>', '\n', '"', '\\']) {
        return None;
    }
    let words = inner
        .split_whitespace()
        .map(word)
        .collect::<Option<Vec<String>>>()?;
    let (program, args) = words.split_first()?;
    let text = match program.as_str() {
        "echo" => {
            let args: Vec<&String> = args
                .iter()
                .skip_while(|a| matches!(a.as_str(), "-n" | "-e" | "-E"))
                .collect();
            args.iter()
                .map(|a| a.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        }
        "printf" => match args.split_first()? {
            (format, rest) if format == "%s" => rest.concat(),
            (format, []) if !format.contains('%') => format.clone(),
            _ => return None,
        },
        _ => return None,
    };
    // `$HOME` is what `word` wrote for a `~`; nothing else may expand
    let plain = text.replace("$HOME", "");
    (!text.is_empty() && plain.chars().all(safe)).then_some(text)
}

/// One word of a foldable substitution, its quotes removed and a leading
/// `~` written as `$HOME`, which means the home folder in either context.
fn word(raw: &str) -> Option<String> {
    let unquoted = match raw.strip_prefix('\'') {
        Some(rest) => {
            let inner = rest.strip_suffix('\'')?;
            if inner.contains('\'') {
                return None;
            }
            inner.to_owned()
        }
        None if raw.contains('\'') => return None,
        None if raw == "~" => return Some("$HOME".to_owned()),
        None => match raw.strip_prefix("~/") {
            Some(path) => return path.chars().all(safe).then(|| format!("$HOME/{path}")),
            None => raw.to_owned(),
        },
    };
    unquoted.chars().all(safe).then_some(unquoted)
}

#[cfg(test)]
mod tests {
    use super::substitutions;

    #[test]
    fn known_output_is_folded() {
        assert_eq!(
            substitutions("\"$(printf %s rm)\" -rf ~").as_deref(),
            Some("\"rm\" -rf ~")
        );
        assert_eq!(
            substitutions("`echo cat` \"$(echo ~/.ssh/id_rsa)\"").as_deref(),
            Some("cat \"$HOME/.ssh/id_rsa\"")
        );
        assert_eq!(
            substitutions("$(printf 'git') push").as_deref(),
            Some("git push")
        );
        assert_eq!(substitutions("$(echo -n a b) c").as_deref(), Some("a b c"));
    }

    #[test]
    fn anything_else_stays_as_written() {
        for line in [
            "$(git rev-parse --show-toplevel)/x",
            "$(printf '%s\\n' a)",
            "$(echo $HOME)",
            "$(echo \"a\")",
            "$(printf %d 1 2)",
            "echo plain",
            "$(echo 'a;b')",
        ] {
            assert_eq!(substitutions(line), None, "{line}");
        }
    }
}
