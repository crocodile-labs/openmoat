//! The signals of a PowerShell line: the spellings Invoke-Obfuscation and
//! hand-written droppers use, which everyday PowerShell does not.

use super::Assessment;

pub(super) fn score(line: &str, out: &mut Assessment) {
    let lower = line.to_ascii_lowercase();
    out.add("backtick-escapes", ticks(line));
    let chars = lower.matches("[char]").count();
    out.add("char-codes", if chars >= 2 { 3 } else { 0 });
    out.add("string-concatenation", concatenations(line));
    out.add(
        "string-building",
        u32::from(lower.contains("-join") || lower.contains("-f ") && line.contains("{0}")),
    );
    out.add(
        "reversal",
        u32::from(lower.contains("::reverse(") || lower.contains("[-1..")),
    );
    out.add("xor", 2 * u32::from(lower.contains("-bxor")));
    out.add(
        "base64-decode",
        2 * u32::from(lower.contains("frombase64string")),
    );
    let encoded = (lower.contains("powershell") || lower.contains("pwsh"))
        && lower
            .split_whitespace()
            .any(|w| w.starts_with(['-', '/']) && is_encoded_command(&w[1..]));
    out.add("encoded-command", 2 * u32::from(encoded));
    out.add(
        "invoke-expression",
        u32::from(
            lower.contains("invoke-expression")
                || lower
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                    .any(|w| w == "iex"),
        ),
    );
    out.add("case-mixing", 2 * u32::from(mixed_case(line)));
    out.add("char-indexing", 2 * u32::from(indexes_characters(&lower)));
}

/// Whether `option` (lowercase, without its `-`) is PowerShell's
/// `-EncodedCommand`, which it takes by any prefix (`-e`, `-enc`) and as `-ec`.
pub(crate) fn is_encoded_command(option: &str) -> bool {
    option == "ec" || (!option.is_empty() && "encodedcommand".starts_with(option))
}

/// Backticks inside a bare word (`` I`nv`oke ``), which PowerShell drops;
/// not the escapes of a string (`` "`n" ``) or a line continuation.
fn ticks(line: &str) -> u32 {
    let chars: Vec<char> = line.chars().collect();
    let n = chars
        .windows(3)
        .filter(|w| w[0].is_ascii_alphabetic() && w[1] == '`' && w[2].is_ascii_alphabetic())
        .count();
    match n {
        0 => 0,
        1 => 2,
        _ => 3,
    }
}

/// `'Inv'+'oke'`: two or more joins of quoted strings.
fn concatenations(line: &str) -> u32 {
    let joins = ["'+'", "\"+\"", "' + '", "\" + \"", "'+\"", "\"+'"]
        .iter()
        .map(|j| line.matches(j).count())
        .sum::<usize>();
    match joins {
        0 => 0,
        1 => 1,
        _ => 3,
    }
}

/// A run of letters whose case changes at every other letter or more often
/// (`InVoKe`, `ExPrEsSiOn`); camel case (`ChildItem`, `myVariableName`)
/// changes far less.
fn mixed_case(line: &str) -> bool {
    line.split(|c: char| !c.is_ascii_alphabetic()).any(|part| {
        let changes = part
            .as_bytes()
            .windows(2)
            .filter(|w| w[0].is_ascii_uppercase() != w[1].is_ascii_uppercase())
            .count();
        part.len() >= 6 && changes * 2 >= part.len()
    })
}

/// `$env:comspec[4,15,25]`, `$pshome[4]+$pshome[30]`: letters picked out of
/// a known string to spell a command.
fn indexes_characters(lower: &str) -> bool {
    lower
        .match_indices('[')
        .filter(|(at, _)| {
            let before = lower[..*at].chars().last();
            let inner = lower[at + 1..].split(']').next().unwrap_or("");
            before.is_some_and(|c| c.is_ascii_alphanumeric() || c == ')')
                && !inner.is_empty()
                && inner
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b',' || b == b' ')
        })
        .count()
        >= 2
        || lower.contains("$env:comspec[")
}
