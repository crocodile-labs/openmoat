//! What `CreateProcessAsUserW` takes for the agent on Windows (ADR-115): one
//! command line and one environment block, both UTF-16. Pure, over UTF-16
//! units, so the tests run on every system; `windows.rs` turns the
//! `Command` the run built into these.
//!
//! `std::process::Command` cannot start a program under another token, so
//! the Windows tier starts it itself and must quote as the C runtime and
//! `CommandLineToArgvW` read a command line: an argument with a space, tab,
//! newline or quote, or an empty one, goes in quotes; a quote in it is
//! escaped with a backslash, and the backslashes right before a quote (or the
//! closing quote) are doubled. Batch files read their command line by other
//! rules (`cmd.exe`'s), so the run starts no `.bat` or `.cmd` ([`refused`]).

use anyhow::{Result, bail};

const QUOTE: u16 = b'"' as u16;
const BACKSLASH: u16 = b'\\' as u16;
const SPACE: u16 = b' ' as u16;
const EQUALS: u16 = b'=' as u16;

/// Whether `arg` must be quoted.
fn needs_quotes(arg: &[u16]) -> bool {
    arg.is_empty()
        || arg.iter().any(|&u| {
            u == SPACE || u == u16::from(b'\t') || u == u16::from(b'\n') || u == 0x0b || u == QUOTE
        })
}

/// `arg` as one argument of a command line.
fn push_quoted(line: &mut Vec<u16>, arg: &[u16]) {
    if !needs_quotes(arg) {
        line.extend_from_slice(arg);
        return;
    }
    line.push(QUOTE);
    let mut backslashes = 0;
    for &unit in arg {
        if unit == BACKSLASH {
            backslashes += 1;
            continue;
        }
        if unit == QUOTE {
            // Each backslash before a quote doubles, and the quote is escaped.
            line.extend(std::iter::repeat_n(BACKSLASH, backslashes * 2 + 1));
        } else {
            line.extend(std::iter::repeat_n(BACKSLASH, backslashes));
        }
        backslashes = 0;
        line.push(unit);
    }
    // Before the closing quote they double too.
    line.extend(std::iter::repeat_n(BACKSLASH, backslashes * 2));
    line.push(QUOTE);
}

/// The NUL-terminated command line for `program` and `args`. The program is
/// always quoted, so a path with a space is never split; one with a quote
/// cannot be a Windows path and is refused.
pub fn command_line(program: &[u16], args: &[Vec<u16>]) -> Result<Vec<u16>> {
    if program.contains(&QUOTE) || program.contains(&0) {
        bail!("the program's path holds a quote or a NUL");
    }
    let mut line = vec![QUOTE];
    line.extend_from_slice(program);
    line.push(QUOTE);
    for arg in args {
        if arg.contains(&0) {
            bail!("an argument holds a NUL character");
        }
        line.push(SPACE);
        push_quoted(&mut line, arg);
    }
    line.push(0);
    Ok(line)
}

/// Why the run will not start `program` (its path, UTF-8 or lossy), if it
/// will not: a batch file, whose arguments `cmd.exe` reads by rules no
/// quoting makes safe, or a script that is not a program.
pub fn refused(program: &str) -> Option<String> {
    let lower = program.to_ascii_lowercase();
    let extension = lower.rsplit_once('.').map_or("", |(_, ext)| ext);
    match extension {
        "exe" | "com" => None,
        "bat" | "cmd" => Some(format!(
            "`openmoat run` on Windows starts programs, not batch files: {program} is one, whose \
             arguments cmd.exe reads by its own rules. Start the program it runs (for an npm \
             package, `node` with the package's script) instead"
        )),
        _ => Some(format!(
            "`openmoat run` on Windows starts `.exe` programs; {program} is not one"
        )),
    }
}

/// An ASCII letter in upper case, every other unit as it is: Windows
/// compares variable names without case.
fn upper(unit: u16) -> u16 {
    if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
        unit - 32
    } else {
        unit
    }
}

fn same_name(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| upper(*x) == upper(*y))
}

/// The environment block of `inherited` with `changes` applied (a value
/// sets, `None` removes; names compared without case), sorted by name as
/// Windows asks, each `NAME=value` NUL-terminated and one more NUL at the
/// end. A name with `=` past its first unit, or anything with a NUL, is
/// refused.
pub fn environment_block(
    inherited: Vec<(Vec<u16>, Vec<u16>)>,
    changes: Vec<(Vec<u16>, Option<Vec<u16>>)>,
) -> Result<Vec<u16>> {
    let mut vars = inherited;
    for (name, value) in changes {
        vars.retain(|(have, _)| !same_name(have, &name));
        if let Some(value) = value {
            vars.push((name, value));
        }
    }
    vars.sort_by(|(a, _), (b, _)| a.iter().map(|u| upper(*u)).cmp(b.iter().map(|u| upper(*u))));
    let mut block = Vec::new();
    for (name, value) in vars {
        let bad_name = name.is_empty() || name.iter().skip(1).any(|&u| u == EQUALS);
        if bad_name || name.contains(&0) || value.contains(&0) {
            bail!(
                "the environment variable {} cannot be passed on",
                String::from_utf16_lossy(&name)
            );
        }
        block.extend_from_slice(&name);
        block.push(EQUALS);
        block.extend_from_slice(&value);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn line(program: &str, args: &[&str]) -> String {
        let args: Vec<Vec<u16>> = args.iter().map(|a| w(a)).collect();
        let mut line = command_line(&w(program), &args).unwrap();
        assert_eq!(line.pop(), Some(0));
        String::from_utf16(&line).unwrap()
    }

    /// The C runtime's rules: what `CommandLineToArgvW` splits back into the
    /// same arguments.
    #[test]
    fn arguments_are_quoted_as_the_c_runtime_reads_them() {
        let program = r"C:\Program Files\agent.exe";
        assert_eq!(line(program, &[]), r#""C:\Program Files\agent.exe""#);
        let cases = [
            ("plain", "plain"),
            ("", r#""""#),
            ("two words", r#""two words""#),
            (r#"say "hi""#, r#""say \"hi\"""#),
            (r"C:\dir\", r"C:\dir\"),
            (r"C:\my dir\", r#""C:\my dir\\""#),
            (r#"a\"b"#, r#""a\\\"b""#),
            (r"a\\b c", r#""a\\b c""#),
            ("tab\there", "\"tab\there\""),
        ];
        for (arg, quoted) in cases {
            assert_eq!(
                line("C:/a.exe", &[arg]),
                format!(r#""C:/a.exe" {quoted}"#),
                "{arg:?}"
            );
        }
    }

    #[test]
    fn a_nul_or_a_quoted_program_is_refused() {
        assert!(command_line(&w("C:/a\".exe"), &[]).is_err());
        assert!(command_line(&w("C:/a.exe"), &[vec![0x61, 0]]).is_err());
    }

    #[test]
    fn batch_files_and_scripts_are_refused_programs_are_not() {
        assert_eq!(refused(r"C:\tools\agent.EXE"), None);
        assert_eq!(refused(r"C:\tools\agent.com"), None);
        for script in [
            r"C:\npm\claude.cmd",
            r"C:\x\run.BAT",
            r"C:\x\a.ps1",
            r"C:\x\noext",
        ] {
            assert!(refused(script).is_some(), "{script}");
        }
        assert!(
            refused(r"C:\npm\claude.cmd")
                .unwrap()
                .contains("batch file")
        );
    }

    fn block_text(block: &[u16]) -> Vec<String> {
        let text = String::from_utf16(block).unwrap();
        assert!(text.ends_with("\0\0"), "{text:?}");
        text.trim_end_matches('\0')
            .split('\0')
            .map(str::to_owned)
            .collect()
    }

    /// Changes replace a name whatever its case, removals take it out, and
    /// the block is sorted without case.
    #[test]
    fn the_environment_block_applies_changes_without_case() {
        let inherited = vec![
            (w("Path"), w(r"C:\bin")),
            (w("zeta"), w("1")),
            (w("HTTP_PROXY"), w("old")),
            (w("SECRET"), w("x")),
        ];
        let changes = vec![
            (w("http_proxy"), Some(w("http://127.0.0.1:1"))),
            (w("Secret"), None),
            (w("Alpha"), Some(w("a=b"))),
        ];
        let block = environment_block(inherited, changes).unwrap();
        assert_eq!(
            block_text(&block),
            [
                "Alpha=a=b",
                "http_proxy=http://127.0.0.1:1",
                r"Path=C:\bin",
                "zeta=1"
            ]
        );
    }

    #[test]
    fn an_empty_environment_is_two_nuls_and_a_bad_name_is_refused() {
        assert_eq!(environment_block(Vec::new(), Vec::new()).unwrap(), [0, 0]);
        let bad = vec![(w("A=B"), w("c"))];
        assert!(environment_block(bad, Vec::new()).is_err());
        let drive = vec![(w("=C:"), w(r"C:\x"))];
        assert!(environment_block(drive, Vec::new()).is_ok());
    }
}
