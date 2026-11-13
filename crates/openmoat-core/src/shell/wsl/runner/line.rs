//! What makes a whole runner line opaque, whatever its program words say:
//! it is not simple (`simple.rs`, as PowerShell for a PowerShell line or one
//! that starts PowerShell, as `cmd` for a `cmd`, `start` or `forfiles` line
//! or one that starts `cmd`), it writes a script and may run it, or
//! `forfiles` picks its files by a mask or runs a command on each.

use super::options::Kind;

/// Extensions Windows runs as a script or a batch file.
const SCRIPTS: &[&str] = &[
    "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf",
];

/// Whether `line` (of a runner of `kind`) is opaque as a whole.
pub(super) fn opaque(line: &str, kind: Kind) -> bool {
    let programs: Vec<String> = line
        .split(|c: char| c.is_whitespace() || "&|;\"'".contains(c))
        .map(super::super::path::program)
        .collect();
    let starts = |names: &[&str]| programs.iter().any(|p| names.contains(&p.as_str()));
    let powershell =
        matches!(kind, Kind::PowerShell | Kind::StartProcess) || starts(&["powershell", "pwsh"]);
    let cmd = matches!(kind, Kind::Cmd | Kind::Start | Kind::ForFiles) || starts(&["cmd"]);
    writes_script(line)
        || forfiles(line)
        || (powershell && !super::simple::powershell(line))
        || (cmd && !super::simple::cmd(line))
}

/// Whether `word` names a script by its extension (`a.bat`, `.\x.ps1`).
fn is_script(word: &str) -> bool {
    let path = super::super::path::read(word);
    path.parts
        .last()
        .and_then(|name| name.rsplit_once('.'))
        .is_some_and(|(_, ext)| SCRIPTS.contains(&ext))
}

/// A `>` or `>>` into a script file: the line may run what it wrote
/// (`echo w^sl -e id> a.bat & a.bat`).
fn writes_script(line: &str) -> bool {
    line.match_indices('>').any(|(at, _)| {
        let target = line[at..].trim_start_matches('>').trim_start();
        let end = target
            .find(|c: char| c.is_whitespace() || "&|;)".contains(c))
            .unwrap_or(target.len());
        is_script(target[..end].trim_matches(['"', '\'']))
    })
}

/// `forfiles` with a mask (`/m ws?.exe`) or a command that names the file it
/// is run on (`@path`, `@file`): what it runs is chosen when the line runs.
fn forfiles(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let words: Vec<&str> = lower
        .split_whitespace()
        .map(|w| w.trim_matches(['"', '\'']))
        .collect();
    let runs = words
        .iter()
        .any(|w| super::super::path::program(w) == "forfiles");
    runs && (words.contains(&"/m")
        || ["@path", "@file", "@fname", "@relpath"]
            .iter()
            .any(|name| lower.contains(name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_that_writes_a_script_is_opaque() {
        assert!(writes_script("echo w^sl -e id> a.bat & a.bat"));
        assert!(writes_script("echo x >> \"C:\\t\\run.PS1\""));
        assert!(!writes_script("echo x > out.txt"));
        assert!(is_script(r".\x.ps1"));
        assert!(!is_script("x.exe"));
    }

    #[test]
    fn forfiles_with_a_mask_or_a_file_name_is_opaque() {
        assert!(forfiles(
            r#"forfiles /p C:\Windows\System32 /m ws?.exe /c "@path -e id""#
        ));
        assert!(forfiles(r#"FORFILES /c "cmd /c echo @file""#));
        assert!(!forfiles("forfiles /p C:/logs /d -30"));
        assert!(!forfiles("echo /m @path"));
    }
}
