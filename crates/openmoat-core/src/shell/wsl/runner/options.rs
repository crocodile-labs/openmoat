//! The options of the programs whose lines `runner.rs` reads: which words
//! before the program are options, which take a value, and which make the
//! line unreadable.

/// Whose options a word may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// `cmd`: `/x` and `/x:value`; `/c`, `/k` and `/r` may have the
    /// program glued on (`/cwsl`). Git Bash turns `//c` into `/c`.
    Cmd,
    /// Windows PowerShell and `pwsh` (`-x` or `/x`, any unique prefix).
    PowerShell,
    /// `cmd`'s `start`: `/x`, and `/d`, `/node`, `/affinity` with a value.
    Start,
    /// `Start-Process` (`saps`): `-FilePath` names the program,
    /// `-ArgumentList` its arguments.
    StartProcess,
    /// `explorer`, `wt`, `runas`, `conhost`, `Invoke-Item`: any `-x` or `/x`.
    Launcher,
    /// `forfiles`: `/p` and `/d` take a value, `/m` (a mask) hides which
    /// file it runs, `/c`'s value is the command (`line.rs` reads the rest).
    ForFiles,
    /// A segment's program after a separator: a `-x` word is skipped.
    Plain,
}

/// What an option word does.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Opt {
    /// It stands alone (`-NoProfile`, `-Command`, after which the program
    /// comes).
    Flag,
    /// The next word is its value (`-ExecutionPolicy Bypass`).
    Value,
    /// The words after it are a launched program's arguments.
    Arguments,
    /// It hides what runs, or is not known (`-EncodedCommand`, `-Bogus`).
    Opaque,
    /// `cmd /cwsl`: the program glued to the option.
    Glued(String),
}

/// PowerShell's options by full name, with the class of each
/// (<https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh>,
/// `about_PowerShell_exe`).
const POWERSHELL: &[(&str, Class)] = &[
    ("command", Class::Flag),
    ("commandwithargs", Class::Flag),
    ("noprofile", Class::Flag),
    ("nologo", Class::Flag),
    ("noninteractive", Class::Flag),
    ("noexit", Class::Flag),
    ("noprofileloadtime", Class::Flag),
    ("sta", Class::Flag),
    ("mta", Class::Flag),
    ("login", Class::Flag),
    ("interactive", Class::Flag),
    ("help", Class::Flag),
    ("executionpolicy", Class::Value),
    ("windowstyle", Class::Value),
    ("version", Class::Value),
    ("configurationname", Class::Value),
    ("workingdirectory", Class::Value),
    ("inputformat", Class::Value),
    ("outputformat", Class::Value),
    ("psconsolefile", Class::Value),
    ("file", Class::Value),
    ("settingsfile", Class::Value),
    ("custompipename", Class::Value),
    ("encodedcommand", Class::Opaque),
    ("encodedarguments", Class::Opaque),
];

/// PowerShell's short names, which win over prefix matching.
const POWERSHELL_ALIASES: &[(&str, Class)] = &[
    ("c", Class::Flag),
    ("cwa", Class::Flag),
    ("nop", Class::Flag),
    ("nol", Class::Flag),
    ("noni", Class::Flag),
    ("l", Class::Flag),
    ("i", Class::Flag),
    ("h", Class::Flag),
    ("?", Class::Flag),
    ("ex", Class::Value),
    ("ep", Class::Value),
    ("w", Class::Value),
    ("v", Class::Value),
    ("config", Class::Value),
    ("wd", Class::Value),
    ("if", Class::Value),
    ("inp", Class::Value),
    ("o", Class::Value),
    ("of", Class::Value),
    ("f", Class::Value),
    ("e", Class::Opaque),
    ("ec", Class::Opaque),
    ("ea", Class::Opaque),
];

/// `Start-Process`'s options.
const START_PROCESS: &[(&str, Class)] = &[
    ("filepath", Class::Flag),
    ("wait", Class::Flag),
    ("passthru", Class::Flag),
    ("nonewwindow", Class::Flag),
    ("loaduserprofile", Class::Flag),
    ("usenewenvironment", Class::Flag),
    ("argumentlist", Class::Arguments),
    ("args", Class::Arguments),
    ("windowstyle", Class::Value),
    ("workingdirectory", Class::Value),
    ("verb", Class::Value),
    ("credential", Class::Value),
    ("environment", Class::Value),
    ("redirectstandardinput", Class::Value),
    ("redirectstandardoutput", Class::Value),
    ("redirectstandarderror", Class::Value),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Flag,
    Value,
    Arguments,
    Opaque,
}

impl Kind {
    /// The kind of `program`'s line, if it is a runner.
    pub(super) fn of(program: &str) -> Option<Self> {
        Some(match program {
            "cmd" => Self::Cmd,
            "powershell" | "pwsh" => Self::PowerShell,
            "start" => Self::Start,
            "start-process" | "saps" => Self::StartProcess,
            "explorer" | "wt" | "conhost" | "runas" | "ii" | "invoke-item" => Self::Launcher,
            "forfiles" => Self::ForFiles,
            _ => return None,
        })
    }

    /// Whether `'` quotes in this line (PowerShell's), not only `"` (`cmd`'s).
    pub(super) fn single_quotes(self) -> bool {
        !matches!(self, Self::Cmd | Self::Start | Self::ForFiles)
    }

    /// What `word` is as one of this kind's options; `None` when it is not one.
    pub(super) fn option(self, word: &str) -> Option<Opt> {
        match self {
            Self::Cmd => cmd(word),
            Self::Start => slash_name(word).map(|name| match name.as_str() {
                "d" | "node" | "affinity" => Opt::Value,
                _ => Opt::Flag,
            }),
            // `-Command -` reads the command from standard input
            Self::PowerShell if word == "-" => Some(Opt::Opaque),
            Self::PowerShell => named(word).map(|name| {
                class_of(&name, POWERSHELL_ALIASES, POWERSHELL).map_or(Opt::Opaque, Class::opt)
            }),
            Self::StartProcess => dash_name(word)
                .map(|name| class_of(&name, &[], START_PROCESS).map_or(Opt::Opaque, Class::opt)),
            Self::Launcher => named(word).map(|_| Opt::Flag),
            Self::ForFiles => slash_name(word).map(|name| match name.as_str() {
                "p" | "d" => Opt::Value,
                "m" => Opt::Opaque,
                _ => Opt::Flag,
            }),
            Self::Plain => dash_name(word).map(|_| Opt::Flag),
        }
    }
}

impl Class {
    fn opt(self) -> Opt {
        match self {
            Self::Flag => Opt::Flag,
            Self::Value => Opt::Value,
            Self::Arguments => Opt::Arguments,
            Self::Opaque => Opt::Opaque,
        }
    }
}

/// `cmd`'s `/x`, `/x:value`, `/cprogram`; `//c` as Git Bash hands it on.
fn cmd(word: &str) -> Option<Opt> {
    let word = word
        .strip_prefix('/')
        .filter(|rest| {
            rest.starts_with('/') && rest[1..].starts_with(|c: char| c.is_ascii_alphabetic())
        })
        .unwrap_or(word);
    let rest = word.strip_prefix('/')?;
    let letter = rest.chars().next().filter(char::is_ascii_alphabetic)?;
    let after = &rest[letter.len_utf8()..];
    if after.is_empty() || after.starts_with(':') {
        return Some(Opt::Flag);
    }
    Some(if matches!(letter.to_ascii_lowercase(), 'c' | 'k' | 'r') {
        Opt::Glued(after.to_owned())
    } else {
        Opt::Flag
    })
}

/// The lower-case name of a `-name` option.
fn dash_name(word: &str) -> Option<String> {
    let name = word.strip_prefix('-')?.to_ascii_lowercase();
    (!name.is_empty()).then_some(name)
}

/// The lower-case name of a `/name` option (letters only, so a path is not one).
fn slash_name(word: &str) -> Option<String> {
    let name = word.strip_prefix('/')?;
    let letters = !name.is_empty()
        && name
            .split(':')
            .next()
            .is_some_and(|n| n.chars().all(|c| c.is_ascii_alphanumeric() || c == '?'));
    letters.then(|| name.split(':').next().unwrap_or(name).to_ascii_lowercase())
}

/// `-name` or `/name`.
fn named(word: &str) -> Option<String> {
    dash_name(word).or_else(|| slash_name(word))
}

/// The class of option `name`: a short name, else every full name it is a
/// prefix of, when they all agree; `None` when it is unknown or ambiguous.
/// A value given after `:` (`-ExecutionPolicy:Bypass`) leaves no word to skip.
fn class_of(name: &str, aliases: &[(&str, Class)], full: &[(&str, Class)]) -> Option<Class> {
    let (name, glued) = name
        .split_once(':')
        .map_or((name, false), |(n, _)| (n, true));
    let found = if let Some((_, class)) = aliases.iter().chain(full).find(|(n, _)| *n == name) {
        *class
    } else {
        let mut classes = full
            .iter()
            .filter(|(n, _)| n.starts_with(name))
            .map(|(_, class)| *class);
        let first = classes.next()?;
        if !classes.all(|class| class == first) {
            return None;
        }
        first
    };
    Some(if glued && found == Class::Value {
        Class::Flag
    } else {
        found
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_options_by_name_alias_and_prefix() {
        let ps = Kind::PowerShell;
        assert_eq!(ps.option("-ExecutionPolicy"), Some(Opt::Value));
        assert_eq!(ps.option("-ep"), Some(Opt::Value));
        assert_eq!(ps.option("-w"), Some(Opt::Value));
        assert_eq!(ps.option("-WindowS"), Some(Opt::Value));
        assert_eq!(ps.option("-NoP"), Some(Opt::Flag));
        assert_eq!(ps.option("-Command"), Some(Opt::Flag));
        assert_eq!(ps.option("/c"), Some(Opt::Flag));
        assert_eq!(ps.option("-enc"), Some(Opt::Opaque));
        assert_eq!(ps.option("-e"), Some(Opt::Opaque));
        assert_eq!(ps.option("-ec"), Some(Opt::Opaque));
        assert_eq!(ps.option("-ExecutionPolicy:Bypass"), Some(Opt::Flag));
        assert_eq!(ps.option("-"), Some(Opt::Opaque));
        // unknown, or a prefix of options of different classes
        assert_eq!(ps.option("-Bogus"), Some(Opt::Opaque));
        assert_eq!(ps.option("-co"), Some(Opt::Opaque));
        // a prefix of five options that all stand alone
        assert_eq!(ps.option("-no"), Some(Opt::Flag));
        assert_eq!(ps.option("wsl"), None);
        assert_eq!(ps.option("/c/Windows/System32/wsl.exe"), None);
    }

    #[test]
    fn cmd_options_glued_and_doubled() {
        let cmd = Kind::Cmd;
        assert_eq!(cmd.option("/c"), Some(Opt::Flag));
        assert_eq!(cmd.option("/C"), Some(Opt::Flag));
        assert_eq!(cmd.option("/v:on"), Some(Opt::Flag));
        assert_eq!(cmd.option("//c"), Some(Opt::Flag));
        assert_eq!(cmd.option("/cwsl"), Some(Opt::Glued("wsl".to_owned())));
        assert_eq!(
            cmd.option("/Kwsl.exe"),
            Some(Opt::Glued("wsl.exe".to_owned()))
        );
        assert_eq!(cmd.option("//cwsl"), Some(Opt::Glued("wsl".to_owned())));
        assert_eq!(cmd.option("wsl"), None);
        assert_eq!(cmd.option("//wsl$/x"), Some(Opt::Flag));
    }

    #[test]
    fn start_process_names_its_program_and_arguments() {
        let sp = Kind::StartProcess;
        assert_eq!(sp.option("-FilePath"), Some(Opt::Flag));
        assert_eq!(sp.option("-ArgumentList"), Some(Opt::Arguments));
        assert_eq!(sp.option("-Args"), Some(Opt::Arguments));
        assert_eq!(sp.option("-WindowStyle"), Some(Opt::Value));
        assert_eq!(sp.option("-Bogus"), Some(Opt::Opaque));
        assert_eq!(Kind::Start.option("/d"), Some(Opt::Value));
        assert_eq!(Kind::Start.option("/b"), Some(Opt::Flag));
    }
}
