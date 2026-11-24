//! The cmdlets the reader knows, their aliases and parameters, and the POSIX
//! command each one does the same as (`powershell.rs`): `Get-Content` reads
//! like `cat`, `Remove-Item -Recurse -Force` deletes like `rm -r -f`,
//! `Invoke-WebRequest -OutFile` downloads like `curl -o`, so the default
//! policy's rules for those commands decide them.
//!
//! Parameters are matched as PowerShell matches them: case ignored, any
//! unique prefix (`-Rec`), `-Name:value`. A parameter a cmdlet's table does
//! not list is read as a switch, so the word after it stays an operand: a
//! path there is still a path.

/// What a parameter takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Arg {
    Switch,
    Value,
}

/// What a cmdlet does, in POSIX terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Does {
    /// `cat PATH…`.
    Read,
    /// `echo VALUE | tee [-a] PATH…`.
    Write { append: bool },
    /// `rm [-r] [-f] PATH…`.
    Remove,
    /// `cp [-r] PATH… DESTINATION`.
    Copy,
    /// `mv PATH… DESTINATION`.
    Move,
    /// `mv PATH NEWNAME`.
    Rename,
    /// `ls [-R] PATH…`.
    List,
    /// `ls -d PATH…`: the item itself, not its contents.
    Stat,
    /// `cd PATH`.
    Cd,
    /// `mkdir -p PATH` or a file write (`New-Item -ItemType`).
    NewItem,
    /// `curl [-X M] [--data-binary B] [-T F] [-o F] URI`.
    Fetch,
    /// `curl -o DESTINATION SOURCE`.
    Transfer,
    /// `echo VALUE…`.
    Print,
    /// `grep PATTERN PATH…`.
    Search,
    /// `sha256sum PATH…`.
    Hash,
    /// `unzip PATH -d DESTINATION`.
    Expand,
    /// `zip -r DESTINATION PATH…`.
    Compress,
    /// The program `-FilePath` names, with `-ArgumentList`; `sudo` before it
    /// for `-Verb RunAs`.
    Start,
    /// Runs its argument, or its input, as PowerShell code.
    Evaluate,
    /// `Set-ExecutionPolicy`.
    ExecutionPolicy,
    /// `source PATH`: `. .\x.ps1` and `Import-Module .\x.psm1`.
    Source,
}

/// One cmdlet: its names (the canonical one first, lowercase), what it does,
/// its parameters (canonical names, lowercase) and which of them its
/// positional operands bind to, in order (the last takes the rest).
pub(super) struct Cmdlet {
    pub(super) names: &'static [&'static str],
    pub(super) does: Does,
    pub(super) params: &'static [(&'static str, Arg)],
    pub(super) positional: &'static [&'static str],
}

use Arg::{Switch, Value};

/// Parameters every cmdlet takes.
const COMMON: &[(&str, Arg)] = &[
    ("erroraction", Value),
    ("warningaction", Value),
    ("informationaction", Value),
    ("errorvariable", Value),
    ("outvariable", Value),
    ("verbose", Switch),
    ("debug", Switch),
    ("whatif", Switch),
    ("confirm", Switch),
];

const PATHS: &[(&str, Arg)] = &[
    ("path", Value),
    ("literalpath", Value),
    ("filter", Value),
    ("include", Value),
    ("exclude", Value),
    ("force", Switch),
    ("recurse", Switch),
    ("credential", Value),
];

pub(super) const CMDLETS: &[Cmdlet] = &[
    Cmdlet {
        names: &["get-content", "gc", "cat", "type"],
        does: Does::Read,
        params: &[
            ("path", Value),
            ("literalpath", Value),
            ("raw", Switch),
            ("encoding", Value),
            ("totalcount", Value),
            ("head", Value),
            ("first", Value),
            ("tail", Value),
            ("wait", Switch),
            ("readcount", Value),
            ("delimiter", Value),
            ("stream", Value),
            ("asbytestream", Switch),
        ],
        positional: &["path"],
    },
    Cmdlet {
        names: &["set-content", "sc"],
        does: Does::Write { append: false },
        params: &[
            ("path", Value),
            ("literalpath", Value),
            ("value", Value),
            ("encoding", Value),
            ("force", Switch),
            ("nonewline", Switch),
            ("stream", Value),
        ],
        positional: &["path", "value"],
    },
    Cmdlet {
        names: &["add-content", "ac"],
        does: Does::Write { append: true },
        params: &[
            ("path", Value),
            ("literalpath", Value),
            ("value", Value),
            ("encoding", Value),
            ("force", Switch),
            ("nonewline", Switch),
            ("stream", Value),
        ],
        positional: &["path", "value"],
    },
    Cmdlet {
        names: &["out-file"],
        does: Does::Write { append: false },
        params: &[
            ("filepath", Value),
            ("literalpath", Value),
            ("append", Switch),
            ("encoding", Value),
            ("force", Switch),
            ("noclobber", Switch),
            ("nonewline", Switch),
            ("width", Value),
            ("inputobject", Value),
        ],
        positional: &["filepath"],
    },
    Cmdlet {
        names: &["remove-item", "rm", "del", "erase", "ri", "rd", "rmdir"],
        does: Does::Remove,
        params: PATHS,
        positional: &["path"],
    },
    Cmdlet {
        names: &["copy-item", "cp", "copy", "cpi"],
        does: Does::Copy,
        params: &[
            ("path", Value),
            ("literalpath", Value),
            ("destination", Value),
            ("recurse", Switch),
            ("force", Switch),
            ("container", Switch),
            ("filter", Value),
            ("include", Value),
            ("exclude", Value),
            ("passthru", Switch),
        ],
        positional: &["path", "destination"],
    },
    Cmdlet {
        names: &["move-item", "mv", "move", "mi"],
        does: Does::Move,
        params: &[
            ("path", Value),
            ("literalpath", Value),
            ("destination", Value),
            ("force", Switch),
            ("filter", Value),
            ("include", Value),
            ("exclude", Value),
            ("passthru", Switch),
        ],
        positional: &["path", "destination"],
    },
    Cmdlet {
        names: &["rename-item", "ren", "rni"],
        does: Does::Rename,
        params: &[
            ("path", Value),
            ("literalpath", Value),
            ("newname", Value),
            ("force", Switch),
            ("passthru", Switch),
        ],
        positional: &["path", "newname"],
    },
    Cmdlet {
        names: &["get-childitem", "gci", "ls", "dir"],
        does: Does::List,
        params: &[
            ("path", Value),
            ("literalpath", Value),
            ("filter", Value),
            ("include", Value),
            ("exclude", Value),
            ("recurse", Switch),
            ("depth", Value),
            ("force", Switch),
            ("name", Switch),
            ("file", Switch),
            ("directory", Switch),
            ("hidden", Switch),
            ("attributes", Value),
        ],
        positional: &["path", "filter"],
    },
    Cmdlet {
        names: &[
            "get-item",
            "gi",
            "test-path",
            "resolve-path",
            "rvpa",
            "get-itemproperty",
            "gp",
        ],
        does: Does::Stat,
        params: &[
            ("path", Value),
            ("literalpath", Value),
            ("pathtype", Value),
            ("force", Switch),
            ("name", Value),
            ("relative", Switch),
            ("isvalid", Switch),
        ],
        positional: &["path"],
    },
    Cmdlet {
        names: &[
            "set-location",
            "cd",
            "sl",
            "chdir",
            "push-location",
            "pushd",
        ],
        does: Does::Cd,
        params: &[
            ("path", Value),
            ("literalpath", Value),
            ("passthru", Switch),
        ],
        positional: &["path"],
    },
    Cmdlet {
        names: &["new-item", "ni", "mkdir", "md"],
        does: Does::NewItem,
        params: &[
            ("path", Value),
            ("name", Value),
            ("itemtype", Value),
            ("value", Value),
            ("force", Switch),
            ("target", Value),
        ],
        positional: &["path"],
    },
    Cmdlet {
        names: &[
            "invoke-webrequest",
            "iwr",
            "invoke-restmethod",
            "irm",
            "curl",
            "wget",
        ],
        does: Does::Fetch,
        params: &[
            ("uri", Value),
            ("outfile", Value),
            ("method", Value),
            ("body", Value),
            ("infile", Value),
            ("headers", Value),
            ("contenttype", Value),
            ("usebasicparsing", Switch),
            ("useragent", Value),
            ("proxy", Value),
            ("credential", Value),
            ("timeoutsec", Value),
            ("maximumredirection", Value),
            ("sessionvariable", Value),
            ("websession", Value),
            ("form", Value),
            ("skipcertificatecheck", Switch),
            ("passthru", Switch),
        ],
        positional: &["uri"],
    },
    Cmdlet {
        names: &["start-bitstransfer"],
        does: Does::Transfer,
        params: &[
            ("source", Value),
            ("destination", Value),
            ("asynchronous", Switch),
            ("credential", Value),
        ],
        positional: &["source", "destination"],
    },
    Cmdlet {
        names: &["write-output", "echo", "write", "write-host"],
        does: Does::Print,
        params: &[
            ("inputobject", Value),
            ("object", Value),
            ("nonewline", Switch),
            ("foregroundcolor", Value),
            ("backgroundcolor", Value),
            ("noenumerate", Switch),
        ],
        positional: &["inputobject"],
    },
    Cmdlet {
        names: &["select-string", "sls"],
        does: Does::Search,
        params: &[
            ("pattern", Value),
            ("path", Value),
            ("literalpath", Value),
            ("simplematch", Switch),
            ("casesensitive", Switch),
            ("context", Value),
            ("list", Switch),
            ("quiet", Switch),
            ("notmatch", Switch),
            ("allmatches", Switch),
            ("encoding", Value),
        ],
        positional: &["pattern", "path"],
    },
    Cmdlet {
        names: &["get-filehash"],
        does: Does::Hash,
        params: &[
            ("path", Value),
            ("literalpath", Value),
            ("algorithm", Value),
        ],
        positional: &["path"],
    },
    Cmdlet {
        names: &["expand-archive"],
        does: Does::Expand,
        params: &[
            ("path", Value),
            ("literalpath", Value),
            ("destinationpath", Value),
            ("force", Switch),
        ],
        positional: &["path", "destinationpath"],
    },
    Cmdlet {
        names: &["compress-archive"],
        does: Does::Compress,
        params: &[
            ("path", Value),
            ("literalpath", Value),
            ("destinationpath", Value),
            ("force", Switch),
            ("update", Switch),
            ("compressionlevel", Value),
        ],
        positional: &["path", "destinationpath"],
    },
    Cmdlet {
        names: &["start-process", "saps", "start"],
        does: Does::Start,
        params: &[
            ("filepath", Value),
            ("argumentlist", Value),
            ("verb", Value),
            ("workingdirectory", Value),
            ("wait", Switch),
            ("nonewwindow", Switch),
            ("passthru", Switch),
            ("windowstyle", Value),
            ("credential", Value),
            ("loaduserprofile", Switch),
            ("redirectstandardoutput", Value),
            ("redirectstandarderror", Value),
            ("redirectstandardinput", Value),
            ("usenewenvironment", Switch),
        ],
        positional: &["filepath", "argumentlist"],
    },
    Cmdlet {
        names: &["invoke-expression", "iex"],
        does: Does::Evaluate,
        params: &[("command", Value)],
        positional: &["command"],
    },
    Cmdlet {
        names: &["set-executionpolicy"],
        does: Does::ExecutionPolicy,
        params: &[
            ("executionpolicy", Value),
            ("scope", Value),
            ("force", Switch),
        ],
        positional: &["executionpolicy", "scope"],
    },
    Cmdlet {
        names: &["import-module", "ipmo"],
        does: Does::Source,
        params: &[
            ("name", Value),
            ("force", Switch),
            ("global", Switch),
            ("passthru", Switch),
        ],
        positional: &["name"],
    },
];

/// The cmdlet `name` (any case, an alias included).
pub(super) fn find(name: &str) -> Option<&'static Cmdlet> {
    let lower = name.to_ascii_lowercase();
    CMDLETS.iter().find(|c| c.names.contains(&lower.as_str()))
}

impl Cmdlet {
    /// The canonical parameter `word` (`-Rec`, `-Path:x`) names, what it
    /// takes, and the value glued to it after `:`; `None` for a word that is
    /// not a parameter. A parameter the table does not list is a switch.
    pub(super) fn parameter(&self, word: &str) -> Option<(&'static str, Arg, Option<String>)> {
        let body = word.strip_prefix('-')?;
        if body.is_empty() || body.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        let (name, glued) = match body.split_once(':') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (body, None),
        };
        let lower = name.to_ascii_lowercase();
        let all = self.params.iter().chain(COMMON);
        let exact = all.clone().find(|(p, _)| *p == lower);
        let mut prefixed = all.filter(|(p, _)| p.starts_with(lower.as_str()));
        let found = exact.or_else(|| match (prefixed.next(), prefixed.next()) {
            (Some(one), None) => Some(one),
            _ => None,
        });
        Some(found.map_or(("", Arg::Switch, glued.clone()), |(p, a)| (p, *a, glued)))
    }
}
