//! What every hook OpenMoat installs runs: `<binary> guard --host <id>`, and
//! `--home <state directory>` (ADR-071).
//!
//! The guard takes the state directory from its command line, which `init`
//! writes into the host's hook file and the lock pins, not from the
//! environment the host hands the hook. Every layout builds its command from
//! [`GuardCommand`] and recognises one of OpenMoat's by [`split_guard`], so the
//! arguments change here and nowhere else.
//!
//! The state directory is written as one word that needs no quoting in any
//! shell a host runs its hooks with (`sh`, `bash`, PowerShell, `cmd`):
//! [`encode_home`] keeps ASCII letters, digits and `/ . _ - :`, and writes every
//! other byte as `+` and two hex digits (a space is `+20`). A plain path such as
//! `/Users/me/.moat` is its own encoding, so a person can read and type it.

use std::fmt::Write as _;

/// The guard's flag that names the state directory.
pub const HOME_FLAG: &str = "--home";

/// The guard's flag that names the hook event its entry is installed for,
/// for a host whose payload names none (GitHub Copilot CLI's camelCase
/// hooks): the entry, not the payload, says which event a payload answers
/// ([`crate::HookSpec::names_event`]).
pub const EVENT_FLAG: &str = "--event";

/// The guard command of a hook entry: the binary and the state directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardCommand {
    /// The binary's path, as the hook runs it.
    pub binary: String,
    /// The state directory, with `/` separators; `None` writes the form of
    /// releases before ADR-071, whose guard reads `MOAT_HOME`.
    pub home: Option<String>,
    /// The hook event the entry is for ([`EVENT_FLAG`]); `None` for an entry
    /// whose payload names its own event.
    pub event: Option<&'static str>,
}

impl GuardCommand {
    /// The command running `binary`, naming no state directory.
    #[must_use]
    pub fn new(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
            home: None,
            event: None,
        }
    }

    /// This command for the entry `spec`: naming its event when the entry
    /// must ([`crate::HookSpec::names_event`]).
    #[must_use]
    pub fn for_entry(&self, spec: &crate::HookSpec) -> Self {
        Self {
            event: spec.names_event.then_some(spec.event),
            ..self.clone()
        }
    }

    /// This command naming `home` as the state directory.
    #[must_use]
    pub fn with_home(self, home: impl Into<String>) -> Self {
        Self {
            home: Some(home.into()),
            ..self
        }
    }

    /// What follows the binary in a shell string: ` guard --host <id>`, then
    /// ` --home <state directory>` ([`encode_home`]) when it names one, then
    /// ` --event <event>` when it names one.
    #[must_use]
    pub fn shell_args(&self, id: &str) -> String {
        let mut args = format!(" guard --host {id}");
        if let Some(home) = &self.home {
            let _ = write!(args, " {HOME_FLAG} {}", encode_home(home));
        }
        if let Some(event) = self.event {
            let _ = write!(args, " {EVENT_FLAG} {event}");
        }
        args
    }

    /// What follows the binary as a list (an exec-form hook, a plugin's
    /// `spawn`): `guard`, `--host`, `<id>`, then `--home` and the state directory.
    #[must_use]
    pub fn arg_list(&self, id: &str) -> Vec<String> {
        let mut args = vec!["guard".to_owned(), "--host".to_owned(), id.to_owned()];
        if let Some(home) = &self.home {
            args.push(HOME_FLAG.to_owned());
            args.push(encode_home(home));
        }
        if let Some(event) = self.event {
            args.push(EVENT_FLAG.to_owned());
            args.push(event.to_owned());
        }
        args
    }
}

/// Whether the entries of the host `id` name their event
/// ([`crate::HookSpec::names_event`]), so their commands end in [`EVENT_FLAG`].
fn names_event(id: &str) -> bool {
    id.parse::<crate::Host>()
        .is_ok_and(crate::Host::entries_name_event)
}

/// Whether `word` can be an event name after [`EVENT_FLAG`]: ASCII letters
/// and `_` only, so no shell reads anything into it.
fn is_event_word(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_')
}

/// A byte [`encode_home`] writes as it is.
fn plain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':')
}

/// `dir` as one word no shell changes: letters, digits and `/ . _ - :` as
/// they are, every other byte as `+` and two hex digits.
#[must_use]
pub fn encode_home(dir: &str) -> String {
    let mut out = String::with_capacity(dir.len());
    for byte in dir.bytes() {
        if plain(byte) {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "+{byte:02X}");
        }
    }
    out
}

/// The state directory `word` names, the inverse of [`encode_home`]; `None`
/// when `word` holds a byte [`encode_home`] never writes, a `+` not followed
/// by two hex digits, or bytes that are not UTF-8.
#[must_use]
pub fn decode_home(word: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(word.len());
    let mut rest = word.bytes();
    while let Some(byte) = rest.next() {
        if plain(byte) {
            bytes.push(byte);
            continue;
        }
        if byte != b'+' {
            return None;
        }
        let hex = [rest.next()?, rest.next()?];
        let hex = std::str::from_utf8(&hex).ok()?;
        bytes.push(u8::from_str_radix(hex, 16).ok()?);
    }
    String::from_utf8(bytes).ok()
}

/// A shell-string command of OpenMoat's guard for host `id`, split: what
/// comes before ` guard --host <id>` (the quoted binary, trimmed) and the
/// state directory's word after `--home`, if any. For a host whose entries
/// name their event ([`names_event`]), a trailing ` --event <event>`
/// ([`EVENT_FLAG`]) after them belongs to the command too. `None` when the
/// command is no guard command for `id`, or carries anything else after it.
pub(crate) fn split_guard<'c>(command: &'c str, id: &str) -> Option<(&'c str, Option<&'c str>)> {
    let command = command.trim_end();
    let marker = format!(" guard --host {id}");
    let at = command.rfind(&marker)?;
    let (program, rest) = (&command[..at], &command[at + marker.len()..]);
    let rest = match rest.rsplit_once(&format!(" {EVENT_FLAG} ")) {
        Some((before, event)) if names_event(id) && is_event_word(event) => before,
        Some(_) => return None,
        None => rest,
    };
    if rest.is_empty() {
        return Some((program.trim(), None));
    }
    let word = rest
        .strip_prefix(" ")?
        .strip_prefix(HOME_FLAG)?
        .strip_prefix(' ')?;
    if word.is_empty() || word.contains(char::is_whitespace) {
        return None;
    }
    Some((program.trim(), Some(word)))
}

/// Whether an exec-form argument list runs OpenMoat's guard for `id`, with or
/// without the state directory.
pub(crate) fn is_guard_list(args: &[&str], id: &str) -> bool {
    let args = match args {
        [rest @ .., flag, event] if *flag == EVENT_FLAG => {
            if !(names_event(id) && is_event_word(event)) {
                return false;
            }
            rest
        }
        _ => args,
    };
    match args {
        ["guard", "--host", host] => *host == id,
        ["guard", "--host", host, flag, word] => {
            *host == id && *flag == HOME_FLAG && decode_home(word).is_some()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_paths_are_their_own_word() {
        assert_eq!(encode_home("/Users/me/.moat"), "/Users/me/.moat");
        assert_eq!(encode_home("C:/Users/me/.moat"), "C:/Users/me/.moat");
    }

    #[test]
    fn every_other_byte_is_written_in_hex_and_read_back() {
        for dir in [
            "/Users/John Smith/.moat",
            "/opt/it's/$(x)/`y`/.moat",
            "C:\\Users\\me\\.moat",
            "/home/ünï/~/.moat+1",
            "/a;b&c|d>e<f*g?h[i]j{k}l!m#n%o^p=q,r@s\"t",
        ] {
            let word = encode_home(dir);
            assert!(word.bytes().all(|b| plain(b) || b == b'+'), "{word}");
            assert_eq!(decode_home(&word).as_deref(), Some(dir), "{word}");
        }
        assert_eq!(encode_home("/a b"), "/a+20b");
    }

    #[test]
    fn a_word_encode_never_writes_is_refused() {
        for word in ["/a b", "/a+2", "/a+zz", "/a'b", "/a\\b", "/a+FF", "/a$b"] {
            assert_eq!(decode_home(word), None, "{word}");
        }
    }

    #[test]
    fn shell_args_and_lists_carry_the_state_directory() {
        let bare = GuardCommand::new("/bin/openmoat");
        assert_eq!(bare.shell_args("cursor"), " guard --host cursor");
        let homed = bare.clone().with_home("/Users/A B/.moat");
        assert_eq!(
            homed.shell_args("cursor"),
            " guard --host cursor --home /Users/A+20B/.moat"
        );
        assert_eq!(
            homed.arg_list("pi"),
            ["guard", "--host", "pi", "--home", "/Users/A+20B/.moat"]
        );
        assert_eq!(bare.arg_list("pi"), ["guard", "--host", "pi"]);
    }

    #[test]
    fn guard_commands_are_split_with_or_without_the_state_directory() {
        assert_eq!(
            split_guard("'/b/om' guard --host cursor", "cursor"),
            Some(("'/b/om'", None))
        );
        assert_eq!(
            split_guard("'/b/om' guard --host cursor --home /h/.moat  ", "cursor"),
            Some(("'/b/om'", Some("/h/.moat")))
        );
        for other in [
            "'/b/om' guard --host cursor-agent",
            "'/b/om' guard --host cursor --home",
            "'/b/om' guard --host cursor --home /h; rm -rf /",
            "'/b/om' guard --host cursor && true",
            "'/b/om' guard --host codex",
        ] {
            assert_eq!(split_guard(other, "cursor"), None, "{other}");
        }
    }

    /// An entry that names its event (`--event`) is still ours, with the
    /// same binary and state directory; anything but a plain event name
    /// after the flag is not.
    #[test]
    fn an_entry_naming_its_event_is_ours_and_nothing_else_after_it() {
        let spec = crate::HookSpec::new("postToolUse", "", 60, false).naming_event();
        let guard = GuardCommand::new("/b/om")
            .with_home("/h/.moat")
            .for_entry(&spec);
        let args = guard.shell_args("copilot-cli");
        assert_eq!(
            args,
            " guard --host copilot-cli --home /h/.moat --event postToolUse"
        );
        assert_eq!(
            split_guard(&format!("'/b/om'{args}"), "copilot-cli"),
            Some(("'/b/om'", Some("/h/.moat")))
        );
        let list = guard.arg_list("copilot-cli");
        let list: Vec<&str> = list.iter().map(String::as_str).collect();
        assert!(is_guard_list(&list, "copilot-cli"));
        let plain = crate::HookSpec::new("preToolUse", "", 60, false);
        assert_eq!(GuardCommand::new("/b/om").for_entry(&plain).event, None);
        // A path holding the flag's text is still the binary's.
        for (id, path) in [
            ("cursor", "'/Users/a --event b/openmoat'"),
            ("copilot-cli", "'/Users/a --event b/om'"),
        ] {
            let event = if id == "copilot-cli" {
                " --event preToolUse"
            } else {
                ""
            };
            let command = format!("{path} guard --host {id} --home /h/.moat{event}");
            assert_eq!(
                split_guard(&command, id),
                Some((path, Some("/h/.moat"))),
                "{command}"
            );
        }
        // Only a host whose entries name their event may carry the flag.
        assert_eq!(
            split_guard(
                "'/b/om' guard --host cursor --home /h/.moat --event preToolUse",
                "cursor"
            ),
            None
        );
        assert!(!is_guard_list(
            &[
                "guard",
                "--host",
                "pi",
                "--home",
                "/h/.moat",
                "--event",
                "tool_call"
            ],
            "pi"
        ));
        for other in [
            "'/b/om' guard --host copilot-cli --home /h/.moat --event post;rm",
            "'/b/om' guard --host copilot-cli --home /h/.moat --event ",
            "'/b/om' guard --host copilot-cli --event postToolUse && true",
        ] {
            assert_eq!(split_guard(other, "copilot-cli"), None, "{other}");
        }
    }

    #[test]
    fn exec_lists_are_ours_only_in_either_form() {
        assert!(is_guard_list(
            &["guard", "--host", "claude-code"],
            "claude-code"
        ));
        assert!(is_guard_list(
            &["guard", "--host", "claude-code", "--home", "/h/.moat"],
            "claude-code"
        ));
        assert!(!is_guard_list(&["guard", "--host", "codex"], "claude-code"));
        assert!(!is_guard_list(
            &["guard", "--host", "claude-code", "--other", "/h"],
            "claude-code"
        ));
        assert!(!is_guard_list(
            &["guard", "--host", "claude-code", "--home", "/a b"],
            "claude-code"
        ));
    }
}
