//! A brokered secret read from a program the person chose (ADR-087): the
//! schema of `source: { command: … }` and its validation. Running the program
//! is the CLI's job (`secrets/command.rs`), and only `openmoat proxy` does it.

use serde::{Deserialize, Serialize};

/// The shortest `lifetime` a command source may have.
pub const MIN_LIFETIME_SECS: u64 = 60;
/// The longest `lifetime` a command source may have: a value older than this
/// is not short-lived.
pub const MAX_LIFETIME_SECS: u64 = 12 * 60 * 60;
/// The shortest `refresh_before`: the program gets at least this long to
/// answer before the value it replaces expires.
pub const MIN_REFRESH_BEFORE_SECS: u64 = 10;
/// The most arguments a command source may name, the program included.
pub const MAX_ARGS: usize = 64;

/// Folders every user can write: a program there could be replaced by
/// anyone, the agent included. Compared on the path as written; the CLI checks
/// the resolved file as well. (macOS's per-user `/var/folders` is the user's
/// own, like the home: a deny rule must cover a program there.)
const SHARED_TEMP: &[&str] = &[
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/private/var/tmp/",
    "/dev/shm/",
];

/// `source: { command: { run: [...], lifetime: 15m, refresh_before: 2m } }`.
/// `Debug` names the program only: arguments can name accounts and projects.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSource {
    /// The program, absolute or under `~/`, then its arguments. Run without a
    /// shell: no word is expanded.
    pub run: Vec<String>,
    /// The longest a value is used, `90s`, `15m` or `1h`, from 1 minute to 12
    /// hours. A shorter expiry the program prints wins.
    pub lifetime: String,
    /// How long before the value expires the proxy asks for a new one; a fifth
    /// of `lifetime` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_before: Option<String>,
}

impl std::fmt::Debug for CommandSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandSource")
            .field("program", &self.program())
            .finish_non_exhaustive()
    }
}

impl CommandSource {
    /// The program as written: the first word of `run`.
    #[must_use]
    pub fn program(&self) -> &str {
        self.run.first().map_or("", String::as_str)
    }

    /// `lifetime` in seconds. Validated when the policy loaded.
    #[must_use]
    pub fn lifetime_secs(&self) -> u64 {
        duration_secs(&self.lifetime).unwrap_or(MIN_LIFETIME_SECS)
    }

    /// The folder every user can write that `path` (slash-separated) lies in,
    /// if any: no program there is the person's alone.
    #[must_use]
    pub fn shared_temp_dir(path: &str) -> Option<&'static str> {
        SHARED_TEMP
            .iter()
            .copied()
            .find(|dir| path.starts_with(dir))
    }

    /// `refresh_before` in seconds, or a fifth of the lifetime, never less
    /// than 10 seconds.
    #[must_use]
    pub fn refresh_before_secs(&self) -> u64 {
        self.refresh_before
            .as_deref()
            .and_then(duration_secs)
            .unwrap_or(self.lifetime_secs() / 5)
            .max(MIN_REFRESH_BEFORE_SECS)
    }
}

/// Why `source` cannot be used, if it cannot.
pub(super) fn check(source: &CommandSource) -> Result<(), String> {
    let program = source.program();
    if source.run.is_empty() || source.run.len() > MAX_ARGS {
        return Err(format!(
            "source command `run` needs a program and at most {} arguments",
            MAX_ARGS - 1
        ));
    }
    if source
        .run
        .iter()
        .any(|word| word.chars().any(char::is_control))
    {
        return Err("source command `run` holds a control character".into());
    }
    if !(crate::paths::is_absolute(program) || program.starts_with("~/")) {
        return Err(format!(
            "source command `{program}` must be an absolute path or start with `~/`: a bare \
             name is looked up in a search path the agent may change"
        ));
    }
    let slashed = program.replace('\\', "/");
    if slashed.split('/').any(|part| part == ".." || part == ".") {
        return Err(format!(
            "source command `{program}` must not name `.` or `..`"
        ));
    }
    if let Some(dir) = CommandSource::shared_temp_dir(&slashed) {
        return Err(format!(
            "source command `{program}` is under {dir}, where any user, the agent too, can put \
             a file"
        ));
    }
    let lifetime = duration_secs(&source.lifetime).ok_or_else(|| {
        format!(
            "source command lifetime `{}` is not a duration such as `90s`, `15m` or `1h`",
            source.lifetime
        )
    })?;
    if !(MIN_LIFETIME_SECS..=MAX_LIFETIME_SECS).contains(&lifetime) {
        return Err(format!(
            "source command lifetime `{}` must be from 1m to 12h",
            source.lifetime
        ));
    }
    if let Some(before) = &source.refresh_before {
        let secs = duration_secs(before).ok_or_else(|| {
            format!("source command refresh_before `{before}` is not a duration such as `2m`")
        })?;
        if secs < MIN_REFRESH_BEFORE_SECS || secs >= lifetime {
            return Err(format!(
                "source command refresh_before `{before}` must be at least 10s and shorter than \
                 the lifetime"
            ));
        }
    }
    Ok(())
}

/// Seconds in `text`: digits then one unit, `s`, `m` or `h`.
#[must_use]
pub fn duration_secs(text: &str) -> Option<u64> {
    let unit = match text.as_bytes().last()? {
        b's' => 1,
        b'm' => 60,
        b'h' => 60 * 60,
        _ => return None,
    };
    let digits = &text[..text.len() - 1];
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok().map(|n| n * unit)
}
