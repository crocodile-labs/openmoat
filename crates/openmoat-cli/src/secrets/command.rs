//! `command` sources (ADR-087): a program the person named in their policy,
//! run by `openmoat proxy` only, whose answer is a brokered value with a
//! deadline.
//!
//! The program is the file the policy names, symlinks resolved, and it must be
//! one the agent cannot change (`program.rs`); its SHA-256 is taken when the
//! proxy starts and compared before every run. It runs without a shell, with
//! no input, no terminal, a short list of environment variables, a time limit
//! and a cap on what it prints. Its error output is dropped, and no error
//! names anything it printed: only exit codes and limits.

use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_core::{Policy, SecretCommand, SecretCommandHome};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{Place, program};

/// How long the program may take.
const TIME_LIMIT: Duration = Duration::from_secs(30);
/// The most the program may print.
const MAX_OUTPUT: usize = 64 * 1024;
/// The shortest lifetime an answer may have: less is as good as expired.
const MIN_ANSWER: Duration = Duration::from_secs(10);

/// The environment variables the program gets, when the proxy has them: who
/// and where the person is, nothing that configures a tool on its own.
#[cfg(unix)]
const PASSED: &[&str] = &["USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "TZ"];
#[cfg(windows)]
const PASSED: &[&str] = &[
    "SystemRoot",
    "windir",
    "USERNAME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramData",
    "TEMP",
    "TMP",
];
#[cfg(not(any(unix, windows)))]
const PASSED: &[&str] = &[];

/// A `command` source made ready to run: its program checked and pinned.
pub struct Program {
    id: String,
    /// The resolved program file.
    path: PathBuf,
    /// The program as the policy names it, home expanded: its `argv[0]`.
    #[cfg_attr(
        not(unix),
        expect(dead_code, reason = "only Unix sets a program's argv[0]")
    )]
    written: String,
    args: Vec<String>,
    /// SHA-256 of the program when the proxy started.
    digest: String,
    /// A script's interpreter and its SHA-256 when the proxy started.
    interpreter: Option<(PathBuf, String)>,
    /// The `HOME` it gets: a private empty folder, or the person's home.
    home: PathBuf,
    lifetime: Duration,
    refresh_before: Duration,
    time_limit: Duration,
}

/// What one run gave: the value and how long it may be used.
pub struct Answer {
    pub value: Zeroizing<String>,
    pub lifetime: Duration,
}

impl Program {
    /// Check `source`'s program against `policy` (`program.rs`) and pin it.
    /// `home` is the person's home directory in slash form.
    pub fn prepare(
        id: &str,
        source: &SecretCommand,
        policy: &Policy,
        place: &Place<'_>,
    ) -> Result<Self> {
        let home = place.home;
        let written = match source.program().strip_prefix("~/") {
            Some(rest) => format!("{home}/{rest}"),
            None => source.program().to_owned(),
        };
        let checked = program::check(&written, policy, home)?;
        let digest = program::digest(&checked.path)?;
        let interpreter = checked
            .interpreter
            .map(|path| program::digest(&path).map(|digest| (path, digest)))
            .transpose()?;
        Ok(Self {
            id: id.to_owned(),
            path: checked.path,
            written,
            args: source.run.iter().skip(1).cloned().collect(),
            digest,
            interpreter,
            home: program_home(id, source.home, place)?,
            lifetime: Duration::from_secs(source.lifetime_secs()),
            refresh_before: Duration::from_secs(source.refresh_before_secs()),
            time_limit: TIME_LIMIT,
        })
    }

    /// The same program with a shorter time limit, for tests.
    #[cfg(test)]
    #[cfg_attr(
        not(unix),
        expect(dead_code, reason = "the stand-in programs are Unix scripts")
    )]
    pub fn with_time_limit(self, time_limit: Duration) -> Self {
        Self { time_limit, ..self }
    }

    /// The secret this program answers for.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// How long before the value expires a new one is asked for.
    pub fn refresh_before(&self) -> Duration {
        self.refresh_before
    }

    /// Run the program and read its answer. Refused when the program file
    /// changed since the proxy started.
    pub fn fetch(&self) -> Result<Answer> {
        let pinned = std::iter::once((&self.path, &self.digest))
            .chain(self.interpreter.iter().map(|(path, digest)| (path, digest)));
        for (path, digest) in pinned {
            ensure!(
                program::digest(path)? == *digest,
                "{} changed since the proxy started; restart `openmoat proxy` to use the new one",
                path.display()
            );
        }
        let out = self.run()?;
        let unix_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        parse(&out, self.lifetime, unix_now)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.path);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            // Its own process group: a read from the terminal stops it, and
            // the time limit ends it.
            command.arg0(&self.written).process_group(0);
        }
        // A folder the agent cannot change, never the proxy's own (the
        // agent's project): a tool there would read the project's `.git`,
        // tool shims and per-folder configuration, which the agent wrote.
        command
            .current_dir(fixed_dir())
            .args(&self.args)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", search_path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        command.env("USERPROFILE", &self.home);
        for name in PASSED {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
    }

    /// The program's output, within the time and size limits.
    fn run(&self) -> Result<Zeroizing<Vec<u8>>> {
        let shown = self.path.display();
        let mut child = spawn(&mut self.command()).with_context(|| format!("starting {shown}"))?;
        let mut stdout = child.stdout.take().context("no output pipe")?;
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let mut out = Zeroizing::new(Vec::new());
            let read = (&mut stdout)
                .take(MAX_OUTPUT as u64 + 1)
                .read_to_end(&mut out);
            let _ = send.send(read.map(|_| out));
        });
        let started = Instant::now();
        let out = receive.recv_timeout(self.time_limit);
        let too_much = matches!(&out, Ok(Ok(out)) if out.len() > MAX_OUTPUT);
        let finished = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if !too_much && started.elapsed() < self.time_limit => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => break None,
            }
        };
        if finished.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        ensure!(
            !too_much,
            "{shown} printed more than {} KiB",
            MAX_OUTPUT / 1024
        );
        let Some(status) = finished else {
            bail!(
                "{shown} did not finish within {}s",
                self.time_limit.as_secs()
            );
        };
        let Ok(Ok(out)) = out else {
            bail!("{shown} did not close its output within the time limit");
        };
        ensure!(status.success(), "{shown} failed ({status})");
        Ok(out)
    }
}

/// Start `command`. A file just written can be held open for writing for a
/// moment by a process another thread is starting (Linux then refuses to run
/// it, "text file busy"), so that is tried a few times.
fn spawn(command: &mut Command) -> std::io::Result<std::process::Child> {
    let mut tries = 0;
    loop {
        match command.spawn() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && tries < 10 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            other => return other,
        }
    }
}

/// The `HOME` of `id`'s program: the person's with `home: user`, else an
/// empty owner-only folder of its own under OpenMoat's state directory, which
/// the agent cannot write (`kernel-self`), so no dotfile it planted is read.
fn program_home(id: &str, home: SecretCommandHome, place: &Place<'_>) -> Result<PathBuf> {
    if home == SecretCommandHome::User {
        return Ok(PathBuf::from(place.home));
    }
    let dir = place.state.join("secret-homes").join(id);
    crate::home::create_private_dir(&dir)?;
    Ok(dir)
}

/// The folder the program runs in: the file system's root, which the agent
/// cannot change.
fn fixed_dir() -> PathBuf {
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        return PathBuf::from(root);
    }
    PathBuf::from("/")
}

/// The system's folders only: never the program's own, where a planted
/// `python3` would be found before the system's, nor the proxy's search path.
fn search_path() -> std::ffi::OsString {
    let mut dirs: Vec<PathBuf> = Vec::new();
    #[cfg(unix)]
    dirs.extend(["/usr/bin", "/bin", "/usr/sbin", "/sbin"].map(PathBuf::from));
    #[cfg(windows)]
    {
        if let Some(root) = std::env::var_os("SystemRoot") {
            let root = PathBuf::from(root);
            dirs.extend([root.join("System32"), root]);
        }
    }
    std::env::join_paths(dirs).unwrap_or_default()
}

/// The JSON form of an answer. Unknown keys are refused: a misspelt expiry
/// would otherwise be ignored.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Json {
    value: String,
    /// Seconds since the Unix epoch.
    #[serde(default)]
    expires_at: Option<u64>,
    /// Seconds from now.
    #[serde(default)]
    expires_in: Option<u64>,
}

/// `out` read as the value alone, or as `{"value": …, "expires_at": …}` or
/// `{"value": …, "expires_in": …}`; the answer's lifetime is the shortest of
/// `lifetime` and what it says. `now` is the Unix time. Errors never quote
/// `out`.
pub(super) fn parse(out: &[u8], lifetime: Duration, now: u64) -> Result<Answer> {
    let text = std::str::from_utf8(out)
        .ok()
        .context("the program's output is not UTF-8")?;
    let text = text.trim_end_matches(['\r', '\n']);
    let (value, said) = if text.trim_start().starts_with('{') {
        // A serde error can quote what it read, which may be the value.
        let json: Json = serde_json::from_str(text).ok().context(
            "the program printed JSON that is not {\"value\": …} with an optional \
             \"expires_at\" or \"expires_in\"",
        )?;
        let said = match (json.expires_at, json.expires_in) {
            (Some(_), Some(_)) => bail!("the program's JSON has both expires_at and expires_in"),
            (Some(at), None) => Some(at.saturating_sub(now)),
            (None, Some(secs)) => Some(secs),
            (None, None) => None,
        };
        (Zeroizing::new(json.value), said)
    } else {
        (Zeroizing::new(text.to_owned()), None)
    };
    ensure!(!value.is_empty(), "the program printed no value");
    ensure!(
        !value.chars().any(char::is_control),
        "the program's value contains a control character"
    );
    let lifetime = said.map_or(lifetime, |s| lifetime.min(Duration::from_secs(s)));
    ensure!(
        lifetime >= MIN_ANSWER,
        "the program's value expires in less than {}s",
        MIN_ANSWER.as_secs()
    );
    Ok(Answer { value, lifetime })
}

#[cfg(test)]
mod tests;
