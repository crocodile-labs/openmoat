//! The files of remote approval under `~/.moat/remote` (ADR-078), all
//! owner-only and all denied to agents by `kernel-self`:
//!
//! - `approval.key`: the key requests, answers, buttons and settings are signed with;
//! - `settings.json`: the signed [`Settings`](super::Settings);
//! - `<channel>/credential`: the channel's secret ([`ChannelFiles`]);
//! - `<channel>/settings.json`: the channel's signed
//!   [`ChannelSettings`](super::settings::ChannelSettings);
//! - `requests/<id>.json`: calls waiting for an answer, written by the guard;
//! - `answers/<id>.json`: answers, written by `openmoat approvals listen`;
//! - `used/<id>`: the replay store, one empty file per approval used.
//!
//! A channel's folder is named by its registered [`Spec`], never by text
//! read from a file, so no setting can point a path elsewhere.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use super::answer::Answer;
use super::channel::{Credential, Spec};
use super::request::Request;
use crate::home::{Home, write_private, write_private_new};

/// The folder under the state directory.
pub const DIR: &str = "remote";
const KEY_FILE: &str = "approval.key";
const SETTINGS_FILE: &str = "settings.json";
const CREDENTIAL_FILE: &str = "credential";
const REQUESTS: &str = "requests";
const ANSWERS: &str = "answers";
const USED: &str = "used";
/// How long a used marker is kept: far longer than any request lives.
const USED_KEPT_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

/// One channel's folder, `~/.moat/remote/<channel>/`, owner-only.
#[derive(Debug, Clone)]
pub struct ChannelFiles {
    dir: PathBuf,
}

impl ChannelFiles {
    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where the channel's secret is kept.
    pub fn credential_path(&self) -> PathBuf {
        self.dir.join(CREDENTIAL_FILE)
    }

    /// Where the channel's signed settings are kept.
    pub fn settings_path(&self) -> PathBuf {
        self.dir.join(SETTINGS_FILE)
    }

    /// The credential, refused when others may read it (`key_file::read`) or
    /// when it is not shaped as `spec`'s.
    pub fn read_credential(&self, spec: &Spec) -> Result<Credential> {
        let path = self.credential_path();
        let text = crate::key_file::read(&path)?;
        let credential = Credential::new(text.trim().to_owned());
        if !(spec.valid_credential)(&credential) {
            bail!(
                "{} does not hold a {} credential",
                path.display(),
                spec.title
            );
        }
        Ok(credential)
    }

    /// Write `credential`, owner-only.
    pub fn put_credential(&self, credential: &Credential) -> Result<()> {
        write_private(&self.credential_path(), credential.as_bytes())
    }

    /// Remove the folder; whether there was one.
    pub fn remove(&self) -> Result<bool> {
        match fs::remove_dir_all(&self.dir) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e).with_context(|| format!("removing {}", self.dir.display())),
        }
    }
}

/// Whether `id` is a request id as OpenMoat makes them (32 hex digits), so it
/// can name a file.
pub fn plain_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Store {
    pub fn of(home: &Home) -> Self {
        Self::at(home.root().join(DIR))
    }

    pub fn at(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn key_path(&self) -> PathBuf {
        self.dir.join(KEY_FILE)
    }

    pub fn settings_path(&self) -> PathBuf {
        self.dir.join(SETTINGS_FILE)
    }

    /// The files of the registered channel `spec`.
    pub fn channel(&self, spec: &Spec) -> ChannelFiles {
        ChannelFiles {
            dir: self.dir.join(spec.name),
        }
    }

    /// Whether a channel is set up: the settings file exists.
    pub fn connected(&self) -> bool {
        self.settings_path().exists()
    }

    fn request_path(&self, id: &str) -> PathBuf {
        self.dir.join(REQUESTS).join(format!("{id}.json"))
    }

    fn answer_path(&self, id: &str) -> PathBuf {
        self.dir.join(ANSWERS).join(format!("{id}.json"))
    }

    /// Every request on file whose name is a request id; a file that cannot
    /// be read as one is returned as `Err` with its id, for the listener to
    /// remove and record.
    pub fn requests(&self) -> Result<Vec<Result<Request, String>>> {
        let dir = self.dir.join(REQUESTS);
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
            let name = entry.file_name();
            let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
                continue;
            };
            if !plain_id(id) {
                continue;
            }
            let read = fs::read_to_string(entry.path())
                .ok()
                .and_then(|text| serde_json::from_str::<Request>(&text).ok())
                .filter(|r| r.id == id);
            out.push(read.ok_or_else(|| id.to_owned()));
        }
        Ok(out)
    }

    /// The request `id`, when it is on file and reads as one.
    pub fn request(&self, id: &str) -> Option<Request> {
        if !plain_id(id) {
            return None;
        }
        let text = fs::read_to_string(self.request_path(id)).ok()?;
        serde_json::from_str::<Request>(&text)
            .ok()
            .filter(|r| r.id == id)
    }

    pub fn put_request(&self, request: &Request) -> Result<()> {
        let text = serde_json::to_vec(request).context("encoding a request")?;
        write_private(&self.request_path(&request.id), &text)
    }

    /// The answer to request `id`, when there is one that reads as one.
    pub fn answer(&self, id: &str) -> Option<Answer> {
        if !plain_id(id) {
            return None;
        }
        let text = fs::read_to_string(self.answer_path(id)).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Write `answer` unless its request has one already; whether it was written.
    pub fn put_answer(&self, answer: &Answer) -> Result<bool> {
        let text = serde_json::to_vec(answer).context("encoding an answer")?;
        write_private_new(&self.answer_path(&answer.id), &text)
    }

    /// Mark approval `id` used; `false` when it was already, by this or
    /// another process. Of two racing callers exactly one gets `true`.
    pub fn use_once(&self, id: &str) -> Result<bool> {
        write_private_new(&self.dir.join(USED).join(id), b"")
    }

    /// Whether approval `id` was used.
    pub fn used(&self, id: &str) -> bool {
        self.dir.join(USED).join(id).exists()
    }

    /// Remove the answer to request `id`.
    pub fn forget_answer(&self, id: &str) {
        let _ = fs::remove_file(self.answer_path(id));
    }

    /// Remove request `id` and its answer.
    pub fn forget(&self, id: &str) {
        let _ = fs::remove_file(self.request_path(id));
        let _ = fs::remove_file(self.answer_path(id));
    }

    /// Remove used markers older than a day, whose requests expired long ago.
    pub fn sweep_used(&self, now_ms: i64) {
        let Ok(entries) = fs::read_dir(self.dir.join(USED)) else {
            return;
        };
        for entry in entries.flatten() {
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|d| i64::try_from(d.as_millis()).ok())
                .is_some_and(|ms| now_ms - ms > USED_KEPT_MS);
            if old {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}
