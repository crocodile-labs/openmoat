//! Session credentials for the standalone `openmoat proxy` (ADR-044).
//!
//! `openmoat proxy` runs for days and serves every session of the host
//! sandboxes that send their commands' traffic to it, so it cannot hold a list
//! of credentials made before it started, as `openmoat run`'s proxy does
//! (ADR-027). Instead each credential is signed: the agent's session-start
//! hook ([`issue`]) and the proxy ([`Verifier`]) share one random key in
//! OpenMoat's home ([`KEY_FILE`]), which no sandboxed command may read
//! (`kernel-self`).
//!
//! A credential is the `Basic` pair `user:password` of a proxy URL:
//!
//! - `user` is `v1.<host>.<expires>.<session>`: the agent host's id, the Unix
//!   time in seconds after which it is refused, and the host's own session id,
//!   which the proxy records every row under;
//! - `password` is the lowercase hex HMAC-SHA-256 of `user` under the key, with
//!   [`DOMAIN`] in front so the key signs nothing else.
//!
//! Nothing about a credential is stored: the proxy recomputes the signature,
//! compares it in constant time, and checks the expiry.

mod hmac;

use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use openmoat_hosts::Host;
use openmoat_proxy::constant_time_eq;
use zeroize::Zeroizing;

use crate::home::Home;

/// The key file in OpenMoat's home: 64 hex characters (256 bits).
pub const KEY_FILE: &str = "proxy.key";

/// How long a credential is accepted after it is issued. Claude Code issues a
/// new one at every start, resume, `/clear` and compaction of a session.
pub const TTL: Duration = Duration::from_hours(24);

/// Signed in front of every `user`, so the key's signatures mean nothing else.
const DOMAIN: &[u8] = b"openmoat-proxy-session-v1\n";

/// The version prefix of `user`.
const VERSION: &str = "v1";

/// Longest session id a credential carries.
const MAX_SESSION_LEN: usize = 128;

/// Slack on an expiry further ahead than [`TTL`] (clocks of the hook and the
/// proxy are the same machine's, so this only covers a second boundary).
const SKEW_S: u64 = 60;

/// The 256-bit key credentials are signed with; zeroed on drop, never printed.
pub struct Key(Zeroizing<[u8; 32]>);

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

impl Key {
    /// The key of `home`, made first when there is none. Two processes making
    /// it at once end with the same key: only the first file is kept.
    pub fn load_or_create(home: &Home) -> Result<Self> {
        let path = key_path(home);
        if !path.exists() {
            let mut raw = Zeroizing::new([0u8; 32]);
            getrandom::fill(raw.as_mut_slice())
                .map_err(|e| anyhow::Error::msg(e.to_string()))
                .context("reading random bytes for the proxy session key")?;
            let mut text = Zeroizing::new(String::with_capacity(65));
            hex_into(&mut text, raw.as_slice());
            text.push('\n');
            crate::home::write_private_new(&path, text.as_bytes())?;
        }
        Self::load(&path)
    }

    /// The key in `path`; an error when it is missing or malformed.
    pub fn load(path: &Path) -> Result<Self> {
        let text = Zeroizing::new(
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
        );
        let text = text.trim();
        let mut key = Zeroizing::new([0u8; 32]);
        if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("{} is not 64 hex characters", path.display());
        }
        for (i, pair) in text.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(pair).context("key is not ASCII")?;
            key[i] = u8::from_str_radix(pair, 16).context("key is not hex")?;
        }
        Ok(Self(key))
    }

    /// The signature of `user`, as lowercase hex.
    fn sign(&self, user: &str) -> Zeroizing<String> {
        let mut message = Vec::with_capacity(DOMAIN.len() + user.len());
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(user.as_bytes());
        let mac = Zeroizing::new(hmac::sha256(self.0.as_slice(), &message));
        let mut out = Zeroizing::new(String::with_capacity(64));
        hex_into(&mut out, mac.as_slice());
        out
    }
}

/// Where the key of `home` is.
pub fn key_path(home: &Home) -> PathBuf {
    home.root().join(KEY_FILE)
}

/// One session's credential; zeroed on drop, never printed.
pub struct Issued {
    user: String,
    password: Zeroizing<String>,
    /// When it stops being accepted (Unix seconds).
    pub expires: u64,
}

impl fmt::Debug for Issued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issued")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl Issued {
    /// `http://<user>:<password>@127.0.0.1:<port>`: what the session's
    /// commands get as their proxy. Needs no escaping in a URL or a shell.
    pub fn proxy_url(&self, port: u16) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "http://{}:{}@127.0.0.1:{port}",
            self.user,
            self.password.as_str()
        ))
    }
}

/// Characters a session id may hold: none needs escaping in a URL's userinfo,
/// in a `Basic` credential or in a shell word.
fn plain_session(session: &str) -> bool {
    !session.is_empty()
        && session.len() <= MAX_SESSION_LEN
        && session
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The credential of `host`'s session `session`, issued at `now` (Unix seconds).
pub fn issue(key: &Key, host: Host, session: &str, now: u64) -> Result<Issued> {
    if !plain_session(session) || openmoat_hosts::is_unknown_session(session) {
        bail!(
            "the session id {session:?} cannot carry a proxy credential: it must be 1 to 128 \
             ASCII letters, digits, `.`, `_` or `-`"
        );
    }
    let expires = now.saturating_add(TTL.as_secs());
    let user = format!("{VERSION}.{}.{expires}.{session}", host.id());
    let password = key.sign(&user);
    Ok(Issued {
        user,
        password,
        expires,
    })
}

/// The session `user` and `password` authenticate at `now` (Unix seconds), or
/// `None`: a malformed `user`, an unknown host, an expired credential, one
/// that claims to last longer than [`TTL`], or a wrong signature.
pub fn verify(key: &Key, user: &[u8], password: &[u8], now: u64) -> Option<String> {
    let user = std::str::from_utf8(user).ok()?;
    let mut parts = user.splitn(4, '.');
    let (version, host, expires, session) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if version != VERSION || host.parse::<Host>().is_err() || !plain_session(session) {
        return None;
    }
    let expires: u64 = expires.parse().ok()?;
    // The signature is checked whatever the expiry says, so the time taken
    // does not tell an expired credential from a forged one.
    let expected = key.sign(user);
    let signed = constant_time_eq(expected.as_bytes(), password);
    let current = now < expires && expires <= now.saturating_add(TTL.as_secs() + SKEW_S);
    (signed && current).then(|| session.to_owned())
}

/// Seconds since the Unix epoch.
pub fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The key file as last read: its length and modification time.
type Stamp = (u64, Option<SystemTime>);

fn stamp(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.len(), meta.modified().ok()))
}

/// How often the proxy looks at the key file for a change: a replaced key
/// revokes every credential within this long.
pub const KEY_RECHECK: Duration = Duration::from_secs(1);

/// The key as last read: when the file was last looked at, what it looked
/// like, and the key, `None` while the file is missing or unreadable.
struct Loaded {
    checked: Instant,
    stamp: Option<Stamp>,
    key: Option<Key>,
}

/// The proxy's check of issued credentials. The key file is looked at at most
/// every [`KEY_RECHECK`] and read again when it changed, so a person who
/// replaces it revokes every credential within a second, without restarting
/// the proxy; while it is missing or unreadable, no credential is accepted.
pub struct Verifier {
    path: PathBuf,
    recheck: Duration,
    loaded: Mutex<Loaded>,
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    /// The verifier of `home`'s credentials; makes the key when there is none.
    pub fn open(home: &Home) -> Result<Self> {
        Self::open_with(home, KEY_RECHECK)
    }

    /// [`Self::open`], looking at the key file every `recheck`.
    fn open_with(home: &Home, recheck: Duration) -> Result<Self> {
        let key = Key::load_or_create(home)?;
        let path = key_path(home);
        Ok(Self {
            loaded: Mutex::new(Loaded {
                checked: Instant::now(),
                stamp: stamp(&path),
                key: Some(key),
            }),
            recheck,
            path,
        })
    }
}

impl openmoat_proxy::Verify for Verifier {
    fn verify(&self, user: &[u8], password: &[u8]) -> Option<String> {
        let now = now_s();
        let mut loaded = self.loaded.lock().unwrap_or_else(PoisonError::into_inner);
        if loaded.checked.elapsed() >= self.recheck {
            let current = stamp(&self.path);
            if current != loaded.stamp {
                loaded.key = current.and_then(|_| Key::load(&self.path).ok());
                loaded.stamp = current;
            }
            loaded.checked = Instant::now();
        }
        verify(loaded.key.as_ref()?, user, password, now)
    }
}

/// Append `bytes` to `out` as lowercase hex; `out` has the room already, so
/// nothing secret is left in a buffer it grew out of.
fn hex_into(out: &mut String, bytes: &[u8]) {
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
}

#[cfg(test)]
mod tests;
