//! An approval the guard used for a call it then refused (ADR-078 Decision
//! 4): the approval is gone, since it was used under the replay store before
//! the call's row was written, and the call is denied, since a call that
//! cannot be recorded is not allowed. The guard leaves a signed note; the
//! listener tells the approver "approved, but the call was refused" and
//! records it, so the approval never vanishes without a word.

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use super::request::Request;
use super::store::Store;
use super::{hex, verify_hex};
use crate::proxy_session::Key;

/// Signed in front of every refusal note.
const REFUSED_DOMAIN: &[u8] = b"openmoat-remote-refused-v1\n";
/// The most characters of the reason an approver is sent.
const REASON_MAX: usize = 300;

/// The note the guard leaves for the listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refused {
    /// The request the approval was for, as signed when it was sent.
    pub request: Request,
    /// Why the call was refused, redacted and cleaned.
    pub reason: String,
    /// HMAC of the other fields under the approval key, hex.
    #[serde(default)]
    pub mac: String,
}

impl Refused {
    fn signed_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.mac.clear();
        serde_json::to_vec(&unsigned).context("encoding a refusal")
    }

    fn signed(key: &Key, request: Request, reason: String) -> Result<Self> {
        let mut note = Self {
            request,
            reason,
            mac: String::new(),
        };
        note.mac = hex(&key.mac(REFUSED_DOMAIN, &note.signed_bytes()?));
        Ok(note)
    }

    /// Whether `key` signed the note and its request.
    pub fn verified(&self, key: &Key) -> bool {
        self.request.verified(key)
            && self
                .signed_bytes()
                .is_ok_and(|bytes| verify_hex(&self.mac, &key.mac(REFUSED_DOMAIN, &bytes)))
    }
}

/// A remote approval the guard used on this call.
pub struct Approved {
    store: Store,
    request: Request,
}

impl Approved {
    pub fn new(store: &Store, request: Request) -> Self {
        Self {
            store: Store::at(store.dir().to_path_buf()),
            request,
        }
    }

    /// The call was refused after its approval was used, because of `why`:
    /// leave the note for the listener, and return the reason line the deny
    /// carries. The call stays denied whatever happens here.
    pub fn refused(self, why: &str) -> String {
        let why = crate::render::truncate(
            &crate::render::clean(&openmoat_audit::redact(why)),
            REASON_MAX,
        );
        let code = self.request.code().to_owned();
        let noted = Key::load(&self.store.key_path())
            .and_then(|key| Refused::signed(&key, self.request, why.clone()))
            .and_then(|note| self.store.put_refused(&note));
        match noted {
            Ok(()) => format!(
                "request {code} was approved, but the call was refused: {why}; the approval is \
                 used, and the approver is told"
            ),
            Err(error) => format!(
                "request {code} was approved, but the call was refused: {why}; the approval is \
                 used, and the approver could not be told: {error:#}"
            ),
        }
    }
}
