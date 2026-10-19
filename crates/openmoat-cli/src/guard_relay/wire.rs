//! The bytes on the wire between a sandboxed `moat guard` and `moat run`.
//!
//! A request is [`REQUEST_MAGIC`] and six fields, a reply [`REPLY_MAGIC`] and
//! four. Each field is its length as four big-endian bytes, then the bytes.
//! Every field has a limit, checked before anything is allocated for it, so a
//! peer cannot make the other side read or hold more than that.

use std::io::{Read, Write};

use anyhow::{Context as _, Result, bail, ensure};
use zeroize::Zeroizing;

use super::MAX_PAYLOAD_BYTES;

/// What a request starts with; no HTTP method does, so the proxy's port can
/// carry it (`openmoat_proxy::LocalService`).
pub const REQUEST_MAGIC: &[u8] = b"MOAT-GUARD/1\n";
/// What a reply starts with.
pub const REPLY_MAGIC: &[u8] = b"MOAT-GUARD-REPLY/1\n";
/// Hex characters of a request's nonce, which the reply must repeat.
pub const NONCE_LEN: usize = 32;
/// The most a reply's standard output or error may hold.
pub const MAX_OUTPUT: usize = 4 * 1024 * 1024;

const MAX_TOKEN: usize = 256;
const MAX_HOST: usize = 64;
const MAX_CWD: usize = 4096;
/// Bit of the flags field: the Continue CLI runs the hook (`CONTINUE_ENV`).
const FLAG_CONTINUE: u8 = 1;

/// One hook call, as the sandboxed guard read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The run's token, from `MOAT_GUARD_TOKEN`.
    pub token: Zeroizing<Vec<u8>>,
    /// Random per call; the reply must carry the same.
    pub nonce: String,
    /// The `--host` the hook was installed with.
    pub host: String,
    /// The guard's working directory: where a payload without one ran.
    pub cwd: String,
    /// Whether the Continue CLI started the hook.
    pub continue_cli: bool,
    /// The hook payload, unchanged.
    pub payload: String,
}

/// What the guard outside the sandbox answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The request's nonce.
    pub nonce: String,
    /// The guard's exit code: 0 or 2.
    pub code: u8,
    /// Its standard output, the host's response.
    pub stdout: Vec<u8>,
    /// Its standard error.
    pub stderr: Vec<u8>,
}

impl Request {
    pub fn write_to(&self, out: &mut impl Write) -> Result<()> {
        let flags = if self.continue_cli { FLAG_CONTINUE } else { 0 };
        let mut frame = Zeroizing::new(REQUEST_MAGIC.to_vec());
        for field in [
            &self.token[..],
            self.nonce.as_bytes(),
            self.host.as_bytes(),
            self.cwd.as_bytes(),
            &[flags],
            self.payload.as_bytes(),
        ] {
            push_field(&mut frame, field)?;
        }
        out.write_all(&frame)?;
        Ok(out.flush()?)
    }

    /// A request, its magic included. Refused when a field is over its limit,
    /// the nonce is not [`NONCE_LEN`] hex characters, or text is not UTF-8.
    pub fn read_from(input: &mut impl Read) -> Result<Self> {
        expect_magic(input, REQUEST_MAGIC).context("not a guard request")?;
        let token = Zeroizing::new(field(input, MAX_TOKEN, "token")?);
        let nonce = nonce(field(input, NONCE_LEN, "nonce")?)?;
        let host = text(field(input, MAX_HOST, "host")?, "host")?;
        let cwd = text(
            field(input, MAX_CWD, "working directory")?,
            "working directory",
        )?;
        let flags = field(input, 1, "flags")?;
        ensure!(flags.len() == 1, "the flags field is not one byte");
        let payload = field(input, payload_limit(), "payload").context(
            "the tool call is larger than OpenMoat reads, so it is refused; ask the agent to \
             write the file in smaller parts",
        )?;
        Ok(Self {
            token,
            nonce,
            host,
            cwd,
            continue_cli: flags[0] & FLAG_CONTINUE != 0,
            payload: text(payload, "payload")?,
        })
    }
}

impl Reply {
    pub fn write_to(&self, out: &mut impl Write) -> Result<()> {
        let mut frame = REPLY_MAGIC.to_vec();
        for field in [
            self.nonce.as_bytes(),
            &[self.code],
            &self.stdout[..],
            &self.stderr[..],
        ] {
            push_field(&mut frame, field)?;
        }
        out.write_all(&frame)?;
        Ok(out.flush()?)
    }

    /// A reply to the request with `nonce`. Refused when it is malformed, a
    /// field is over its limit, it names another nonce, or its exit code is
    /// neither 0 nor 2: whatever produced it was not this run's guard.
    pub fn read_from(input: &mut impl Read, expected_nonce: &str) -> Result<Self> {
        expect_magic(input, REPLY_MAGIC).context("not a guard reply")?;
        let nonce = nonce(field(input, NONCE_LEN, "nonce")?)?;
        ensure!(nonce == expected_nonce, "the reply answers another request");
        let code = field(input, 1, "exit code")?;
        let [code @ (0 | 2)] = code[..] else {
            bail!("the reply's exit code is neither 0 nor 2");
        };
        let stdout = field(input, MAX_OUTPUT, "standard output")?;
        let stderr = field(input, MAX_OUTPUT, "standard error")?;
        Ok(Self {
            nonce,
            code,
            stdout,
            stderr,
        })
    }
}

/// The payload limit `moat guard` applies to standard input.
fn payload_limit() -> usize {
    usize::try_from(MAX_PAYLOAD_BYTES).unwrap_or(usize::MAX)
}

fn push_field(frame: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).context("a field longer than 4 GiB")?;
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(bytes);
    Ok(())
}

fn expect_magic(input: &mut impl Read, magic: &[u8]) -> Result<()> {
    let mut seen = vec![0u8; magic.len()];
    input.read_exact(&mut seen)?;
    ensure!(seen == magic, "wrong start");
    Ok(())
}

/// One field of at most `max` bytes; its length is checked before it is read.
fn field(input: &mut impl Read, max: usize, what: &str) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    input
        .read_exact(&mut len)
        .with_context(|| format!("reading the {what} field"))?;
    let len = usize::try_from(u32::from_be_bytes(len)).unwrap_or(usize::MAX);
    if len > max {
        bail!("the {what} field holds {len} bytes, more than the {max} allowed");
    }
    let mut bytes = vec![0u8; len];
    input
        .read_exact(&mut bytes)
        .with_context(|| format!("reading the {what} field"))?;
    Ok(bytes)
}

fn nonce(bytes: Vec<u8>) -> Result<String> {
    ensure!(
        bytes.len() == NONCE_LEN && bytes.iter().all(u8::is_ascii_hexdigit),
        "the nonce is not {NONCE_LEN} hex characters"
    );
    text(bytes, "nonce")
}

fn text(bytes: Vec<u8>, what: &str) -> Result<String> {
    String::from_utf8(bytes).with_context(|| format!("the {what} field is not UTF-8"))
}
