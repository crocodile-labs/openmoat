//! `openmoat credential git|aws`: the local helper `openmoat run` sets up for
//! a secret with `helper:` (ADR-118). git or the AWS tools start it inside the
//! run's sandbox; it asks the run's proxy for the secret's current minted
//! value over the proxy's port and prints it the way the tool reads it.
//!
//! It needs nothing but the proxy variables the run gave the session: the
//! proxy's loopback address and the session credential, which the proxy
//! checks, so only the session's own processes are answered. It reads no
//! file, holds no value of its own and keeps nothing after it answers. Every
//! ask, handed out or refused, is a row in the audit log (`proxy-helper`).

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_proxy::helper_request;
use zeroize::Zeroizing;

use crate::cli::CredentialCommand;
use crate::exit::Code;

/// How long the proxy may take to answer.
const TIMEOUT: Duration = Duration::from_secs(30);
/// The longest answer line read.
const MAX_ANSWER: u64 = 64 * 1024;
/// The longest request git sends on standard input.
const MAX_GIT_REQUEST: u64 = 64 * 1024;
/// The variables the proxy's address and session credential are read from,
/// in order; `openmoat run` sets them all to the same URL.
const PROXY_VARS: [&str; 2] = ["HTTPS_PROXY", "https_proxy"];

pub fn run(command: &CredentialCommand) -> Result<Code> {
    let proxy = Proxy::from_env(&|name| std::env::var(name).ok())?;
    match command {
        CredentialCommand::Git { id, operation } => {
            // git also tells its helpers what it stored or rejected; a minted
            // value is never stored, so only `get` asks.
            if operation != "get" {
                return Ok(Code::Ok);
            }
            let mut input = Zeroizing::new(String::new());
            std::io::stdin()
                .take(MAX_GIT_REQUEST)
                .read_to_string(&mut input)
                .context("reading git's request")?;
            let host = git_host(&input)?;
            let given = proxy.ask("git", id, Some(&host))?;
            let out = Zeroizing::new(format!(
                "username={}\npassword={}\n",
                given.username.as_deref().unwrap_or("x-access-token"),
                given.value.as_str()
            ));
            print(&out)
        }
        CredentialCommand::Aws { id } => {
            let given = proxy.ask("aws", id, None)?;
            let out = Zeroizing::new(format!("{}\n", given.value.as_str()));
            print(&out)
        }
    }
}

fn print(out: &str) -> Result<Code> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(out.as_bytes())
        .and_then(|()| stdout.flush())
        .context("writing the credential")?;
    Ok(Code::Ok)
}

/// The host git asks for, from its request (`key=value` lines): only for
/// `https`, the one protocol the proxy carries a helper's value for.
pub fn git_host(input: &str) -> Result<String> {
    let field = |key: &str| {
        input
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .map(str::trim_end)
    };
    let protocol = field("protocol").unwrap_or("");
    ensure!(
        protocol == "https",
        "openmoat hands git a credential for https only, not `{protocol}`"
    );
    match field("host") {
        Some(host) if !host.is_empty() && !host.contains(char::is_whitespace) => {
            Ok(host.to_owned())
        }
        _ => bail!("git's request names no host"),
    }
}

/// The run's proxy, as its variables name it.
pub struct Proxy {
    addr: SocketAddr,
    basic: Zeroizing<String>,
}

/// What the proxy handed out.
pub struct Given {
    pub username: Option<String>,
    pub value: Zeroizing<String>,
}

impl Proxy {
    /// The proxy of `http://<session>:<token>@<loopback address>` in the first
    /// of [`PROXY_VARS`] `get` has. Refused for any other address: the session
    /// credential is never sent off this machine.
    pub fn from_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Self> {
        let url = PROXY_VARS
            .iter()
            .find_map(|name| get(name))
            .map(Zeroizing::new)
            .context("no HTTPS_PROXY: `openmoat credential` works inside `openmoat run` only")?;
        let rest = url
            .strip_prefix("http://")
            .context("HTTPS_PROXY is not an http:// proxy URL")?;
        let (user, addr) = rest
            .trim_end_matches('/')
            .rsplit_once('@')
            .context("HTTPS_PROXY holds no session credential")?;
        let addr: SocketAddr = addr
            .parse()
            .context("HTTPS_PROXY does not name an address and port")?;
        ensure!(
            addr.ip().is_loopback(),
            "HTTPS_PROXY names {}, not this machine's loopback: nothing is asked",
            addr.ip()
        );
        ensure!(
            user.split_once(':')
                .is_some_and(|(s, t)| !s.is_empty() && !t.is_empty()),
            "HTTPS_PROXY holds no session credential"
        );
        Ok(Self {
            addr,
            basic: Zeroizing::new(crate::secrets::base64(user.as_bytes())),
        })
    }

    /// Ask for secret `id` for `tool`, for `host` where the tool names one.
    pub fn ask(&self, tool: &str, id: &str, host: Option<&str>) -> Result<Given> {
        ensure!(
            !id.is_empty() && !id.contains(char::is_whitespace),
            "`{id}` is not a secret id"
        );
        let mut stream = TcpStream::connect_timeout(&self.addr, TIMEOUT)
            .with_context(|| format!("connecting to the proxy at {}", self.addr))?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
            .context("setting up the connection to the proxy")?;
        stream
            .write_all(&helper_request(tool, id, host, &self.basic))
            .and_then(|()| stream.flush())
            .context("asking the proxy")?;
        let mut line = Zeroizing::new(String::new());
        BufReader::new(stream.take(MAX_ANSWER))
            .read_line(&mut line)
            .context("reading the proxy's answer")?;
        answer(&line)
    }
}

/// The proxy's answer line: `OK <user or -> <value>` or `NO <reason>`.
pub fn answer(line: &str) -> Result<Given> {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some(reason) = line.strip_prefix("NO ") {
        bail!("the proxy refused: {reason}");
    }
    let Some((user, value)) = line.strip_prefix("OK ").and_then(|r| r.split_once(' ')) else {
        bail!("the proxy's answer is not one this helper reads");
    };
    ensure!(!value.is_empty(), "the proxy answered with no value");
    Ok(Given {
        username: (user != "-").then(|| user.to_owned()),
        value: Zeroizing::new(value.to_owned()),
    })
}

#[cfg(test)]
mod tests;
