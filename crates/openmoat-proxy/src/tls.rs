//! TLS termination for brokered secrets (ADR-043).
//!
//! For a host whose secret says `tls: terminate`, `openmoat run`'s proxy ends
//! the agent's TLS itself, with a leaf for the host that its own certificate
//! authority signs, reads and checks each request in the clear, puts the value
//! in, and opens its own TLS to the host, verified against the system's roots
//! with the same server name. The agent trusts that CA only inside the run.
//!
//! - The CA ([`new_ca`]) is name-constrained to the terminated hosts, so it
//!   cannot vouch for any other name, and is made by a person (`openmoat proxy
//!   ca init`); the CLI keeps it where no sandbox lets the agent read and pins
//!   it in the policy lock.
//! - [`Tls::new`] checks, for each host, that a leaf the CA signs verifies for
//!   that host and today, the way a client will check it.
//! - Only `http/1.1` is offered to the agent, so a client that speaks HTTP/2
//!   alone fails the handshake instead of sending what the proxy cannot read.

mod ca;
mod date;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier as _;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use zeroize::Zeroizing;

pub(crate) use self::date::Day;

/// Rule id of a terminated tunnel refused for its TLS: a handshake that
/// failed on either side, or an upstream certificate that did not verify.
pub const RULE_TLS: &str = "proxy-tls";

/// The one application protocol the proxy speaks inside a terminated tunnel.
const HTTP_1_1: &[u8] = b"http/1.1";

/// Why a CA cannot be made or used, or a terminated connection set up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// No host to make a CA for.
    #[error("no secret sets `tls: terminate`, so there is no host to make a CA for")]
    NoHosts,
    /// The clock reads a day no certificate can be written for.
    #[error("the system clock is before 1970 or past the year 9000")]
    Clock,
    /// The CA key file holds no ECDSA P-256 key.
    #[error("the CA key is not the ECDSA P-256 key `openmoat proxy ca init` writes")]
    Key,
    /// The CA certificate file holds no certificate.
    #[error("the CA certificate file holds no PEM certificate")]
    Cert,
    /// A host no certificate can name.
    #[error("{0} is not a name a certificate can carry")]
    Host(String),
    /// A leaf the CA signs for the host does not verify: another key, a host
    /// outside its name constraints, or a CA that expired.
    #[error("the OpenMoat proxy CA does not cover {host} today ({why})")]
    Uncovered {
        /// The host.
        host: String,
        /// What the verification said.
        why: String,
    },
    /// No root certificate to verify upstream hosts with.
    #[error("no trusted root certificates found on this system to verify upstream hosts")]
    NoRoots,
    /// rcgen could not make a certificate.
    #[error("making a certificate: {0}")]
    Certificate(String),
    /// rustls refused a configuration.
    #[error("TLS configuration: {0}")]
    Config(String),
}

impl TlsError {
    fn rcgen(e: &rcgen::Error) -> Self {
        Self::Certificate(e.to_string())
    }

    fn config(e: &rustls::Error) -> Self {
        Self::Config(e.to_string())
    }
}

/// A new CA, as the files `openmoat proxy ca init` writes. The key is zeroed
/// when dropped and left out of `Debug`.
pub struct CaFiles {
    /// The certificate, PEM: what clients inside `openmoat run` trust.
    pub cert_pem: String,
    /// The private key, PKCS #8 PEM: only the proxy reads it.
    pub key_pem: Zeroizing<String>,
}

impl std::fmt::Debug for CaFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaFiles").finish_non_exhaustive()
    }
}

/// Make a CA that may sign for `hosts` (and names under them) alone, valid
/// from yesterday for a year.
pub fn new_ca(hosts: &[String]) -> Result<CaFiles, TlsError> {
    let made = ca::generate(hosts, Day::today()?)?;
    Ok(CaFiles {
        cert_pem: made.cert,
        key_pem: made.key,
    })
}

/// How long a CA [`new_ca`] makes is valid, in days.
pub const CA_VALID_DAYS: i64 = ca::CA_DAYS;

/// What upstream certificates are verified against.
#[derive(Debug, Clone)]
pub enum Roots {
    /// The operating system's trust store (`rustls-native-certs`).
    System,
    /// These PEM certificates alone: tests, or a private CA.
    Pem(String),
}

/// One proxy run's termination: the CA's signer, the leaves made from it and
/// the configuration upstream connections use.
pub struct Tls {
    provider: Arc<CryptoProvider>,
    signer: ca::Signer,
    ca: CertificateDer<'static>,
    upstream: Arc<ClientConfig>,
    /// Per host, the server configuration holding today's leaf.
    leaves: Mutex<HashMap<String, (Day, Arc<ServerConfig>)>>,
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls").finish_non_exhaustive()
    }
}

impl Tls {
    /// Termination with the CA in `cert_pem` and `key_pem`, verifying
    /// upstreams against `roots`. Refused unless the key signs leaves that
    /// verify, today, for every one of `hosts`.
    pub fn new(
        cert_pem: &str,
        key_pem: &str,
        roots: &Roots,
        hosts: &[String],
    ) -> Result<Self, TlsError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let ca = CertificateDer::from_pem_slice(cert_pem.as_bytes()).map_err(|_| TlsError::Cert)?;
        let tls = Self {
            signer: ca::Signer::new(key_pem)?,
            upstream: Arc::new(upstream_config(roots, &provider)?),
            provider,
            ca,
            leaves: Mutex::new(HashMap::new()),
        };
        for host in hosts {
            tls.check(host)?;
        }
        Ok(tls)
    }

    /// Whether a leaf for `host` verifies against the CA alone today, the
    /// check a client makes: chain, validity and name constraints.
    fn check(&self, host: &str) -> Result<(), TlsError> {
        let uncovered = |why: String| TlsError::Uncovered {
            host: host.to_owned(),
            why,
        };
        let mut roots = RootCertStore::empty();
        roots
            .add(self.ca.clone())
            .map_err(|e| uncovered(e.to_string()))?;
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                .build()
                .map_err(|e| uncovered(e.to_string()))?;
        let (leaf, _) = self.signer.leaf(host, Day::today()?)?;
        let name = server_name(host)?;
        verifier
            .verify_server_cert(
                &CertificateDer::from(leaf),
                &[],
                &name,
                &[],
                UnixTime::now(),
            )
            .map(drop)
            .map_err(|e| uncovered(e.to_string()))
    }

    /// A server connection presenting today's leaf for `host`, offering
    /// `http/1.1` only.
    pub(crate) fn accept(&self, host: &str) -> Result<ServerConnection, TlsError> {
        let config = self.server_config(host)?;
        ServerConnection::new(config).map_err(|e| TlsError::config(&e))
    }

    /// A client connection to `host`, verified against the upstream roots
    /// with `host` as the server name.
    pub(crate) fn connect(&self, host: &str) -> Result<ClientConnection, TlsError> {
        ClientConnection::new(self.upstream.clone(), server_name(host)?)
            .map_err(|e| TlsError::config(&e))
    }

    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, TlsError> {
        let today = Day::today()?;
        // A poisoned cache only lost leaves; they are made again.
        let mut leaves = self
            .leaves
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((day, config)) = leaves.get(host)
            && *day == today
        {
            return Ok(config.clone());
        }
        let (cert, key) = self.signer.leaf(host, today)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()));
        let certified =
            CertifiedKey::from_der(vec![CertificateDer::from(cert)], key, &self.provider)
                .map_err(|e| TlsError::config(&e))?;
        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsError::config(&e))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
        config.alpn_protocols = vec![HTTP_1_1.to_vec()];
        let config = Arc::new(config);
        leaves.insert(host.to_owned(), (today, config.clone()));
        Ok(config)
    }
}

fn server_name(host: &str) -> Result<ServerName<'static>, TlsError> {
    ServerName::try_from(host.to_owned()).map_err(|_| TlsError::Host(host.to_owned()))
}

fn upstream_config(
    roots: &Roots,
    provider: &Arc<CryptoProvider>,
) -> Result<ClientConfig, TlsError> {
    let mut store = RootCertStore::empty();
    match roots {
        Roots::System => {
            // Certificates the store holds that rustls cannot use are skipped,
            // as browsers skip them.
            let found = rustls_native_certs::load_native_certs();
            store.add_parsable_certificates(found.certs);
        }
        Roots::Pem(pem) => {
            let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| TlsError::Cert)?;
            store.add_parsable_certificates(certs);
        }
    }
    if store.is_empty() {
        return Err(TlsError::NoRoots);
    }
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::config(&e))?
        .with_root_certificates(store)
        .with_no_client_auth();
    config.alpn_protocols = vec![HTTP_1_1.to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests;
