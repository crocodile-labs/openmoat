//! What the agent's clients trust inside `openmoat run` (ADR-043).
//!
//! The run writes the proxy CA's certificate, and a bundle of the system's
//! roots with it, to a directory of its own in the temp directory, and points
//! the variables common TLS clients read at them, in the agent's environment
//! only. Nothing outside the run trusts the CA: no system or user trust store
//! is changed, and the files go when the run ends.
//!
//! The files are not a boundary. A command in the run may change them or the
//! variables, which changes only what it itself trusts: the proxy verifies
//! every upstream on its own, and the value is added outside the sandbox.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

use crate::home::write_private;

/// Variables read as a bundle that replaces the client's roots: they get the
/// system's roots and the CA.
const REPLACING: &[&str] = &[
    // OpenSSL and what is built on it: curl, Python's `ssl`, Ruby, Go on Linux.
    "SSL_CERT_FILE",
    // Python `requests` and pip, which otherwise use `certifi`.
    "REQUESTS_CA_BUNDLE",
    "PIP_CERT",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "CARGO_HTTP_CAINFO",
];

/// Variables read as certificates added to the client's roots: the CA alone.
const ADDING: &[&str] = &["NODE_EXTRA_CA_CERTS"];

/// Where the system keeps its roots as one PEM file, by distribution.
const SYSTEM_BUNDLES: &[&str] = &[
    // macOS, Alpine, the BSDs
    "/etc/ssl/cert.pem",
    // Debian, Ubuntu, Arch
    "/etc/ssl/certs/ca-certificates.crt",
    // Fedora, RHEL
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    // openSUSE
    "/etc/ssl/ca-bundle.pem",
];

/// The run's trust files; removed when dropped.
#[derive(Debug)]
pub struct Trust {
    dir: PathBuf,
    ca: PathBuf,
    /// `None` when no system bundle was found: then only the adding variables
    /// are set, and clients that replace their roots do not trust the CA.
    bundle: Option<PathBuf>,
}

impl Trust {
    /// Write `cert_pem` (and a bundle with the roots in the person's
    /// `SSL_CERT_FILE` or the system's) to a new directory in the temp directory.
    pub fn write(cert_pem: &str) -> Result<Self> {
        let temp =
            std::fs::canonicalize(std::env::temp_dir()).context("resolving the temp directory")?;
        let dir = temp.join(format!("moat-run-{}-ca", std::process::id()));
        let ca = dir.join("ca.pem");
        write_private(&ca, cert_pem.as_bytes())?;
        let mut trust = Self {
            dir,
            ca,
            bundle: None,
        };
        let person = std::env::var_os("SSL_CERT_FILE").map(PathBuf::from);
        let base = person
            .into_iter()
            .chain(SYSTEM_BUNDLES.iter().map(PathBuf::from))
            .find_map(|path| std::fs::read_to_string(path).ok());
        if let Some(mut roots) = base {
            if !roots.ends_with('\n') {
                roots.push('\n');
            }
            roots.push_str(cert_pem);
            let bundle = trust.dir.join("bundle.pem");
            write_private(&bundle, roots.as_bytes())?;
            trust.bundle = Some(bundle);
        }
        Ok(trust)
    }

    /// The directory the files are in, which a sandbox that hides the temp
    /// directory (`openmoat run --isolate`) binds in read-only.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The variables the agent gets, and the file each names.
    pub fn env(&self) -> Vec<(&'static str, &Path)> {
        let mut vars: Vec<(&'static str, &Path)> =
            ADDING.iter().map(|v| (*v, self.ca.as_path())).collect();
        if let Some(bundle) = &self.bundle {
            vars.extend(REPLACING.iter().map(|v| (*v, bundle.as_path())));
        }
        vars
    }

    /// Said before the agent starts, when clients that replace their roots
    /// were not given the CA.
    pub fn notice(&self) -> Option<String> {
        self.bundle.is_none().then(|| {
            format!(
                "moat run: no system root bundle found ({}), so only Node.js clients \
                 (`NODE_EXTRA_CA_CERTS`) trust the proxy CA; others refuse the hosts \
                 `tls: terminate` names",
                SYSTEM_BUNDLES.join(", ")
            )
        })
    }
}

impl Drop for Trust {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.ca);
        if let Some(bundle) = &self.bundle {
            let _ = std::fs::remove_file(bundle);
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}
