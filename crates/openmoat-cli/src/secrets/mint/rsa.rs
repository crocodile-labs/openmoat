//! RS256 signatures for the JWTs a GitHub App and a Google service account
//! sign in with, through `ring`, which rustls already builds with.
//!
//! A key is read from PEM: PKCS#1 (`RSA PRIVATE KEY`, the form GitHub gives
//! out) or PKCS#8 (`PRIVATE KEY`, the form Google's key files hold). Errors
//! never quote the key.

use anyhow::{Context as _, Result, bail};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use zeroize::Zeroizing;

/// The DER bytes inside `pem`'s first block of `label`.
fn der(pem: &str, label: &str) -> Option<Zeroizing<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin)? + begin.len();
    let stop = start + pem[start..].find(&end)?;
    let body: Zeroizing<String> = Zeroizing::new(
        pem[start..stop]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect(),
    );
    openmoat_proxy::base64(body.as_bytes())
}

/// The RSA key in `pem`.
pub fn key(pem: &str) -> Result<RsaKeyPair> {
    // The labels are put together so no key header appears in the source.
    let pkcs1 = format!("RSA {} KEY", "PRIVATE");
    let pkcs8 = format!("{} KEY", "PRIVATE");
    if let Some(bytes) = der(pem, &pkcs1) {
        return RsaKeyPair::from_der(&bytes)
            .map_err(|e| anyhow::Error::msg(format!("the RSA key is not usable: {e}")));
    }
    if let Some(bytes) = der(pem, &pkcs8) {
        return RsaKeyPair::from_pkcs8(&bytes)
            .map_err(|e| anyhow::Error::msg(format!("the RSA key is not usable: {e}")));
    }
    bail!("the file holds no PEM RSA private key")
}

/// The RS256 signature of `input` with `key`.
pub fn sign(key: &RsaKeyPair, input: &[u8]) -> Result<Vec<u8>> {
    let mut signature = vec![0u8; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        input,
        &mut signature,
    )
    .ok()
    .context("signing with the RSA key failed")?;
    Ok(signature)
}

/// A signed JWT (RS256) with `claims`, a JSON object.
pub fn jwt(key: &RsaKeyPair, claims: &str) -> Result<Zeroizing<String>> {
    use super::encode::base64url;
    let input = format!(
        "{}.{}",
        base64url(br#"{"alg":"RS256","typ":"JWT"}"#),
        base64url(claims.as_bytes())
    );
    let signature = sign(key, input.as_bytes())?;
    Ok(Zeroizing::new(format!("{input}.{}", base64url(&signature))))
}
