//! The certificate authority and the leaves it signs (ADR-043).
//!
//! The CA is ECDSA P-256, may sign leaves only (path length 0), and carries
//! X.509 name constraints: DNS names under the hosts it was made for, and no
//! IP address at all. A client that checks name constraints (every current TLS
//! library does) accepts nothing else it signs, even if it leaks into a wider
//! trust store. Leaves are made in memory, per host, for three days at most.

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, PKCS_ECDSA_P256_SHA256, SanType,
};
use zeroize::Zeroizing;

use super::TlsError;
use super::date::Day;

/// The CA's subject, the same in every CA OpenMoat makes, so a leaf's issuer
/// can be named from the key alone.
const CA_NAME: &str = "OpenMoat proxy CA";
const ORGANISATION: &str = "OpenMoat";

/// How long a CA is valid, in days.
pub(super) const CA_DAYS: i64 = 365;

/// A new CA: its certificate and key, both PEM.
pub(super) struct NewCa {
    pub(super) cert: String,
    pub(super) key: Zeroizing<String>,
}

fn subject() -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, CA_NAME);
    name.push(DnType::OrganizationName, ORGANISATION);
    name
}

/// The parameters every CA shares; only the leaves' issuer fields and key
/// usages are read from them when signing.
fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = subject();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

/// A CA for `hosts`, valid from yesterday for [`CA_DAYS`].
pub(super) fn generate(hosts: &[String], today: Day) -> Result<NewCa, TlsError> {
    if hosts.is_empty() {
        return Err(TlsError::NoHosts);
    }
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| TlsError::rcgen(&e))?;
    let mut params = ca_params();
    valid(&mut params, today.add(-1)?, today.add(CA_DAYS)?)?;
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: hosts.iter().cloned().map(GeneralSubtree::DnsName).collect(),
        // No address of any kind: the proxy terminates DNS names only.
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
        ],
    });
    let cert = params.self_signed(&key).map_err(|e| TlsError::rcgen(&e))?;
    Ok(NewCa {
        cert: cert.pem(),
        key: Zeroizing::new(key.serialize_pem()),
    })
}

/// The CA's key, ready to sign leaves.
pub(super) struct Signer {
    issuer: Issuer<'static, KeyPair>,
}

impl Signer {
    /// The signer for the CA whose key is `key_pem`.
    pub(super) fn new(key_pem: &str) -> Result<Self, TlsError> {
        let key = KeyPair::from_pem(key_pem).map_err(|_| TlsError::Key)?;
        if !key.is_compatible(&PKCS_ECDSA_P256_SHA256) {
            return Err(TlsError::Key);
        }
        Ok(Self {
            issuer: Issuer::new(ca_params(), key),
        })
    }

    /// A leaf for `host`, valid from yesterday to the day after tomorrow, and
    /// its key as PKCS #8 DER.
    pub(super) fn leaf(
        &self,
        host: &str,
        today: Day,
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), TlsError> {
        let key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| TlsError::rcgen(&e))?;
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        params.distinguished_name = name;
        let dns = host
            .try_into()
            .map_err(|_| TlsError::Host(host.to_owned()))?;
        params.subject_alt_names = vec![SanType::DnsName(dns)];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        valid(&mut params, today.add(-1)?, today.add(2)?)?;
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|e| TlsError::rcgen(&e))?;
        Ok((cert.der().to_vec(), Zeroizing::new(key.serialize_der())))
    }
}

/// Set `params` valid from the start of `from` to the start of `to` (UTC).
fn valid(params: &mut CertificateParams, from: Day, to: Day) -> Result<(), TlsError> {
    let (y, m, d) = from.ymd()?;
    params.not_before = rcgen::date_time_ymd(y, m, d);
    let (y, m, d) = to.ymd()?;
    params.not_after = rcgen::date_time_ymd(y, m, d);
    Ok(())
}
