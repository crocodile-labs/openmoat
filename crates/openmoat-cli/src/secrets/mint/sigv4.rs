//! AWS Signature Version 4 for one request (the AWS General Reference,
//! "Create a signed AWS API request"): HMAC-SHA256 through `ring`, SHA-256
//! through `sha2`, both already in the build.

use std::fmt::Write as _;

use ring::hmac;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::encode::hex;

/// What signs: the access key and its secret, and the session token when the
/// keys are temporary ones.
pub struct Keys {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
}

/// One request to sign. `headers` are lowercase names with their values; the
/// `host` and `x-amz-date` headers must be among them.
pub struct ToSign<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
    /// `YYYYMMDDTHHMMSSZ`.
    pub amz_date: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn mac(key: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    Zeroizing::new(hmac::sign(&key, data).as_ref().to_vec())
}

/// The canonical request (step 1), headers sorted by name.
pub fn canonical_request(req: &ToSign<'_>) -> (String, String) {
    let mut headers: Vec<(&str, &str)> = req.headers.to_vec();
    headers.sort_by(|a, b| a.0.cmp(b.0));
    let canonical_headers = headers.iter().fold(String::new(), |mut text, (n, v)| {
        let _ = writeln!(text, "{n}:{}", v.trim());
        text
    });
    let signed: Vec<&str> = headers.iter().map(|(n, _)| *n).collect();
    let signed = signed.join(";");
    let text = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed}\n{}",
        req.method,
        req.path,
        req.query,
        sha256_hex(req.body)
    );
    (text, signed)
}

/// The `Authorization` header value for `req` signed with `keys`.
pub fn authorization(req: &ToSign<'_>, keys: &Keys) -> Zeroizing<String> {
    let (canonical, signed) = canonical_request(req);
    let date = &req.amz_date[..8];
    let scope = format!("{date}/{}/{}/aws4_request", req.region, req.service);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        req.amz_date,
        sha256_hex(canonical.as_bytes())
    );
    let first = Zeroizing::new(format!("AWS4{}", keys.secret_access_key.as_str()));
    let k_date = mac(first.as_bytes(), date.as_bytes());
    let k_region = mac(&k_date, req.region.as_bytes());
    let k_service = mac(&k_region, req.service.as_bytes());
    let k_signing = mac(&k_service, b"aws4_request");
    let signature = hex(&mac(&k_signing, to_sign.as_bytes()));
    Zeroizing::new(format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
        keys.access_key_id
    ))
}

/// `ms` since the epoch as `SigV4`'s `YYYYMMDDTHHMMSSZ`.
pub fn amz_date(ms: i64) -> String {
    crate::time::rfc3339(ms).replace(['-', ':'], "")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example of AWS's `SigV4` documentation (IAM `ListUsers`,
    /// 2015-08-30), with its published canonical-request hash and signature.
    /// The example key is put together at run time.
    #[test]
    fn matches_the_documented_example() {
        let keys = Keys {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: Zeroizing::new(format!(
                "{}{}",
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCY", "EXAMPLEKEY"
            )),
            session_token: None,
        };
        let headers = [
            (
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            ),
            ("host", "iam.amazonaws.com"),
            ("x-amz-date", "20150830T123600Z"),
        ];
        let req = ToSign {
            method: "GET",
            path: "/",
            query: "Action=ListUsers&Version=2010-05-08",
            headers: &headers,
            body: b"",
            amz_date: "20150830T123600Z",
            region: "us-east-1",
            service: "iam",
        };
        let (canonical, signed) = canonical_request(&req);
        assert_eq!(signed, "content-type;host;x-amz-date");
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );
        let auth = authorization(&req, &keys);
        assert!(
            auth.ends_with(
                "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
            ),
            "{}",
            auth.as_str()
        );
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, "
        ));
        assert_eq!(
            amz_date(crate::time::parse_rfc3339("2015-08-30T12:36:00Z").unwrap()),
            "20150830T123600Z"
        );
    }
}
