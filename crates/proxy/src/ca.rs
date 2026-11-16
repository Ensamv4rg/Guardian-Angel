//! The per-install certificate authority used to inspect HTTPS.
//!
//! Each install generates its own CA key, so no two computers share one and
//! nobody else can use it to intercept this computer's traffic. The CA only
//! becomes effective once the user trusts it (Windows shows its own prompt);
//! this module never installs it.

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::IpAddr;
use std::path::Path;
use time::{Duration, OffsetDateTime};

pub const CA_COMMON_NAME: &str = "Guardian Angel Local Inspection CA";
const CA_FILE: &str = "ca.cer";
const KEY_FILE: &str = "ca.key.pem";
/// Leaf certificates are short-lived and regenerated on demand.
const LEAF_DAYS: i64 = 30;
const CA_DAYS: i64 = 2 * 365;

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("certificate error: {0}")]
    Cert(#[from] rcgen::Error),
    #[error("could not read or write the CA files: {0}")]
    Io(#[from] std::io::Error),
}

pub struct CertAuthority {
    issuer: Issuer<'static, KeyPair>,
    cert_der: CertificateDer<'static>,
}

/// Name, key usage and validity of the CA. The issuer rebuilt from saved
/// files must use the same name, or leaf certificates would not chain.
fn ca_params(now: OffsetDateTime) -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, "Guardian Angel (this computer only)");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.not_before = now - Duration::days(1);
    p.not_after = now + Duration::days(CA_DAYS);
    p
}

impl CertAuthority {
    /// Creates a new CA with a fresh key.
    pub fn generate() -> Result<(Self, String), CaError> {
        let key = KeyPair::generate()?;
        let key_pem = key.serialize_pem();
        let params = ca_params(OffsetDateTime::now_utc());
        let cert = params.self_signed(&key)?;
        Ok((
            Self {
                cert_der: cert.der().clone(),
                issuer: Issuer::new(params, key),
            },
            key_pem,
        ))
    }

    /// Rebuilds a CA from its saved certificate and key.
    pub fn from_parts(cert_der: Vec<u8>, key_pem: &str) -> Result<Self, CaError> {
        let key = KeyPair::from_pem(key_pem)?;
        Ok(Self {
            cert_der: CertificateDer::from(cert_der),
            issuer: Issuer::new(ca_params(OffsetDateTime::now_utc()), key),
        })
    }

    /// Loads the CA from `dir`, creating and saving one on first use.
    ///
    /// The key is stored in the user's own profile folder, which only that
    /// user and administrators can read. Encrypting it with Windows DPAPI is
    /// left to the service.
    pub fn load_or_create(dir: &Path) -> Result<Self, CaError> {
        let (cert_path, key_path) = (dir.join(CA_FILE), dir.join(KEY_FILE));
        if cert_path.is_file() && key_path.is_file() {
            return Self::from_parts(std::fs::read(cert_path)?, &std::fs::read_to_string(key_path)?);
        }
        let (ca, key_pem) = Self::generate()?;
        std::fs::create_dir_all(dir)?;
        std::fs::write(&key_path, key_pem)?;
        std::fs::write(&cert_path, ca.cert_der.as_ref())?;
        Ok(ca)
    }

    /// The CA certificate (DER), for the user to trust or export.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// The CA certificate as PEM text, for tools that want a `.pem` file.
    pub fn cert_pem(&self) -> String {
        pem::encode(&pem::Pem::new("CERTIFICATE", self.cert_der.to_vec()))
    }

    /// An empty revocation list signed by the CA.
    ///
    /// Windows' TLS library (Schannel) checks revocation, and rejects a
    /// certificate whose status it cannot determine. Each leaf therefore
    /// points at this list, served by the proxy itself, so the check succeeds.
    pub fn crl_der(&self) -> Result<Vec<u8>, CaError> {
        let now = OffsetDateTime::now_utc();
        let params = CertificateRevocationListParams {
            this_update: now - Duration::hours(1),
            next_update: now + Duration::days(7),
            crl_number: SerialNumber::from(now.unix_timestamp().max(1) as u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        Ok(params.signed_by(&self.issuer)?.der().to_vec())
    }

    /// Issues a certificate for `host`, returning the chain (leaf, CA) and
    /// key. `crl_url` is where clients can fetch the revocation list.
    pub fn leaf_for(
        &self,
        host: &str,
        crl_url: Option<&str>,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), CaError> {
        let now = OffsetDateTime::now_utc();
        let mut p = CertificateParams::default();
        p.subject_alt_names = vec![match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.try_into()?),
        }];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        p.distinguished_name = dn;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.not_before = now - Duration::days(1);
        p.not_after = now + Duration::days(LEAF_DAYS);
        if let Some(url) = crl_url {
            p.crl_distribution_points = vec![CrlDistributionPoint {
                uris: vec![url.to_owned()],
            }];
        }

        let key = KeyPair::generate()?;
        let cert = p.signed_by(&key, &self.issuer)?;
        Ok((
            vec![cert.der().clone(), self.cert_der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        ))
    }
}
