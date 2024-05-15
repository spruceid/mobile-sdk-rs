use std::time::SystemTime;

use uniffi::deps::{
  anyhow::{bail, Context, Result},
  log
};
use cose_rs::CoseSign1;
use x509_cert::{
    der::{oid::AssociatedOid, Decode},
    ext::pkix::{CrlDistributionPoints, KeyUsage},
    time::Validity,
    Certificate,
};

pub fn get_signer_certificate(cwt: &CoseSign1) -> Result<Certificate> {
    let cert_der = match cwt
        .protected()
        .get_i(33)
        .context("x5chain (label '33') is not in the protected header")?
    {
        serde_cbor::Value::Bytes(der) => der,
        serde_cbor::Value::Array(x5c) if x5c.len() == 1 => match &x5c[0] {
            serde_cbor::Value::Bytes(der) => der,
            v => bail!("unexpected format for x509 certificate: {v:?}"),
        },
        serde_cbor::Value::Array(_) => {
            bail!("x5chain contains more than one certificate")
        }
        v => bail!("unexpected format for x5chain: {v:?}"),
    };

    Certificate::from_der(cert_der).context("signer certificate could not be parsed")
}

pub fn extract_extensions(certificate: &Certificate) -> Result<(KeyUsage, CrlDistributionPoints)> {
    let mut key_usage = None;
    let mut crl_dp = None;

    // Find specific extensions and error if any unsupported 'critical' extensions are found.
    for extension in certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .context("no extensions")?
    {
        match extension.extn_id {
            KeyUsage::OID => key_usage = Some(&extension.extn_value),
            CrlDistributionPoints::OID => crl_dp = Some(&extension.extn_value),
            oid if extension.critical => bail!("unexpected critical extension: {oid}"),
            oid => {
                log::debug!("skipping certificate extension {oid}")
            }
        }
    }

    let key_usage = KeyUsage::from_der(
        key_usage
            .context("'key usage' extension could not be found")?
            .as_bytes(),
    )
    .context("unable to parse 'key usage' extension")?;

    let crl_dp = CrlDistributionPoints::from_der(
        crl_dp
            .context("'crl distribution points' extension could not be found")?
            .as_bytes(),
    )
    .context("unable to parse 'crl distribution points' extension")?;

    Ok((key_usage, crl_dp))
}

pub fn check_validity(validity: &Validity) -> Result<()> {
    let nbf = validity.not_before.to_system_time();
    let exp = validity.not_after.to_system_time();

    let now = SystemTime::now();

    if nbf <= now && now < exp {
        return Ok(());
    }

    bail!("certificate is invalid")
}
