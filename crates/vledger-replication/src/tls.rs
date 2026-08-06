//! TLS acceptor / connector builders for the replication channel.
//!
//! ## Tasks #1 and #2
//! - Task #1: TLS wraps every byte of the WAL stream so replication traffic
//!   is encrypted and authenticated in transit.
//! - Task #2: when `client_cert` / `client_key` are set in
//!   `ReplicationTlsConfig` the primary requires a client certificate
//!   (mutual TLS).  The replica presents its certificate; the primary
//!   validates it against `ca_cert`.
//!
//! ## Fix #3 — Hard failure when `ca_cert` is absent
//! `build_connector` now returns `Err(ReplicationError::Tls(...))` when
//! `ca_cert` is `None` in a production build.  The `NoVerifier` bypass is
//! compiled in only when the `dev-insecure-replication` feature is explicitly
//! enabled, making it impossible to accidentally ship a replica that skips
//! server certificate verification.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::pki_types::pem::PemObject;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::ReplicationTlsConfig;
use crate::error::ReplicationError;

// ── Primary (server) ──────────────────────────────────────────────────────────

/// Build a `TlsAcceptor` for the primary (WAL shipper) side.
///
/// If `tls.server_cert` / `tls.server_key` are not set, a self-signed
/// certificate is generated in-process for `tls.server_hostname`.
///
/// If `tls.client_cert` is Some (mTLS mode), the acceptor is configured to
/// require and verify a client certificate using `tls.ca_cert` as the trust
/// root.
pub fn build_acceptor(cfg: &ReplicationTlsConfig) -> Result<TlsAcceptor, ReplicationError> {
    let (certs, key) = load_server_cert_key(cfg)?;

    let server_config = if let Some(ca_path) = &cfg.ca_cert {
        // mTLS — require and verify a client certificate.
        let ca_certs = load_ca_certs(ca_path)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in ca_certs {
            roots.add(cert).map_err(|e| ReplicationError::Tls(e.to_string()))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| ReplicationError::Tls(e.to_string()))?;

        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| ReplicationError::Tls(e.to_string()))?
    } else {
        // TLS without mTLS — no client certificate required.
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ReplicationError::Tls(e.to_string()))?
    };

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

// ── Replica (client) ──────────────────────────────────────────────────────────

/// Build a `TlsConnector` for the replica (WAL receiver) side.
///
/// If `tls.ca_cert` is set the replica verifies the primary's certificate
/// against it.  If not set, server certificate verification is disabled
/// (acceptable only in dev/test with a self-signed primary cert).
///
/// If `tls.client_cert` / `tls.client_key` are set (mTLS), the replica
/// presents its own certificate during the handshake.
pub fn build_connector(cfg: &ReplicationTlsConfig) -> Result<TlsConnector, ReplicationError> {
    let client_config = if let Some(ca_path) = &cfg.ca_cert {
        // Verify the primary's certificate against the provided CA.
        let ca_certs = load_ca_certs(ca_path)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in ca_certs {
            roots.add(cert).map_err(|e| ReplicationError::Tls(e.to_string()))?;
        }

        if let (Some(cert_path), Some(key_path)) = (&cfg.client_cert, &cfg.client_key) {
            // mTLS: present client certificate.
            let (client_certs, client_key) = load_cert_key(cert_path, key_path)?;
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_client_auth_cert(client_certs, client_key)
                .map_err(|e| ReplicationError::Tls(e.to_string()))?
        } else {
            // TLS only, no client cert.
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
    } else {
        // No CA cert provided.
        //
        // Fix #3: in a production build this is a hard error.  The
        // `dev-insecure-replication` feature must be explicitly enabled to
        // allow skipping server certificate verification — it is never set by
        // the default workspace profile.
        #[cfg(not(feature = "dev-insecure-replication"))]
        {
            return Err(ReplicationError::Tls(
                "replication ca_cert is required but not configured. \
                 Set tls.ca_cert in replication.json to the primary's CA certificate path. \
                 (To bypass for local dev only, rebuild with \
                 --features dev-insecure-replication — never use in production.)"
                    .into(),
            ));
        }

        // Dev-only bypass: accept any server certificate.
        // Compiled in only when dev-insecure-replication feature is set.
        #[cfg(feature = "dev-insecure-replication")]
        {
            tracing::warn!(
                "⚠  dev-insecure-replication feature active — replica will NOT verify \
                 the primary's TLS certificate. THIS BUILD MUST NOT BE USED IN PRODUCTION."
            );
            let mut config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
            config.alpn_protocols.clear();
            config
        }
    };

    Ok(TlsConnector::from(Arc::new(client_config)))
}

// ── Certificate / key loaders ─────────────────────────────────────────────────

/// Load or generate the primary's server certificate and key.
fn load_server_cert_key(
    cfg: &ReplicationTlsConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ReplicationError> {
    match (&cfg.server_cert, &cfg.server_key) {
        (Some(cert_path), Some(key_path)) => load_cert_key(cert_path, key_path),
        _ => {
            // Generate a self-signed cert for dev / zero-config deployments.
            use rcgen::{generate_simple_self_signed, CertifiedKey};
            let CertifiedKey { cert, key_pair } =
                generate_simple_self_signed(vec![cfg.server_hostname.clone()])
                    .map_err(|e| ReplicationError::Tls(e.to_string()))?;
            let cert_der = CertificateDer::from(cert.der().to_vec());
            let key_der  = PrivateKeyDer::Pkcs8(
                PrivatePkcs8KeyDer::from(key_pair.serialize_der())
            );
            tracing::info!(
                hostname = %cfg.server_hostname,
                "Replication: generated self-signed TLS certificate"
            );
            Ok((vec![cert_der], key_der))
        }
    }
}

/// Load a certificate chain and private key from PEM files.
fn load_cert_key(
    cert_path: &str,
    key_path:  &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ReplicationError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| ReplicationError::Tls(format!("read cert {cert_path}: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ReplicationError::Tls(format!("parse cert {cert_path}: {e}")))?;

    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| ReplicationError::Tls(format!("read key {key_path}: {e}")))?;

    Ok((certs, key))
}

/// Load CA certificates from a PEM file.
fn load_ca_certs(
    ca_path: &str,
) -> Result<Vec<CertificateDer<'static>>, ReplicationError> {
    CertificateDer::pem_file_iter(ca_path)
        .map_err(|e| ReplicationError::Tls(format!("read CA cert {ca_path}: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ReplicationError::Tls(format!("parse CA cert {ca_path}: {e}")))
}

// ── NoVerifier — dev-only self-signed cert bypass ─────────────────────────────

/// A `ServerCertVerifier` that accepts any certificate.
/// Compiled in only when `dev-insecure-replication` feature is enabled.
#[cfg(feature = "dev-insecure-replication")]
#[derive(Debug)]
struct NoVerifier;

#[cfg(feature = "dev-insecure-replication")]
impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message:   &[u8],
        _cert:      &CertificateDer<'_>,
        _dss:       &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message:   &[u8],
        _cert:      &CertificateDer<'_>,
        _dss:       &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
