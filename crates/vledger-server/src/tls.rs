//! TLS 1.3 certificate and acceptor setup.
//!
//! ## Cert persistence (Task #5)
//! Self-signed certificates are now persisted to
//! `<catalog_dir>/tls_cert.pem` and `<catalog_dir>/tls_key.pem`
//! (mode 0o600 on each file).  On restart the existing files are loaded
//! rather than generating a new cert, so:
//! - Clients that pin the certificate keep working across restarts.
//! - The cert can be distributed to clients (e.g. via `vledger status`)
//!   before the first connection.
//! - To force a new cert (e.g. hostname change), delete both PEM files.
//!
//! ## Mutual TLS (Task #5)
//! When `mtls_ca_cert` is `Some(path)` in `ServerConfig`, the acceptor is
//! built with `WebPkiClientVerifier` — every client must present a
//! certificate signed by that CA.

use std::path::Path;
use std::sync::Arc;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig as RustlsConfig;
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::error::ServerError;

// ── Public entry points ───────────────────────────────────────────────────────

/// Build a `TlsAcceptor` from PEM files on disk.
///
/// `mtls_ca_cert` — if `Some`, enable mutual TLS using this CA certificate.
pub fn acceptor_from_files(
    cert_path: &Path,
    key_path: &Path,
    mtls_ca_cert: Option<&str>,
) -> Result<TlsAcceptor, ServerError> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    build_acceptor(certs, key, mtls_ca_cert)
}

/// Load or generate a self-signed certificate for `hostname`.
///
/// If `<catalog_dir>/tls_cert.pem` and `<catalog_dir>/tls_key.pem` already
/// exist they are reloaded.  Otherwise a new cert/key pair is generated and
/// written to those paths (mode 0o600) so the cert survives restarts.
///
/// `catalog_dir` — `None` keeps the cert in memory only (no persistence,
/// used when running self-tests without a real data directory).
///
/// `mtls_ca_cert` — if `Some`, enable mutual TLS using this CA certificate.
pub fn self_signed_acceptor(
    hostname: &str,
    catalog_dir: Option<&str>,
    mtls_ca_cert: Option<&str>,
) -> Result<TlsAcceptor, ServerError> {
    // If catalog_dir is set, try to load existing persisted cert first.
    if let Some(dir) = catalog_dir {
        let cert_path = std::path::Path::new(dir).join("tls_cert.pem");
        let key_path = std::path::Path::new(dir).join("tls_key.pem");

        if cert_path.exists() && key_path.exists() {
            info!(
                cert = %cert_path.display(),
                "Loading persisted self-signed TLS certificate"
            );
            return acceptor_from_files(&cert_path, &key_path, mtls_ca_cert);
        }

        // Generate once — persist the *same* CertifiedKey to disk so the
        // acceptor and the on-disk files are always in sync (Fix #4).
        let ck = generate_self_signed(hostname)?;
        persist_cert_key(dir, &ck)?;
        let (certs, key) = certified_to_der(&ck);
        return build_acceptor(certs, key, mtls_ca_cert);
    }

    // No catalog_dir — ephemeral cert (self-tests / pgwire with no data dir).
    info!(
        hostname,
        "Generating ephemeral self-signed TLS certificate (not persisted)"
    );
    let ck = generate_self_signed(hostname)?;
    let (certs, key) = certified_to_der(&ck);
    build_acceptor(certs, key, mtls_ca_cert)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn generate_self_signed(hostname: &str) -> Result<CertifiedKey, ServerError> {
    generate_simple_self_signed(vec![hostname.to_string()])
        .map_err(|e| ServerError::Tls(e.to_string()))
}

/// Convert a `CertifiedKey` into the DER types rustls needs.
fn certified_to_der(ck: &CertifiedKey) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    (vec![cert_der], key_der)
}

/// Write cert and key as PEM files to `<dir>/tls_cert.pem` and
/// `<dir>/tls_key.pem` with mode 0o600.
///
/// Fix #4: persist the `CertifiedKey` produced by `generate_self_signed`
/// rather than calling `generate_simple_self_signed` a second time.  The
/// previous code discarded the `certs`/`key` arguments and wrote a
/// completely different keypair to disk, so the acceptor used cert A while
/// the file contained cert B.  On restart the server would load cert B and
/// any client that had pinned cert A would fail to connect.
fn persist_cert_key(dir: &str, certified: &CertifiedKey) -> Result<(), ServerError> {
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();

    let cert_path = std::path::Path::new(dir).join("tls_cert.pem");
    let key_path = std::path::Path::new(dir).join("tls_key.pem");

    std::fs::write(&cert_path, &cert_pem)
        .map_err(|e| ServerError::Tls(format!("write tls_cert.pem: {e}")))?;
    std::fs::write(&key_path, &key_pem)
        .map_err(|e| ServerError::Tls(format!("write tls_key.pem: {e}")))?;

    set_mode_600(&cert_path);
    set_mode_600(&key_path);

    info!(
        cert = %cert_path.display(),
        key  = %key_path.display(),
        "Persisted self-signed TLS certificate"
    );
    Ok(())
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, ServerError> {
    CertificateDer::pem_file_iter(path)
        .map_err(|e| ServerError::Tls(format!("read cert {}: {e}", path.display())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ServerError::Tls(format!("parse cert {}: {e}", path.display())))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, ServerError> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| ServerError::Tls(format!("read key {}: {e}", path.display())))
}

fn build_acceptor(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    mtls_ca_cert: Option<&str>,
) -> Result<TlsAcceptor, ServerError> {
    let config = if let Some(ca_path) = mtls_ca_cert {
        // mTLS: require and verify a client certificate.
        let ca_certs = load_certs(std::path::Path::new(ca_path))?;
        let mut roots = rustls::RootCertStore::empty();
        for c in ca_certs {
            roots.add(c).map_err(|e| ServerError::Tls(e.to_string()))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| ServerError::Tls(e.to_string()))?;

        info!("mTLS enabled — client certificate required");
        RustlsConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Tls(e.to_string()))?
    } else {
        RustlsConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Tls(e.to_string()))?
    };

    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn set_mode_600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path; // Windows uses ACLs; file is inside the protected data dir
    }
}
