//! Server configuration.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to bind, e.g. "127.0.0.1:5433".
    pub bind_addr: String,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Path to the TLS certificate (PEM).  None → use self-signed.
    pub tls_cert_path: Option<String>,
    /// Path to the TLS private key (PEM).  None → use self-signed.
    pub tls_key_path: Option<String>,
    /// Hostname used for self-signed certificate generation.
    pub tls_hostname: String,
    /// Attach Merkle proofs to every SELECT response.
    pub attach_proofs: bool,
    /// Whether to require authentication on every connection.
    ///
    /// **Default: `true`.  This field should always remain `true` in
    /// production.**
    ///
    /// Setting this to `false` has *no effect* unless the crate is compiled
    /// with `--features dev-no-auth` (Task #5).  In a production binary the
    /// bypass path is compiled out entirely — authentication is always
    /// enforced regardless of this field's value.
    pub require_auth: bool,
    /// Path to the catalog directory (for users.json and server secret).
    pub catalog_dir: Option<String>,
    /// Path to CA certificate PEM for mutual TLS client authentication.
    /// When set, every client must present a certificate signed by this CA.
    /// `None` → mTLS disabled (one-way TLS only).
    pub mtls_ca_cert: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr:       "127.0.0.1:5433".into(),
            max_connections: 128,
            tls_cert_path:   None,
            tls_key_path:    None,
            tls_hostname:    "localhost".into(),
            attach_proofs:   true,
            require_auth:    true,
            catalog_dir:     None,
            mtls_ca_cert:    None,
        }
    }
}
