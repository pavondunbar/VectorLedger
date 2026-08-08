//! # vledger-license-gen
//!
//! **Internal VectorGuard Labs tool — not distributed to customers.**
//!
//! Generates Ed25519 keypairs for license signing and issues signed
//! `license.json` files for customers.
//!
//! ## Commands
//!
//! ```
//! # Generate a new signing keypair (run once, store private key offline)
//! vledger-license-gen keygen --output ./vgl-license-keys
//!
//! # Issue a license file for a customer
//! vledger-license-gen issue \
//!   --private-key ./vgl-license-keys/license_signing_key.hex \
//!   --licensee "Acme Corp" \
//!   --email ops@acme.com \
//!   --tier starter \
//!   --expires 2027-08-06 \
//!   --output ./acme-license.json
//!
//! # Tiers and default feature sets:
//! #   free       — no gated features ($0/month)
//! #   starter    — pgwire ($99/month)
//! #   growth     — pgwire, replication, compliance_report,
//! #                audit_export_unlimited ($399/month)
//! #   enterprise — all features + hsm + multi_node ($999/month)
//!
//! # Verify a license file (without needing the private key)
//! vledger-license-gen verify \
//!   --public-key ./vgl-license-keys/license_signing_pubkey.hex \
//!   --license ./acme-license.json
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{NaiveDate, Utc};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::Value;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "vledger-license-gen",
    about   = "VectorGuard Labs internal license issuance tool",
    version,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 signing keypair.
    /// Run once and store the private key securely offline.
    Keygen {
        /// Directory to write key files into.
        #[arg(long, default_value = ".")]
        output: PathBuf,
    },

    /// Issue a signed license.json for a customer.
    Issue {
        /// Path to the hex-encoded private signing key file.
        #[arg(long)]
        private_key: PathBuf,

        /// Customer / organisation name.
        #[arg(long)]
        licensee: String,

        /// Customer contact email.
        #[arg(long)]
        email: String,

        /// License tier: free, starter, growth, enterprise.
        #[arg(long)]
        tier: String,

        /// Expiry date in YYYY-MM-DD format.
        #[arg(long)]
        expires: String,

        /// Comma-separated list of features to override.
        /// If omitted, uses the default feature set for the tier.
        /// Valid values: pgwire, replication, hsm, compliance_report,
        ///               audit_export_unlimited, multi_node
        #[arg(long)]
        features: Option<String>,

        /// Output path for the license.json file.
        #[arg(long, default_value = "license.json")]
        output: PathBuf,
    },

    /// Verify a license.json file against a public key.
    Verify {
        /// Path to the hex-encoded public key file.
        #[arg(long)]
        public_key: PathBuf,

        /// Path to the license.json to verify.
        #[arg(long)]
        license: PathBuf,
    },
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen { output }                                         => cmd_keygen(output),
        Commands::Issue { private_key, licensee, email, tier, expires, features, output }
            => cmd_issue(private_key, licensee, email, tier, expires, features, output),
        Commands::Verify { public_key, license }                            => cmd_verify(public_key, license),
    }
}

// ── keygen ────────────────────────────────────────────────────────────────────

fn cmd_keygen(output: PathBuf) -> Result<()> {
    std::fs::create_dir_all(&output)?;

    let signing_key    = SigningKey::generate(&mut OsRng);
    let verifying_key  = signing_key.verifying_key();

    let privkey_hex    = hex::encode(signing_key.to_bytes());
    let pubkey_hex     = hex::encode(verifying_key.to_bytes());

    let priv_path = output.join("license_signing_key.hex");
    let pub_path  = output.join("license_signing_pubkey.hex");

    std::fs::write(&priv_path, &privkey_hex)
        .context("Failed to write private key")?;
    std::fs::write(&pub_path,  &pubkey_hex)
        .context("Failed to write public key")?;

    // Restrict private key to owner read-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o400))?;
    }

    println!("✓ License signing keypair generated");
    println!();
    println!("  Private key : {}", priv_path.display());
    println!("  Public key  : {}", pub_path.display());
    println!();
    println!("  Public key hex (paste into vledger-license/src/store.rs):");
    println!("  {pubkey_hex}");
    println!();
    println!("  ⚠  Keep the private key OFFLINE and NEVER commit it to source control.");
    println!("     The public key is the only value that belongs in the binary.");

    Ok(())
}

// ── issue ─────────────────────────────────────────────────────────────────────

fn cmd_issue(
    private_key_path: PathBuf,
    licensee:         String,
    email:            String,
    tier:             String,
    expires:          String,
    features_override: Option<String>,
    output:           PathBuf,
) -> Result<()> {
    // Validate tier.
    let _valid_tiers = ["free", "starter", "growth", "enterprise"];
    if !_valid_tiers.contains(&tier.as_str()) {
        anyhow::bail!("Unknown tier '{}' — use: free, starter, growth, enterprise", tier);
    }

    // Validate expiry date.
    NaiveDate::parse_from_str(&expires, "%Y-%m-%d")
        .with_context(|| format!("Invalid expiry date '{}' — use YYYY-MM-DD", expires))?;

    // Resolve feature list.
    let features: Vec<String> = if let Some(f) = features_override {
        f.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        default_features_for_tier(&tier)
    };

    // Load private key.
    let privkey_hex = std::fs::read_to_string(&private_key_path)
        .with_context(|| format!("Cannot read private key: {}", private_key_path.display()))?;
    let privkey_bytes = hex::decode(privkey_hex.trim())
        .context("Private key is not valid hex")?;
    let privkey_arr: [u8; 32] = privkey_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Private key must be 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&privkey_arr);

    let issued_at = Utc::now().format("%Y-%m-%d").to_string();

    // Build canonical payload (sorted BTreeMap → compact JSON).
    let features_val: Vec<Value> = features.iter()
        .map(|f| Value::String(f.clone()))
        .collect();
    let mut map = BTreeMap::new();
    map.insert("email",      Value::String(email.clone()));
    map.insert("expires_at", Value::String(expires.clone()));
    map.insert("features",   Value::Array(features_val));
    map.insert("issued_at",  Value::String(issued_at.clone()));
    map.insert("licensee",   Value::String(licensee.clone()));
    map.insert("tier",       Value::String(tier.clone()));

    let payload = serde_json::to_vec(&map)?;
    let signature: Signature = signing_key.sign(&payload);
    let sig_hex = hex::encode(signature.to_bytes());

    // Build the final license JSON (pretty-printed for readability).
    let license = serde_json::json!({
        "licensee":   licensee,
        "email":      email,
        "tier":       tier,
        "issued_at":  issued_at,
        "expires_at": expires,
        "features":   features,
        "signature":  sig_hex,
    });

    let json = serde_json::to_string_pretty(&license)?;
    std::fs::write(&output, &json)
        .with_context(|| format!("Cannot write license to {}", output.display()))?;

    println!("✓ License issued");
    println!();
    println!("  Licensee   : {licensee}");
    println!("  Email      : {email}");
    println!("  Tier       : {tier}");
    println!("  Issued     : {issued_at}");
    println!("  Expires    : {expires}");
    println!("  Features   : {}", features.join(", "));
    println!("  Output     : {}", output.display());

    Ok(())
}

// ── verify ────────────────────────────────────────────────────────────────────

fn cmd_verify(public_key_path: PathBuf, license_path: PathBuf) -> Result<()> {
    let pubkey_hex = std::fs::read_to_string(&public_key_path)
        .with_context(|| format!("Cannot read public key: {}", public_key_path.display()))?;
    let pubkey_bytes = hex::decode(pubkey_hex.trim())
        .context("Public key is not valid hex")?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .context("Invalid public key")?;

    let json = std::fs::read_to_string(&license_path)
        .with_context(|| format!("Cannot read license: {}", license_path.display()))?;
    let file: serde_json::Value = serde_json::from_str(&json)?;

    let sig_hex = file["signature"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing 'signature' field"))?;
    let sig_bytes = hex::decode(sig_hex).context("Signature is not valid hex")?;
    let sig_arr: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_arr);

    // Rebuild canonical payload from the license fields.
    let features_val: Vec<Value> = file["features"].as_array()
        .ok_or_else(|| anyhow::anyhow!("Missing 'features' field"))?
        .clone();
    let mut map = BTreeMap::new();
    map.insert("email",      file["email"].clone());
    map.insert("expires_at", file["expires_at"].clone());
    map.insert("features",   Value::Array(features_val));
    map.insert("issued_at",  file["issued_at"].clone());
    map.insert("licensee",   file["licensee"].clone());
    map.insert("tier",       file["tier"].clone());

    let payload = serde_json::to_vec(&map)?;
    verifying_key.verify(&payload, &signature)
        .context("Signature verification FAILED — license may be tampered")?;

    // Check expiry.
    let expires_str = file["expires_at"].as_str().unwrap_or("");
    let expires = NaiveDate::parse_from_str(expires_str, "%Y-%m-%d")
        .with_context(|| format!("Invalid expires_at: {expires_str}"))?;
    let today = Utc::now().date_naive();
    let days = (expires - today).num_days();

    println!("✓ License signature is VALID");
    println!();
    println!("  Licensee : {}", file["licensee"].as_str().unwrap_or("?"));
    println!("  Email    : {}", file["email"].as_str().unwrap_or("?"));
    println!("  Tier     : {}", file["tier"].as_str().unwrap_or("?"));
    println!("  Issued   : {}", file["issued_at"].as_str().unwrap_or("?"));
    println!("  Expires  : {expires_str}");
    if days < 0 {
        println!("  ⚠  EXPIRED {} days ago", -days);
    } else {
        println!("  Days left: {days}");
    }
    if let Some(features) = file["features"].as_array() {
        let flist: Vec<&str> = features.iter()
            .filter_map(|f| f.as_str())
            .collect();
        println!("  Features : {}", flist.join(", "));
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn default_features_for_tier(tier: &str) -> Vec<String> {
    match tier {
        "starter" => vec![
            "pgwire".into(),
        ],
        "growth" => vec![
            "pgwire".into(),
            "replication".into(),
            "compliance_report".into(),
            "audit_export_unlimited".into(),
        ],
        "enterprise" => vec![
            "pgwire".into(),
            "replication".into(),
            "hsm".into(),
            "compliance_report".into(),
            "audit_export_unlimited".into(),
            "multi_node".into(),
        ],
        _ => vec![], // free has no gated features
    }
}
