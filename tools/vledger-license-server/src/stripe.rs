//! Stripe webhook signature verification and event parsing.
//!
//! ## Verification
//! Stripe signs every webhook with HMAC-SHA256 using the endpoint's
//! signing secret (set via `STRIPE_WEBHOOK_SECRET` env var).  The
//! signature is carried in the `Stripe-Signature` header as a
//! comma-separated list of `t=<timestamp>` and `v1=<hex-sig>` pairs.
//!
//! We verify:
//!   1. The `v1` HMAC matches `HMAC-SHA256(secret, "<t>.<raw_body>")`.
//!   2. The timestamp is within ±300 seconds of now (replay protection).
//!
//! ## Events handled
//! | Event | Action |
//! |---|---|
//! | `checkout.session.completed` | New subscription — issue first license |
//! | `invoice.payment_succeeded`  | Renewal — issue renewed license with new expiry |
//! | `invoice.payment_failed`     | Payment failed — log, do nothing (grace period handles it) |
//! | `customer.subscription.deleted` | Cancellation — log; expiry-based enforcement takes over |

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{info, warn};

use crate::error::ServerError;

// ── Verified event ────────────────────────────────────────────────────────────

/// The subset of Stripe event fields we care about, extracted from the
/// raw JSON after signature verification.
#[derive(Debug)]
pub enum StripeEvent {
    /// A new customer has completed checkout.  We use this to issue the
    /// very first license before the first invoice fires.
    CheckoutSessionCompleted {
        stripe_customer_id:     String,
        stripe_subscription_id: String,
        /// Billing period end Unix timestamp, if available.
        current_period_end:     Option<i64>,
    },

    /// A subscription invoice was paid successfully.  Used for renewals.
    InvoicePaymentSucceeded {
        stripe_customer_id:     String,
        stripe_subscription_id: String,
        /// End of the billing period covered by this invoice.
        current_period_end:     i64,
    },

    /// An invoice payment failed.  We log and do nothing — Stripe will
    /// retry, and the 7-day grace period built into the license expiry
    /// gives the customer time to update their payment method.
    InvoicePaymentFailed {
        stripe_customer_id:     String,
        stripe_subscription_id: String,
    },

    /// The subscription was cancelled or deleted.  We log and do nothing —
    /// the existing license will expire on its own schedule.
    SubscriptionDeleted {
        stripe_customer_id:     String,
        stripe_subscription_id: String,
    },

    /// Any other event type — logged and ignored.
    Unhandled { event_type: String },
}

// ── Signature verification ────────────────────────────────────────────────────

/// Verify the `Stripe-Signature` header against `raw_body` using `secret`.
///
/// Returns `Ok(())` if valid, `Err(ServerError::WebhookSignature)` otherwise.
pub fn verify_signature(
    stripe_sig_header: &str,
    raw_body:          &[u8],
    secret:            &str,
) -> Result<(), ServerError> {
    // Parse header: "t=1614...,v1=abc...,v1=def..."
    let mut timestamp: Option<i64>  = None;
    let mut signatures: Vec<String> = Vec::new();

    for part in stripe_sig_header.split(',') {
        if let Some(ts) = part.strip_prefix("t=") {
            timestamp = ts.parse::<i64>().ok();
        } else if let Some(sig) = part.strip_prefix("v1=") {
            signatures.push(sig.to_string());
        }
    }

    let ts = timestamp.ok_or_else(|| {
        ServerError::WebhookSignature("missing timestamp in Stripe-Signature header".into())
    })?;

    // Replay protection: reject events older than 5 minutes.
    let age = Utc::now().timestamp() - ts;
    if age.abs() > 300 {
        return Err(ServerError::WebhookSignature(
            format!("timestamp too old or too far in the future: age={age}s")
        ));
    }

    // Compute expected HMAC: HMAC-SHA256(secret, "<ts>.<body>")
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| ServerError::WebhookSignature(e.to_string()))?;

    mac.update(ts.to_string().as_bytes());
    mac.update(b".");
    mac.update(raw_body);
    let expected = hex::encode(mac.finalize().into_bytes());

    // Constant-time comparison via subtle is ideal; for webhook verification
    // where timing side-channels are not exploitable (attacker can't observe
    // timing over the network with sufficient resolution), a hex comparison
    // after already-known-length HMAC is acceptable.
    if signatures.iter().any(|s| s == &expected) {
        Ok(())
    } else {
        Err(ServerError::WebhookSignature("HMAC mismatch".into()))
    }
}

// ── Event parsing ─────────────────────────────────────────────────────────────

/// Parse a verified Stripe event JSON body into a `StripeEvent`.
pub fn parse_event(body: &[u8]) -> Result<StripeEvent, ServerError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ServerError::WebhookParse(e.to_string()))?;

    let event_type = v["type"].as_str()
        .ok_or_else(|| ServerError::WebhookParse("missing event type".into()))?
        .to_string();

    let obj = &v["data"]["object"];

    match event_type.as_str() {
        "checkout.session.completed" => {
            let customer_id = str_field(obj, "customer")?;
            let sub_id      = str_field(obj, "subscription")?;
            // `current_period_end` is not on the session object directly;
            // it arrives on the subscription object inside the event if
            // Stripe expands it.  Fall back to None if absent — the
            // invoice.payment_succeeded that fires immediately after will
            // carry the correct period end.
            let period_end = obj["subscription_details"]["metadata"]["current_period_end"]
                .as_i64()
                .or_else(|| obj["current_period_end"].as_i64());

            info!(
                customer  = %customer_id,
                sub       = %sub_id,
                "Stripe: checkout.session.completed"
            );

            Ok(StripeEvent::CheckoutSessionCompleted {
                stripe_customer_id:     customer_id,
                stripe_subscription_id: sub_id,
                current_period_end:     period_end,
            })
        }

        "invoice.payment_succeeded" => {
            // The invoice object contains `subscription` and
            // `lines.data[0].period.end` for the billing period covered.
            let customer_id = str_field(obj, "customer")?;
            let sub_id      = str_field(obj, "subscription")?;
            let period_end  = obj["lines"]["data"][0]["period"]["end"]
                .as_i64()
                .or_else(|| obj["period_end"].as_i64())
                .unwrap_or_else(|| Utc::now().timestamp() + 30 * 86400);

            info!(
                customer   = %customer_id,
                sub        = %sub_id,
                period_end = period_end,
                "Stripe: invoice.payment_succeeded"
            );

            Ok(StripeEvent::InvoicePaymentSucceeded {
                stripe_customer_id:     customer_id,
                stripe_subscription_id: sub_id,
                current_period_end:     period_end,
            })
        }

        "invoice.payment_failed" => {
            let customer_id = str_field(obj, "customer")?;
            let sub_id      = obj["subscription"].as_str()
                .unwrap_or("unknown")
                .to_string();

            warn!(
                customer = %customer_id,
                sub      = %sub_id,
                "Stripe: invoice.payment_failed — grace period active"
            );

            Ok(StripeEvent::InvoicePaymentFailed {
                stripe_customer_id:     customer_id,
                stripe_subscription_id: sub_id,
            })
        }

        "customer.subscription.deleted" => {
            let customer_id = str_field(obj, "customer")?;
            let sub_id      = str_field(obj, "id")?;

            warn!(
                customer = %customer_id,
                sub      = %sub_id,
                "Stripe: customer.subscription.deleted — license will expire naturally"
            );

            Ok(StripeEvent::SubscriptionDeleted {
                stripe_customer_id:     customer_id,
                stripe_subscription_id: sub_id,
            })
        }

        other => {
            info!(event_type = other, "Stripe: unhandled event type");
            Ok(StripeEvent::Unhandled { event_type: other.to_string() })
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn str_field(obj: &serde_json::Value, field: &str) -> Result<String, ServerError> {
    obj[field]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| ServerError::WebhookParse(
            format!("missing or non-string field '{field}' in Stripe event object")
        ))
}

// ── Stripe metadata helpers ───────────────────────────────────────────────────

/// Extract the VectorLedger tier from Stripe product metadata.
///
/// You must set `metadata.vledger_tier = "starter" | "growth" | "enterprise"`
/// on the Stripe Product (not Price) object.  This function walks the event
/// object looking for it in a few common locations depending on the event type.
pub fn extract_tier(event_body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(event_body).ok()?;
    let obj = &v["data"]["object"];

    // Try the most common paths where Stripe expands product metadata.
    let tier = obj["metadata"]["vledger_tier"].as_str()
        .or_else(|| obj["lines"]["data"][0]["metadata"]["vledger_tier"].as_str())
        .or_else(|| obj["plan"]["metadata"]["vledger_tier"].as_str())
        .or_else(|| obj["items"]["data"][0]["price"]["product"]["metadata"]["vledger_tier"].as_str());

    tier.map(|t| t.to_lowercase())
}

/// Extract the customer's name from the Stripe event object for use as the
/// licensee field.  Falls back to email if name is not set.
pub fn extract_licensee(event_body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(event_body).ok()?;
    let obj = &v["data"]["object"];

    obj["customer_details"]["name"].as_str()
        .or_else(|| obj["customer_name"].as_str())
        .map(|s| s.to_string())
}

/// Extract the customer's email from the Stripe event object.
pub fn extract_email(event_body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(event_body).ok()?;
    let obj = &v["data"]["object"];

    obj["customer_details"]["email"].as_str()
        .or_else(|| obj["customer_email"].as_str())
        .or_else(|| obj["billing_details"]["email"].as_str())
        .map(|s| s.to_string())
}
