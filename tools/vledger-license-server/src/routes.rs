//! Axum route handlers.
//!
//! ## Endpoints
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | `POST` | `/webhook` | Stripe webhook receiver |
//! | `GET`  | `/license/:token` | One-time 72-hour download link |
//! | `GET`  | `/license/current` | Pull endpoint (`?token=<api_token>`) |
//! | `GET`  | `/health` | Uptime check |
//!
//! ## Webhook flow
//!
//! ```text
//! POST /webhook
//!   │
//!   ├─ verify Stripe-Signature header
//!   ├─ parse event type
//!   │
//!   ├─ checkout.session.completed ──► issue_and_deliver() → first license
//!   ├─ invoice.payment_succeeded  ──► renew_and_deliver()  → renewal license
//!   ├─ invoice.payment_failed     ──► send payment-failed warning email
//!   ├─ customer.subscription.deleted ► log only (expiry handles enforcement)
//!   └─ anything else              ──► 200 OK, ignored
//! ```

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use crate::{
    AppState,
    db::{LicenseRecord, new_id},
    email,
    error::ServerError,
    signing,
    stripe::{self, StripeEvent},
};

// ── Health ────────────────────────────────────────────────────────────────────

pub async fn health() -> Response {
    (StatusCode::OK, Json(json!({
        "status": "ok",
        "service": "vledger-license-server",
        "ts": Utc::now().to_rfc3339(),
    }))).into_response()
}

// ── Stripe webhook ────────────────────────────────────────────────────────────

pub async fn stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers:      HeaderMap,
    body:         Bytes,
) -> Result<Response, ServerError> {
    // ── 1. Verify signature ───────────────────────────────────────────────
    let sig_header = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            ServerError::WebhookSignature("missing Stripe-Signature header".into())
        })?;

    stripe::verify_signature(sig_header, &body, &state.config.stripe_webhook_secret)?;

    // ── 2. Parse event ────────────────────────────────────────────────────
    let event = stripe::parse_event(&body)?;

    // ── 3. Dispatch ───────────────────────────────────────────────────────
    match event {
        StripeEvent::CheckoutSessionCompleted {
            stripe_customer_id,
            stripe_subscription_id,
            current_period_end,
        } => {
            // Derive expiry: use period_end if Stripe provided it, otherwise
            // fall back to 30 days + 7-day grace from now.
            let expires_at = current_period_end
                .map(signing::expiry_for_period_end)
                .unwrap_or_else(signing::expiry_monthly_from_now);

            // Extract licensee name, email, and tier from the event body.
            let email_addr = stripe::extract_email(&body)
                .unwrap_or_else(|| "unknown@unknown.com".into());
            let licensee = stripe::extract_licensee(&body)
                .unwrap_or_else(|| email_addr.clone());
            let tier = stripe::extract_tier(&body)
                .unwrap_or_else(|| "starter".into());

            issue_and_deliver(
                &state,
                &stripe_customer_id,
                &stripe_subscription_id,
                &licensee,
                &email_addr,
                &tier,
                &expires_at,
                /* is_renewal */ false,
            ).await?;
        }

        StripeEvent::InvoicePaymentSucceeded {
            stripe_customer_id,
            stripe_subscription_id,
            current_period_end,
        } => {
            let expires_at = signing::expiry_for_period_end(current_period_end);

            // For renewals, look up the customer's existing license to reuse
            // their licensee name and tier.  If somehow we have no prior
            // record (e.g. the checkout event was lost), fall back to
            // extracting from the invoice body.
            let (licensee, email_addr, tier) =
                if let Some(prev) = state.db.latest_license_for_subscription(
                    &stripe_subscription_id
                )? {
                    (prev.licensee, prev.email, prev.tier)
                } else {
                    let email_addr = stripe::extract_email(&body)
                        .unwrap_or_else(|| "unknown@unknown.com".into());
                    let licensee = stripe::extract_licensee(&body)
                        .unwrap_or_else(|| email_addr.clone());
                    let tier = stripe::extract_tier(&body)
                        .unwrap_or_else(|| "starter".into());
                    (licensee, email_addr, tier)
                };

            issue_and_deliver(
                &state,
                &stripe_customer_id,
                &stripe_subscription_id,
                &licensee,
                &email_addr,
                &tier,
                &expires_at,
                /* is_renewal */ true,
            ).await?;
        }

        StripeEvent::InvoicePaymentFailed {
            stripe_customer_id,
            stripe_subscription_id,
        } => {
            // Look up existing license to get email, tier, and expiry for
            // the warning email.
            if let Some(prev) = state.db.latest_license_for_subscription(
                &stripe_subscription_id
            )? {
                if let Err(e) = email::send_payment_failed_email(
                    &state.http,
                    &state.config.resend_api_key,
                    &state.config.email_from,
                    &prev.email,
                    &prev.licensee,
                    &prev.tier,
                    &prev.expires_at,
                ).await {
                    // Non-fatal — log and continue.  The grace period still
                    // protects the customer even if the email fails.
                    warn!(
                        customer = %stripe_customer_id,
                        error    = %e,
                        "Failed to send payment-failed email"
                    );
                }
            } else {
                warn!(
                    customer = %stripe_customer_id,
                    sub      = %stripe_subscription_id,
                    "invoice.payment_failed but no prior license found — nothing to notify"
                );
            }
        }

        StripeEvent::SubscriptionDeleted {
            stripe_customer_id,
            stripe_subscription_id,
        } => {
            // No action — the existing license expires on its own schedule.
            // Log so we have a record.
            info!(
                customer = %stripe_customer_id,
                sub      = %stripe_subscription_id,
                "Subscription deleted — license will expire naturally"
            );
        }

        StripeEvent::Unhandled { event_type } => {
            info!(event_type, "Ignoring unhandled Stripe event");
        }
    }

    Ok((StatusCode::OK, Json(json!({ "received": true }))).into_response())
}

// ── License download (one-time token) ────────────────────────────────────────

pub async fn download_license(
    State(state): State<Arc<AppState>>,
    Path(token):  Path<String>,
) -> Result<Response, ServerError> {
    // Consume the token — returns None if expired or already used.
    let dt = state.db.consume_download_token(&token)?
        .ok_or(ServerError::TokenExpired)?;

    // Load the license record.
    let rec = state.db.get_license(&dt.license_id)?
        .ok_or_else(|| ServerError::NotFound("license record not found".into()))?;

    info!(
        license_id = %rec.id,
        email      = %rec.email,
        tier       = %rec.tier,
        "License downloaded via one-time token"
    );

    Ok((
        StatusCode::OK,
        [
            ("Content-Type",        "application/json"),
            ("Content-Disposition", "attachment; filename=\"license.json\""),
            ("Cache-Control",       "no-store"),
        ],
        rec.license_json,
    ).into_response())
}

// ── License pull endpoint (long-lived API token) ──────────────────────────────

#[derive(Deserialize)]
pub struct PullQuery {
    token: String,
}

pub async fn pull_license(
    State(state): State<Arc<AppState>>,
    Query(q):     Query<PullQuery>,
) -> Result<Response, ServerError> {
    let rec = state.db.get_license_for_api_token(&q.token)?
        .ok_or_else(|| ServerError::NotFound(
            "token not found, expired, or revoked".into()
        ))?;

    info!(
        license_id = %rec.id,
        email      = %rec.email,
        tier       = %rec.tier,
        "License pulled via API token"
    );

    Ok((
        StatusCode::OK,
        [
            ("Content-Type",        "application/json"),
            ("Content-Disposition", "attachment; filename=\"license.json\""),
            ("Cache-Control",       "no-store"),
        ],
        rec.license_json,
    ).into_response())
}

// ── Shared: issue + deliver ───────────────────────────────────────────────────

/// Sign a new license, store it, create tokens, and send the appropriate
/// email.  Called for both new subscriptions and renewals.
async fn issue_and_deliver(
    state:          &AppState,
    customer_id:    &str,
    subscription_id: &str,
    licensee:       &str,
    email_addr:     &str,
    tier:           &str,
    expires_at:     &str,
    is_renewal:     bool,
) -> Result<(), ServerError> {
    // ── Sign the license ──────────────────────────────────────────────────
    let (license_json, features_csv) = signing::issue_license(
        &state.config.license_signing_key,
        licensee,
        email_addr,
        tier,
        expires_at,
        None,
    )?;

    // ── Store in DB ───────────────────────────────────────────────────────
    let license_id = new_id();
    let issued_at  = Utc::now().format("%Y-%m-%d").to_string();

    let rec = LicenseRecord {
        id:                     license_id.clone(),
        stripe_customer_id:     customer_id.to_string(),
        stripe_subscription_id: subscription_id.to_string(),
        licensee:               licensee.to_string(),
        email:                  email_addr.to_string(),
        tier:                   tier.to_string(),
        issued_at,
        expires_at:             expires_at.to_string(),
        features:               features_csv,
        license_json:           license_json.clone(),
        created_at:             Utc::now(),
    };

    state.db.insert_license(&rec)?;

    info!(
        license_id = %license_id,
        customer   = %customer_id,
        sub        = %subscription_id,
        tier,
        expires_at,
        renewal    = is_renewal,
        "License issued"
    );

    // ── Create download token (one-time, 72h) ─────────────────────────────
    let download_token = state.db.create_download_token(&license_id, email_addr)?;
    let download_url   = format!(
        "{}/license/{}",
        state.config.base_url.trim_end_matches('/'),
        download_token
    );

    // ── Create or repoint API token (long-lived pull) ─────────────────────
    // On first subscription, create a new API token.
    // On renewal, repoint existing API tokens to the new license record.
    let api_token = if is_renewal {
        state.db.repoint_api_tokens_for_subscription(subscription_id, &license_id)?;
        // Return the existing token by looking it up — the repoint updated
        // the license_id it points at.  We need a token string for the email;
        // retrieve the first valid one for this subscription.
        // If none exists (e.g. prior token was consumed or revoked), create a new one.
        state.db.get_api_token_for_subscription(subscription_id)?
            .unwrap_or_else(|| {
                // Fallback: create fresh (shouldn't happen in normal flow).
                state.db.create_api_token(&license_id, email_addr)
                    .unwrap_or_default()
            })
    } else {
        state.db.create_api_token(&license_id, email_addr)?
    };

    // ── Send email ────────────────────────────────────────────────────────
    let email_result = if is_renewal {
        email::send_renewal_email(
            &state.http,
            &state.config.resend_api_key,
            &state.config.email_from,
            email_addr,
            licensee,
            tier,
            expires_at,
            &download_url,
            &api_token,
            &state.config.base_url,
        ).await
    } else {
        email::send_new_license_email(
            &state.http,
            &state.config.resend_api_key,
            &state.config.email_from,
            email_addr,
            licensee,
            tier,
            expires_at,
            &download_url,
            &api_token,
            &license_json,
            &state.config.base_url,
        ).await
    };

    // Email failure is non-fatal — the license is stored and the customer
    // can still pull it via the API token.  Log the error prominently so
    // ops can follow up manually.
    if let Err(e) = email_result {
        warn!(
            license_id = %license_id,
            email      = %email_addr,
            error      = %e,
            "License issued but email delivery failed — customer must pull manually"
        );
    }

    Ok(())
}
