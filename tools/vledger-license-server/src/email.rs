//! Email delivery via the Resend API.
//!
//! Resend (<https://resend.com>) is a transactional email API with a simple
//! REST interface.  We use it directly over `reqwest` rather than pulling
//! in an SDK so we control exactly what is sent and logged.
//!
//! ## Required environment variables
//! | Variable | Description |
//! |---|---|
//! | `RESEND_API_KEY` | Resend API key (starts with `re_`) |
//! | `EMAIL_FROM` | Sender address, e.g. `licenses@vectorguardlabs.com` |
//!
//! ## Two email templates
//! - **New license** — sent when a customer signs up for the first time.
//!   Includes the `license.json` as an attachment and a one-time download
//!   link good for 72 hours.
//! - **Renewal** — sent on every successful recurring payment.
//!   Includes the renewed `license.json` and the persistent pull-endpoint
//!   API token so the customer can automate renewal via cron.

use reqwest::Client;
use serde_json::json;
use tracing::{error, info};

use crate::error::ServerError;

// ── Public API ────────────────────────────────────────────────────────────────

/// Send the initial "your license is ready" email to a new customer.
///
/// - `download_url` — one-time 72-hour link pointing at
///   `GET /license/<token>` on this server.
/// - `api_token`    — long-lived pull token for
///   `GET /license/current?token=<api_token>`.
/// - `license_json` — the signed `license.json` content, attached inline.
pub async fn send_new_license_email(
    http:         &Client,
    resend_key:   &str,
    from:         &str,
    to:           &str,
    licensee:     &str,
    tier:         &str,
    expires_at:   &str,
    download_url: &str,
    api_token:    &str,
    license_json: &str,
    base_url:     &str,
) -> Result<(), ServerError> {
    let tier_display = tier_display_name(tier);
    let subject      = format!("Your VectorLedger {tier_display} License");

    let html = new_license_html(
        licensee, tier_display, expires_at,
        download_url, api_token, license_json, base_url,
    );
    let text = new_license_text(
        licensee, tier_display, expires_at,
        download_url, api_token, base_url,
    );

    send(http, resend_key, from, to, &subject, &html, &text).await
}

/// Send the "your license has been renewed" email to an existing customer.
///
/// - `download_url` — one-time 72-hour link for the renewed `license.json`.
/// - `api_token`    — same long-lived pull token as before (unchanged).
pub async fn send_renewal_email(
    http:         &Client,
    resend_key:   &str,
    from:         &str,
    to:           &str,
    licensee:     &str,
    tier:         &str,
    expires_at:   &str,
    download_url: &str,
    api_token:    &str,
    base_url:     &str,
) -> Result<(), ServerError> {
    let tier_display = tier_display_name(tier);
    let subject      = format!("VectorLedger {tier_display} License Renewed");

    let html = renewal_html(
        licensee, tier_display, expires_at,
        download_url, api_token, base_url,
    );
    let text = renewal_text(
        licensee, tier_display, expires_at,
        download_url, api_token, base_url,
    );

    send(http, resend_key, from, to, &subject, &html, &text).await
}

/// Send a payment failure warning email.
/// Does not cancel the license — just notifies the customer to update
/// their payment method before the grace period expires.
pub async fn send_payment_failed_email(
    http:       &Client,
    resend_key: &str,
    from:       &str,
    to:         &str,
    licensee:   &str,
    tier:       &str,
    expires_at: &str,
) -> Result<(), ServerError> {
    let tier_display = tier_display_name(tier);
    let subject = format!(
        "Action required: VectorLedger {tier_display} payment failed"
    );

    let html = payment_failed_html(licensee, tier_display, expires_at);
    let text = payment_failed_text(licensee, tier_display, expires_at);

    send(http, resend_key, from, to, &subject, &html, &text).await
}

// ── Core send ─────────────────────────────────────────────────────────────────

async fn send(
    http:       &Client,
    resend_key: &str,
    from:       &str,
    to:         &str,
    subject:    &str,
    html:       &str,
    text:       &str,
) -> Result<(), ServerError> {
    let body = json!({
        "from":    from,
        "to":      [to],
        "subject": subject,
        "html":    html,
        "text":    text,
    });

    let resp = http
        .post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {resend_key}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| ServerError::Email(e.to_string()))?;

    let status = resp.status();
    if status.is_success() {
        info!(to, subject, "Email sent via Resend");
        Ok(())
    } else {
        let body_text = resp.text().await.unwrap_or_default();
        error!(
            to, subject,
            status = status.as_u16(),
            response = %body_text,
            "Resend API error"
        );
        Err(ServerError::Email(format!(
            "Resend returned HTTP {}: {}", status, body_text
        )))
    }
}

// ── Email templates ───────────────────────────────────────────────────────────

fn new_license_html(
    licensee:     &str,
    tier:         &str,
    expires_at:   &str,
    download_url: &str,
    api_token:    &str,
    license_json: &str,
    base_url:     &str,
) -> String {
    format!(r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          color: #1a1a1a; max-width: 600px; margin: 0 auto; padding: 24px; }}
  .badge {{ display: inline-block; background: #0f172a; color: #fff;
             font-size: 12px; font-weight: 600; padding: 3px 10px;
             border-radius: 4px; letter-spacing: 0.05em; }}
  .btn {{ display: inline-block; background: #2563eb; color: #fff;
           text-decoration: none; padding: 10px 20px; border-radius: 6px;
           font-weight: 600; margin: 16px 0; }}
  pre {{ background: #f1f5f9; padding: 12px; border-radius: 6px;
          font-size: 12px; overflow-x: auto; }}
  .note {{ font-size: 13px; color: #64748b; border-left: 3px solid #e2e8f0;
             padding-left: 12px; margin: 16px 0; }}
</style></head>
<body>
<p>Hi {licensee},</p>
<p>Your <strong>VectorLedger {tier}</strong> license is ready.</p>

<table cellpadding="0" cellspacing="0" style="margin:16px 0">
  <tr><td style="width:120px;color:#64748b">Tier</td>
      <td><span class="badge">{tier}</span></td></tr>
  <tr><td style="color:#64748b">Expires</td>
      <td><strong>{expires_at}</strong></td></tr>
</table>

<p><strong>Step 1 — Download your license file</strong><br>
Click the button below to download <code>license.json</code>.
This link is valid for 72 hours.</p>

<a class="btn" href="{download_url}">Download license.json</a>

<p><strong>Step 2 — Install it</strong></p>
<pre>cp license.json ./vledger-data/license.json
vledger start --data-dir ./vledger-data</pre>

<p><strong>Step 3 — Automate renewals (optional)</strong><br>
Your license is renewed automatically on each billing cycle.
To receive the new file without clicking an email link, add this
to a daily cron job on your server:</p>

<pre>curl -sSf "{base_url}/license/current?token={api_token}" \
  -o /path/to/vledger-data/license.json</pre>

<div class="note">
  Keep your API token private — it provides read-only access to your
  current license file and is tied to your subscription.
</div>

<p><strong>Your current license.json</strong></p>
<pre>{license_json}</pre>

<hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
<p style="font-size:13px;color:#64748b">
  Questions? Reply to this email or contact
  <a href="mailto:support@vectorguardlabs.com">support@vectorguardlabs.com</a>.<br>
  VectorGuard Labs — financial infrastructure that proves its own integrity.
</p>
</body>
</html>"#,
    licensee     = licensee,
    tier         = tier,
    expires_at   = expires_at,
    download_url = download_url,
    api_token    = api_token,
    license_json = html_escape(license_json),
    base_url     = base_url,
    )
}

fn new_license_text(
    licensee:     &str,
    tier:         &str,
    expires_at:   &str,
    download_url: &str,
    api_token:    &str,
    base_url:     &str,
) -> String {
    format!(
        "Hi {licensee},\n\n\
         Your VectorLedger {tier} license is ready.\n\n\
         Tier    : {tier}\n\
         Expires : {expires_at}\n\n\
         STEP 1 — Download your license.json (valid 72 hours):\n\
         {download_url}\n\n\
         STEP 2 — Install it:\n\
         cp license.json ./vledger-data/license.json\n\
         vledger start --data-dir ./vledger-data\n\n\
         STEP 3 — Automate renewals (daily cron):\n\
         curl -sSf \"{base_url}/license/current?token={api_token}\" \\\n  \
             -o /path/to/vledger-data/license.json\n\n\
         Keep your API token private.\n\n\
         Questions? support@vectorguardlabs.com\n\
         VectorGuard Labs\n"
    )
}

fn renewal_html(
    licensee:     &str,
    tier:         &str,
    expires_at:   &str,
    download_url: &str,
    api_token:    &str,
    base_url:     &str,
) -> String {
    format!(r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          color: #1a1a1a; max-width: 600px; margin: 0 auto; padding: 24px; }}
  .btn {{ display: inline-block; background: #2563eb; color: #fff;
           text-decoration: none; padding: 10px 20px; border-radius: 6px;
           font-weight: 600; margin: 16px 0; }}
  pre {{ background: #f1f5f9; padding: 12px; border-radius: 6px;
          font-size: 12px; overflow-x: auto; }}
</style></head>
<body>
<p>Hi {licensee},</p>
<p>Your <strong>VectorLedger {tier}</strong> subscription has been renewed.</p>

<table cellpadding="0" cellspacing="0" style="margin:16px 0">
  <tr><td style="width:120px;color:#64748b">Tier</td>
      <td><strong>{tier}</strong></td></tr>
  <tr><td style="color:#64748b">New expiry</td>
      <td><strong>{expires_at}</strong></td></tr>
</table>

<p>Download your renewed <code>license.json</code> (link valid 72 hours):</p>
<a class="btn" href="{download_url}">Download renewed license.json</a>

<p>Or pull it automatically using your API token:</p>
<pre>curl -sSf "{base_url}/license/current?token={api_token}" \
  -o /path/to/vledger-data/license.json</pre>

<hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
<p style="font-size:13px;color:#64748b">
  VectorGuard Labs —
  <a href="mailto:support@vectorguardlabs.com">support@vectorguardlabs.com</a>
</p>
</body>
</html>"#,
    licensee     = licensee,
    tier         = tier,
    expires_at   = expires_at,
    download_url = download_url,
    api_token    = api_token,
    base_url     = base_url,
    )
}

fn renewal_text(
    licensee:     &str,
    tier:         &str,
    expires_at:   &str,
    download_url: &str,
    api_token:    &str,
    base_url:     &str,
) -> String {
    format!(
        "Hi {licensee},\n\n\
         Your VectorLedger {tier} subscription has been renewed.\n\n\
         Tier       : {tier}\n\
         New expiry : {expires_at}\n\n\
         Download your renewed license.json (valid 72 hours):\n\
         {download_url}\n\n\
         Or pull automatically:\n\
         curl -sSf \"{base_url}/license/current?token={api_token}\" \\\n  \
             -o /path/to/vledger-data/license.json\n\n\
         VectorGuard Labs — support@vectorguardlabs.com\n"
    )
}

fn payment_failed_html(licensee: &str, tier: &str, expires_at: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          color: #1a1a1a; max-width: 600px; margin: 0 auto; padding: 24px; }}
  .warning {{ background: #fef3c7; border-left: 4px solid #f59e0b;
               padding: 12px 16px; border-radius: 4px; margin: 16px 0; }}
</style></head>
<body>
<p>Hi {licensee},</p>

<div class="warning">
  <strong>Payment failed</strong> — your VectorLedger {tier} subscription
  could not be renewed.
</div>

<p>Your current license remains active until <strong>{expires_at}</strong>.
After that date, VectorLedger will automatically downgrade to the Free tier.</p>

<p>To keep your {tier} features, please update your payment method in the
<a href="https://billing.stripe.com">billing portal</a> before that date.
Stripe will retry the payment automatically.</p>

<hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
<p style="font-size:13px;color:#64748b">
  Need help?
  <a href="mailto:support@vectorguardlabs.com">support@vectorguardlabs.com</a>
</p>
</body>
</html>"#,
    licensee   = licensee,
    tier       = tier,
    expires_at = expires_at,
    )
}

fn payment_failed_text(licensee: &str, tier: &str, expires_at: &str) -> String {
    format!(
        "Hi {licensee},\n\n\
         Your VectorLedger {tier} payment failed.\n\n\
         Your license remains active until {expires_at}. After that, \
         VectorLedger will downgrade to the Free tier.\n\n\
         Update your payment method at https://billing.stripe.com\n\n\
         Questions? support@vectorguardlabs.com\n\
         VectorGuard Labs\n"
    )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn tier_display_name(tier: &str) -> &str {
    match tier {
        "starter"    => "Starter",
        "growth"     => "Growth",
        "enterprise" => "Enterprise",
        _            => "Free",
    }
}

/// Minimal HTML escaping for embedding JSON in <pre> blocks.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}
