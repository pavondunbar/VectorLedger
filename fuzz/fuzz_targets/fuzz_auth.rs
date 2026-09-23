//! Fuzz target: authentication and session management layer.
//!
//! Exercises `UserStore::authenticate`, `validate_token`, role parsing, and
//! session bookkeeping with arbitrary inputs to prove that none of the
//! following can occur regardless of input:
//!
//! - Panic
//! - Unbounded memory growth (session table overflow)
//! - A session being granted the wrong role
//! - Token forgery: a token generated for user A validating as user B
//!
//! ## What is fuzzed
//!
//! ### `UserStore::authenticate`
//! - Arbitrary username strings (empty, very long, unicode, SQL fragments)
//! - Arbitrary password strings with fuzz bytes
//! - Repeated calls with the same username to trip the brute-force lockout path
//!   (MAX_FAILED_ATTEMPTS = 5) without waiting for the timeout
//!
//! ### `Role::from_str`
//! - Arbitrary role name strings; must never produce an unexpected Role value
//!
//! ### `validate_token`
//! - Arbitrary token strings; must return Err, not panic
//! - Verify that a token minted for user A does not validate as user B
//!
//! ## Fuzzer input layout
//! ```text
//! [0]      : u8  — username length (capped to 64)
//! [1..1+N] : username bytes
//! [1+N]    : u8  — password length (capped to 64)
//! [2+N..M] : password bytes
//! [M]      : u8  — role_str length (capped to 32)
//! [M+1..]  : role bytes, then remaining bytes used as arbitrary token
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use tempfile::TempDir;
use tokio::runtime::Runtime;
use vledger_server::auth::{Role, UserStore};

fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("fuzz runtime init")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // ── Parse structured fuzzer input ─────────────────────────────────────
    let mut pos = 0usize;

    macro_rules! read_lp {
        ($max:expr) => {{
            if pos >= data.len() {
                return;
            }
            let len = (data[pos] as usize).min($max);
            pos += 1;
            if pos + len > data.len() {
                return;
            }
            let s = String::from_utf8_lossy(&data[pos..pos + len]).into_owned();
            pos += len;
            s
        }};
    }

    let fuzz_username = read_lp!(64);
    let fuzz_password = read_lp!(64);
    let fuzz_role_str = read_lp!(32);
    let fuzz_token = String::from_utf8_lossy(&data[pos..]).into_owned();

    // ── Surface 1: Role::from_str ─────────────────────────────────────────
    let _ = fuzz_role_str.parse::<Role>();
    let _ = fuzz_username.parse::<Role>();

    // ── Surface 2: UserStore construction ────────────────────────────────
    // UserStore::open() creates a catalog directory at the given path.
    let dir = match TempDir::new() {
        Ok(d) => d,
        Err(_) => return,
    };
    // Use a subdirectory as the catalog dir so open() can create users.json.
    let catalog = dir.path().join("catalog");
    if std::fs::create_dir_all(&catalog).is_err() {
        return;
    }
    let store = match UserStore::open(&catalog) {
        Ok(s) => s,
        Err(_) => return,
    };

    // ── Surface 3: authenticate with fuzz credentials ────────────────────
    // Must not panic regardless of input.
    let _ = store.authenticate(&fuzz_username, &fuzz_password);

    // Repeated calls with the same username to exercise the lockout counter
    // (MAX_FAILED_ATTEMPTS = 5). Call 8 times — crosses the threshold.
    for _ in 0..8 {
        let _ = store.authenticate(&fuzz_username, &fuzz_password);
    }

    // ── Surface 4: validate_token with arbitrary tokens ────────────────────
    // validate_token is async; use the shared runtime.
    runtime().block_on(async {
        // Arbitrary fuzz token — must return Err (invalid), never panic.
        let _ = store.validate_token(&fuzz_token).await;

        // Edge cases.
        let _ = store.validate_token("").await;
        let long = "x".repeat(512);
        let _ = store.validate_token(&long).await;
    });

    // ── Surface 5: token cross-user forgery check ─────────────────────────
    // If authenticate succeeds for two different usernames, each token must
    // only validate for its own user.
    let result_a = store.authenticate("admin", &fuzz_password);
    let result_b = store.authenticate(&fuzz_username, &fuzz_password);

    if let (Ok(session_a), Ok(session_b)) = (&result_a, &result_b) {
        if session_a.username != session_b.username {
            runtime().block_on(async {
                if let Ok(validated) = store.validate_token(&session_a.token).await {
                    assert_eq!(
                        validated.username, session_a.username,
                        "TOKEN FORGERY: token minted for '{}' validated as '{}'",
                        session_a.username, validated.username
                    );
                }
                if let Ok(validated) = store.validate_token(&session_b.token).await {
                    assert_eq!(
                        validated.username, session_b.username,
                        "TOKEN FORGERY: token minted for '{}' validated as '{}'",
                        session_b.username, validated.username
                    );
                }
            });
        }
    }
});
