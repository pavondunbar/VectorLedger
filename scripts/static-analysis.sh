#!/usr/bin/env bash
# scripts/static-analysis.sh
#
# VectorLedger static analysis — cargo clippy with project-specific lint rules.
#
# Two passes:
#   Pass 1 — correctness + suspicious lints on all lib code (hard errors)
#   Pass 2 — additional security lints on the financial/crypto packages only
#
# Usage:
#   ./scripts/static-analysis.sh            # CI default
#   ./scripts/static-analysis.sh --fix      # auto-fix safe lints
#
# Exit codes:  0 = pass,  1 = deny-level lint fired

set -uo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

FIX_FLAG=""
[[ "${1:-}" == "--fix" ]] && FIX_FLAG="--fix --allow-dirty --allow-staged"

CLIPPY_VER=$(cargo +stable clippy --version 2>/dev/null | awk '{print $2}')
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  VectorLedger Static Analysis (clippy ${CLIPPY_VER})"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

OVERALL=0

# Shared allow flags (suppress noisy style lints that add no value here)
ALLOW=(
    -A clippy::must_use_candidate
    -A clippy::module_name_repetitions
    -A clippy::wildcard_imports
    -A clippy::missing_errors_doc
    -A clippy::missing_panics_doc
    -A clippy::missing_docs_in_private_items
    -A clippy::similar_names
    -A clippy::too_many_lines
    -A clippy::option_if_let_else
    -A clippy::return_self_not_must_use
    -A clippy::use_self
    -A clippy::too_many_arguments
)

# ── Pass 1: correctness + suspicious on all lib code ─────────────────────────
echo ""
echo "Pass 1: All lib code — correctness and suspicious lints"
echo "────────────────────────────────────────────────────────"

# shellcheck disable=SC2086
cargo +stable clippy --workspace $FIX_FLAG --lib --no-deps -- \
    -D clippy::correctness \
    -D clippy::suspicious \
    -D clippy::await_holding_lock \
    -D clippy::let_underscore_lock \
    -D clippy::ptr_arg \
    -D clippy::todo \
    -D clippy::unimplemented \
    -W clippy::perf \
    -W clippy::style \
    -W unused_variables \
    -W dead_code \
    "${ALLOW[@]}" \
    -A clippy::unwrap_used \
    -A clippy::expect_used \
    -A clippy::panic \
    -A clippy::indexing_slicing \
    -A clippy::cast_possible_truncation \
    -A clippy::cast_sign_loss \
    2>&1
P1=$?; [[ $P1 -ne 0 ]] && OVERALL=1

# ── Pass 2: strict security lints on financial / crypto packages only ─────────
echo ""
echo "Pass 2: Financial/crypto packages — panic safety + cast safety"
echo "────────────────────────────────────────────────────────────────"

# These packages handle money, keys, and authentication.
# unwrap/expect/panic/cast violations here are hard errors.
STRICT=(vledger-crypto vledger-audit vledger-foureyes vledger-license
        vledger-compliance vledger-replication)

for pkg in "${STRICT[@]}"; do
    # shellcheck disable=SC2086
    cargo +stable clippy -p "$pkg" $FIX_FLAG --lib --no-deps -- \
        -D clippy::correctness \
        -D clippy::suspicious \
        -D clippy::unwrap_used \
        -D clippy::expect_used \
        -D clippy::panic \
        -D clippy::todo \
        -D clippy::unimplemented \
        -D clippy::cast_possible_truncation \
        -D clippy::cast_sign_loss \
        -D clippy::indexing_slicing \
        -W clippy::perf \
        "${ALLOW[@]}" \
        2>&1
    [[ $? -ne 0 ]] && OVERALL=1
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ $OVERALL -eq 0 ]]; then
    echo "  ✅  Static analysis PASSED"
else
    echo "  ❌  Static analysis FAILED — fix the errors above before merging."
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
exit $OVERALL
