#!/usr/bin/env bash
# scripts/formal-verify.sh
#
# VectorLedger formal verification — runs Kani proof harnesses.
#
# Kani is a bit-precise model checker that exhaustively explores all
# reachable program states for bounded inputs, proving the ABSENCE of
# panics, overflows, and violated assertions — not just testing on
# specific inputs.
#
# Usage:
#   ./scripts/formal-verify.sh                          # run all harnesses
#   ./scripts/formal-verify.sh --harness kdf_same_context_same_key
#   ./scripts/formal-verify.sh --list                   # list all harnesses
#
# Exit codes:
#   0  — all proofs succeeded (no violations found)
#   1  — one or more proofs failed (counterexample found)

set -uo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

HARNESS_FLAG=""
LIST_FLAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --harness) HARNESS_FLAG="--harness $2"; shift 2 ;;
        --list)    LIST_FLAG="list"; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

KANI_VER=$(cargo kani --version 2>/dev/null | head -1 | awk '{print $4}')
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  VectorLedger Formal Verification (Kani ${KANI_VER})"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# List harnesses only
if [[ "$LIST_FLAG" == "list" ]]; then
    cargo kani list --package vledger-kani 2>&1
    exit 0
fi

# Run proofs
# shellcheck disable=SC2086
cargo kani \
    --package vledger-kani \
    $HARNESS_FLAG \
    2>&1

EXIT_CODE=$?

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ $EXIT_CODE -eq 0 ]]; then
    echo "  ✅  All Kani proofs PASSED"
    echo "      Every harness was exhaustively verified."
else
    echo "  ❌  One or more Kani proofs FAILED"
    echo "      A counterexample was found. See output above."
    echo "      This means an assertion can be violated by some input."
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
exit $EXIT_CODE
