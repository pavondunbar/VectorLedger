#!/usr/bin/env bash
# scripts/mutation-test.sh
#
# VectorLedger mutation testing — injects bugs into source code and checks
# whether the test suite catches them.
#
# A "surviving" mutant means a test gap: a code path exists that could be
# wrong and no test would notice.
#
# Usage:
#   ./scripts/mutation-test.sh                            # all configured packages
#   ./scripts/mutation-test.sh --package vledger-crypto   # single package
#   ./scripts/mutation-test.sh --list                     # list mutants only
#   ./scripts/mutation-test.sh --shard 1/4                # CI sharding
#
# Exit codes:
#   0  — completed (surviving mutants are warnings, not errors)
#   2  — cargo-mutants invocation error

set -uo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

PACKAGE_FLAG=""
LIST_FLAG=""
SHARD_FLAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --package)  PACKAGE_FLAG="--package $2"; shift 2 ;;
        --list)     LIST_FLAG="--list"; shift ;;
        --shard)    SHARD_FLAG="--shard $2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

OUTDIR="mutants.out"
MUTANTS_VER=$(cargo mutants --version 2>/dev/null | awk '{print $2}')
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  VectorLedger Mutation Testing (cargo-mutants ${MUTANTS_VER})"
echo "  Package : ${PACKAGE_FLAG:-all configured packages}"
[[ -n "$SHARD_FLAG" ]] && echo "  Shard   : $SHARD_FLAG"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# cargo mutants exits 3 when mutants are missed — that's expected, not an error
# shellcheck disable=SC2086
cargo mutants \
    $PACKAGE_FLAG \
    $LIST_FLAG \
    $SHARD_FLAG \
    --output "$OUTDIR" \
    2>&1

RAW_EXIT=$?

[[ -n "$LIST_FLAG" ]] && exit 0

# Results land in $OUTDIR/mutants.out/ (cargo-mutants nests the dir)
RESULTS="$OUTDIR/mutants.out"

count_lines() {
    local f="$RESULTS/$1"
    [[ -f "$f" ]] && grep -c "" "$f" || echo 0
}

CAUGHT=$(count_lines caught.txt)
SURVIVED=$(count_lines missed.txt)
TIMEOUTS=$(count_lines timeout.txt)
UNVIABLE=$(count_lines unviable.txt)
TOTAL=$(( CAUGHT + SURVIVED + TIMEOUTS ))
SCORE=0
[[ $TOTAL -gt 0 ]] && SCORE=$(( (CAUGHT * 100) / TOTAL ))

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Mutation Testing Results"
echo "  ───────────────────────────────────────────────────"
printf "  %-22s %s\n" "Mutants caught:"   "$CAUGHT   (tests correctly detected the bug)"
printf "  %-22s %s\n" "Mutants survived:" "$SURVIVED  (test gaps — review these)"
printf "  %-22s %s\n" "Timeouts:"         "$TIMEOUTS"
printf "  %-22s %s\n" "Unviable:"         "$UNVIABLE (did not compile)"
echo "  ───────────────────────────────────────────────────"
printf "  %-22s %s%%  (%s / %s caught)\n" "Mutation score:" "$SCORE" "$CAUGHT" "$TOTAL"

if [[ $SURVIVED -gt 0 ]]; then
    echo ""
    echo "  Surviving mutants (first 20):"
    head -20 "$RESULTS/missed.txt" 2>/dev/null | sed 's/^/    /'
    [[ $SURVIVED -gt 20 ]] && echo "    ... and $((SURVIVED - 20)) more — see $RESULTS/missed.txt"
fi

echo ""
if [[ $SURVIVED -eq 0 ]]; then
    echo "  ✅  All mutants caught — no test gaps found."
else
    echo "  ⚠️   $SURVIVED mutant(s) survived — see $RESULTS/missed.txt"
    echo "      These indicate untested code paths. Add tests to cover them."
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Surviving mutants are warnings, not CI-blocking errors.
# Exit 1 only on a real invocation failure (not exit 3 from survivors).
[[ $RAW_EXIT -ne 0 && $RAW_EXIT -ne 3 ]] && exit 1
exit 0
