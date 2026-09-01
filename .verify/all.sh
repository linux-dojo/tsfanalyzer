#!/usr/bin/env bash
# Everything that can be checked without a Go compiler or a browser.
# Run this before handing anything over.
#
# Checks are grouped by the tool they need. A missing tool is reported as
# SKIPPED, not FAILED, and does not fail the run: "node is not installed" is a
# fact about the machine, not a defect in the code, and a checker that cries
# failure over its own prerequisites is one people learn to ignore.
#
# Skipping is loud rather than silent, though. The summary says exactly what
# was not covered, because "all green" has to mean "everything ran and passed"
# — a clean run that quietly skipped the TypeScript check is worse than a
# noisy one.
set -u
cd "$(dirname "$0")/.."

pass=0
fail=0
declare -a skipped=()

have() { command -v "$1" >/dev/null 2>&1; }

run() {
  local label=$1; shift
  printf "%-22s " "$label"
  local out
  if out=$("$@" 2>&1); then
    echo "${out##*$'\n'}"
    pass=$((pass + 1))
  else
    echo "FAILED"
    echo "$out" | sed 's/^/    /'
    fail=$((fail + 1))
  fi
}

skip() {
  printf "%-22s SKIPPED (%s)\n" "$1" "$2"
  skipped+=("$1")
}

# ---- Go: pure Python, so these run anywhere ------------------------------
if have python3; then
  run "go: braces"     python3 .verify/gobalance.py
  run "go: imports"    python3 .verify/goimports.py
  run "go: duplicates" python3 .verify/godupes.py
  run "go: undefined"  python3 .verify/goundef.py
else
  for c in braces imports duplicates undefined; do
    skip "go: $c" "python3 not installed"
  done
fi

# ---- TypeScript and the JS harnesses: need node --------------------------
if have node; then
  run "ts: types" bash .verify/tscheck.sh
  for m in sidx fieldfilter-parity kind-detect result-separators; do
    run "js: $m" node ".verify/$m.mjs"
  done
else
  skip "ts: types" "node not installed"
  for m in sidx fieldfilter-parity kind-detect result-separators; do
    skip "js: $m" "node not installed"
  done
fi

echo
if [ ${#skipped[@]} -gt 0 ]; then
  echo "$pass passed, $fail failed, ${#skipped[@]} skipped."
  echo "Not covered on this machine: ${skipped[*]}"
  if ! have node; then
    echo "  Install node to run them:  brew install node   (macOS)"
    echo "                             apt install nodejs   (Debian/Ubuntu)"
  fi
else
  echo "$pass passed, $fail failed."
fi

# A skipped check is not a failure, but a real one is.
exit $((fail > 0 ? 1 : 0))
