#!/usr/bin/env bash
# Everything that can be checked without a Go compiler or a browser.
# Run this before handing anything over.
set -u
cd "$(dirname "$0")/.."
fail=0
run() { printf "%-22s " "$1"; shift; if out=$("$@" 2>&1); then echo "${out##*$'\n'}"; else echo "FAILED"; echo "$out" | sed 's/^/    /'; fail=1; fi; }

run "go: braces"      python3 .verify/gobalance.py
run "go: imports"     python3 .verify/goimports.py
run "go: duplicates"  python3 .verify/godupes.py
run "go: undefined"   python3 .verify/goundef.py
run "ts: types"       bash .verify/tscheck.sh
for m in sidx fieldfilter-parity kind-detect result-separators; do
  run "js: $m" node ".verify/$m.mjs"
done
exit $fail
