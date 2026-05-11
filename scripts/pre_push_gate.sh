#!/usr/bin/env bash
# Pre-push gate — run before any registry submission or public push.
# Fans out to all stability + drift checks. Exit 0 = ship green. Exit 1 = block.
#
# ORIGIN: any lane (Velo/Nel/RAV).
# EXECUTION: bash this script from anywhere.
# TARGET: aiegis-compliance-bundle + aiegis.ie VPS.
# AIEGIS_BUNDLE_DIR env var overrides the default path for cross-lane portability.

set -u
PASS=0
FAIL=0
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLE_DIR="${AIEGIS_BUNDLE_DIR:-$HOME/Documents/VELO/aiegis-compliance-bundle}"
PUBLIC_PREP_DIR="${AIEGIS_PUBLIC_PREP_DIR:-$HOME/Documents/VELO/aiegis-public-prep}"
# PYTHON: must point to a python3 that has jsonschema + pytest installed.
# Mac default: /Library/Developer/CommandLineTools/usr/bin/python3 (has them).
# CI override: set AIEGIS_PYTHON after `pip install jsonschema pytest`.
DEFAULT_PYTHON="/Library/Developer/CommandLineTools/usr/bin/python3"
PYTHON="${AIEGIS_PYTHON:-$DEFAULT_PYTHON}"
if [ ! -x "$PYTHON" ]; then
  PYTHON="$(command -v python3 || true)"
fi
if [ -z "$PYTHON" ] || [ ! -x "$PYTHON" ]; then
  echo "no usable python3; set AIEGIS_PYTHON" >&2; exit 2
fi
export PYTHON

# Pinned context shas (Velo lap-104 receipts). Bump deliberately when contexts change.
EXPECTED_COMPLIANCE_SHA="${AIEGIS_COMPLIANCE_CTX_SHA:-}"
EXPECTED_SUBSTRATE_SHA="${AIEGIS_SUBSTRATE_CTX_SHA:-}"

run() {
  local label="$1"
  shift
  echo ""
  echo "=== $label ==="
  if "$@"; then
    PASS=$((PASS+1))
    echo "OK  $label"
  else
    FAIL=$((FAIL+1))
    echo "FAIL  $label"
  fi
}

run "error_codes stability contract" \
    python3 "$BUNDLE_DIR/test_error_codes.py"

run "IdentityError both-worlds contract" \
    python3 "$BUNDLE_DIR/test_errors.py"

run "pytest full suite" \
    bash -c "cd '$BUNDLE_DIR' && "$PYTHON" -m pytest -q 2>&1 | tail -3"

run "JSON-LD @context body verify" \
    bash "$SCRIPT_DIR/verify_jsonld_contexts.sh"

if [ -n "${AIEGIS_SKIP_LIVE:-}" ]; then
  echo ""; echo "=== AIEGIS_SKIP_LIVE set — skipping gates (v)–(viii) ==="
else

run "VPS aiegis.ie reachability" \
    bash -c 'code=$(curl -sI -o /dev/null -w "%{http_code}" https://aiegis.ie); test "$code" = "200"'

run "VPS /api/health 200" \
    bash -c 'code=$(curl -sI -o /dev/null -w "%{http_code}" https://aiegis.ie/api/health); test "$code" = "200"'

run "compliance @context byte-stable" \
    bash -c '
        actual=$(curl -s https://aiegis.ie/ns/compliance/v1 | shasum -a 256 | awk "{print \$1}")
        expected="${EXPECTED_COMPLIANCE_SHA:-7b89231e5ba5a520aeab7f067e2ddb4f29d855e0d415ee26abe6db3cd7737c91}"
        test "$actual" = "$expected" || { echo "drift: $actual != $expected"; exit 1; }
    '

run "substrate @context byte-stable" \
    bash -c '
        actual=$(curl -s https://aiegis.ie/ns/substrate/v1 | shasum -a 256 | awk "{print \$1}")
        expected="${EXPECTED_SUBSTRATE_SHA:-cde816b2c908100164ea273c1f674ad848619d6449f3800202861ec30a8f3247}"
        test "$actual" = "$expected" || { echo "drift: $actual != $expected"; exit 1; }
    '

fi  # AIEGIS_SKIP_LIVE end

run "grid.schema.json validates grid_example_smb.json" \
    bash -c '
        schema="'"$PUBLIC_PREP_DIR"'/spec/grid.schema.json"
        example="'"$PUBLIC_PREP_DIR"'/spec/grid_example_smb.json"
        for f in "$schema" "$example"; do
          [ -e "$f" ] || { echo "missing: $f"; exit 1; }
        done
        "$PYTHON" - <<PY
import json, sys, jsonschema
schema = json.load(open("$schema"))
example = json.load(open("$example"))
jsonschema.Draft202012Validator.check_schema(schema)
v = jsonschema.Draft202012Validator(schema)
errs = list(v.iter_errors(example))
if errs:
    for e in errs[:5]:
        path = ".".join(map(str, e.path)) or "<root>"
        print(f"DRIFT: {path} → {e.message[:140]}", file=sys.stderr)
    sys.exit(1)
print("grid_example_smb.json: 0 schema errors")
PY
    '

run "test-count consistency (README ↔ CHANGELOG ↔ pytest)" \
    bash -c '
        readme="'"$PUBLIC_PREP_DIR"'/README.md"
        changelog="'"$PUBLIC_PREP_DIR"'/CHANGELOG.md"
        bundle="'"$BUNDLE_DIR"'"
        for f in "$readme" "$changelog" "$bundle"; do
          [ -e "$f" ] || { echo "missing: $f"; exit 1; }
        done
        # Extract (N on substrate-pack, M on compliance-bundle) from README
        r_sub=$(grep -oE "[0-9]+ on substrate-pack" "$readme" | head -1 | grep -oE "[0-9]+")
        r_bun=$(grep -oE "[0-9]+ on compliance-bundle" "$readme" | head -1 | grep -oE "[0-9]+")
        # Same from CHANGELOG (Substrate-pack section: "N tests"; Compliance-bundle section: "M tests")
        c_sub=$(awk "/### Substrate-pack/{f=1} f&&/[0-9]+ tests/{match(\$0,/[0-9]+/); print substr(\$0,RSTART,RLENGTH); exit}" "$changelog")
        c_bun=$(awk "/### Compliance-bundle/{f=1} f&&/[0-9]+ tests/{match(\$0,/[0-9]+/); print substr(\$0,RSTART,RLENGTH); exit}" "$changelog")
        # Live compliance-bundle pytest count
        live_bun=$(cd "$bundle" && "$PYTHON" -m pytest --collect-only -q 2>/dev/null | tail -1 | grep -oE "[0-9]+ tests? collected" | grep -oE "[0-9]+" | head -1)
        echo "README:    substrate=$r_sub  compliance=$r_bun"
        echo "CHANGELOG: substrate=$c_sub  compliance=$c_bun"
        echo "pytest:    compliance=$live_bun"
        [ -n "$r_sub" ] && [ "$r_sub" = "$c_sub" ] || { echo "substrate count drift between README ($r_sub) and CHANGELOG ($c_sub)"; exit 1; }
        [ -n "$r_bun" ] && [ "$r_bun" = "$c_bun" ] && [ "$r_bun" = "$live_bun" ] || { echo "compliance count drift: README=$r_bun CHANGELOG=$c_bun pytest=$live_bun"; exit 1; }
    '

echo ""
echo "================================"
echo "PRE-PUSH GATE: $PASS pass / $FAIL fail"
if [[ $FAIL -eq 0 ]]; then
  echo "GREEN — ship clear"
  exit 0
else
  echo "RED — block push"
  exit 1
fi
