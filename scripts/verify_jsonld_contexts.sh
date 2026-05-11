#!/usr/bin/env bash
# Verify all @context URLs cited in substrate-binding spec are HTTP 200 AND
# contain expected term-definitions in body. Per Nel lap-92 + Velo gap-hypothesis
# joint pin: HTTP 200 alone is insufficient — body must contain expected terms.
#
# Exit 0 = all green. Exit 1 = drift detected.
# Run as part of pre-push gate before any registry submission.

set -u

declare -a CHECKS=(
  "https://aiegis.ie/ns/compliance/v1|AiEGISComplianceBundle"
  "https://aiegis.ie/ns/substrate/v1|SubstrateAttestation"
  "https://www.w3.org/ns/did/v1|assertionMethod"
  "https://w3id.org/security/suites/ed25519-2020/v1|Ed25519VerificationKey2020"
  "https://www.w3.org/ns/credentials/v2|VerifiableCredential"
  "https://w3id.org/security/data-integrity/v2|DataIntegrityProof"
)

fail=0
CTX_TMP="$(mktemp -t aiegis-ctx.XXXXXX)"
trap 'rm -f "$CTX_TMP"' EXIT
for check in "${CHECKS[@]}"; do
  url="${check%%|*}"
  term="${check##*|}"
  status=$(curl -s --max-time 10 -o "$CTX_TMP" -w "%{http_code}" -L "$url" || echo "000")
  if [[ "$status" != "200" ]]; then
    echo "FAIL  $url  HTTP $status"
    fail=1
    continue
  fi
  if grep -q "$term" "$CTX_TMP"; then
    echo "PASS  $url  contains '$term'"
  else
    echo "FAIL  $url  HTTP 200 but missing term '$term'"
    fail=1
  fi
done

if [[ $fail -eq 0 ]]; then
  echo "---"
  echo "ALL ${#CHECKS[@]} @context URLs verified (header + body)"
  exit 0
else
  echo "---"
  echo "DRIFT DETECTED — block pre-push gate"
  exit 1
fi
