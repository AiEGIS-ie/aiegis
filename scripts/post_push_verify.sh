#!/usr/bin/env bash
# post_push_verify.sh — fires after `git push` of AiEGIS-ie/aiegis.
# Verifies the public repo is a faithful, complete, importable copy.
#
# Usage: post_push_verify.sh <expected-commit-sha>
#   <expected-commit-sha> = full sha (or >=7-char prefix) just pushed.
#   Verifies clone HEAD matches; closes the race window where another push
#   lands between our push and our verify call.
#
# Composes with: scripts/pre_push_gate.sh (re-run on the clone as POST-push)
# Retry policy per failure-class: retry only the CDN-lag step (raw fetch);
#   fail-fast on structural steps (clone / gate / pytest / grep).
set -uo pipefail   # set -e omitted: script uses explicit pass/fail counters; -e would short-circuit on first non-zero
shopt -s inherit_errexit 2>/dev/null || true

EXPECTED_SHA="${1:-}"
if [ -z "$EXPECTED_SHA" ]; then
  echo "usage: $0 <expected-commit-sha>" >&2
  echo "  (the sha you just pushed; verify clone HEAD matches before trusting any other check)" >&2
  exit 64
fi
if [ "${#EXPECTED_SHA}" -lt 7 ]; then
  echo "expected-sha must be >=7 chars; got ${#EXPECTED_SHA}" >&2
  exit 64
fi

REPO_HTTPS="https://github.com/AiEGIS-ie/aiegis"
REPO_RAW="https://raw.githubusercontent.com/AiEGIS-ie/aiegis/main"
CLONE_DIR="$(mktemp -d -t aiegis-postpush.XXXXXX)"
ERRORS_PY_EXPECTED_SHA="5ca60e8c"   # canonical errors.py prefix (8-char)
trap 'rm -rf "$CLONE_DIR"' EXIT

pass=0; fail=0
ok()   { printf '  [✓] %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  [✗] %s\n' "$1"; fail=$((fail+1)); }

echo "── post_push_verify ──"
echo "clone target: $CLONE_DIR"

# (1) Clone the public repo — 60s wall-clock cap; rejects network hangs.
# Capture clone-stderr to a log so reader can debug a failure without re-running.
if timeout 60 git clone --depth 1 "$REPO_HTTPS" "$CLONE_DIR" >/tmp/postpush_clone.log 2>&1; then
  ok "git clone $REPO_HTTPS"
else
  clone_exit=$?
  bad "git clone $REPO_HTTPS (exit $clone_exit; see /tmp/postpush_clone.log — repo missing, network, auth, or >60s hang)"
  echo "── RESULT: FAIL ($pass pass / $fail fail) ──"; exit 2
fi

# (1b) Verify clone HEAD matches the expected pushed sha (race-window close)
HEAD_SHA="$(cd "$CLONE_DIR" && git rev-parse HEAD 2>/dev/null || echo MISSING)"
if [ "${HEAD_SHA#"$EXPECTED_SHA"}" != "$HEAD_SHA" ]; then
  ok "clone HEAD ${HEAD_SHA:0:12} matches expected $EXPECTED_SHA"
else
  bad "clone HEAD $HEAD_SHA ≠ expected $EXPECTED_SHA — another push landed, or yours didn't"
  echo "── RESULT: FAIL ($pass pass / $fail fail) ──"; exit 2
fi

# (2) Re-run pre_push_gate.sh on the clone as a POST-push verifier — 90s cap
if [ -x "$CLONE_DIR/scripts/pre_push_gate.sh" ]; then
  if ( cd "$CLONE_DIR" && timeout 90 bash scripts/pre_push_gate.sh ) >/tmp/postpush_gate.log 2>&1; then
    ok "pre_push_gate.sh on clone — 8/8"
  else
    bad "pre_push_gate.sh on clone (see /tmp/postpush_gate.log; exit was $?)"
  fi
else
  bad "scripts/pre_push_gate.sh not present in clone — push dropped files"
fi

# (3) substrate-pack pytest on the clone (catches packaging-broke-imports) — 120s cap
if [ -d "$CLONE_DIR/substrate-pack" ]; then
  if ( cd "$CLONE_DIR" && timeout 120 python -m pytest substrate-pack -q ) >/tmp/postpush_pytest.log 2>&1; then
    ok "substrate-pack pytest on clone"
  else
    bad "substrate-pack pytest (see /tmp/postpush_pytest.log; exit was $?)"
  fi
else
  bad "substrate-pack/ absent in clone"
fi

# (4) raw.githubusercontent.com sha-compare for errors.py — 3x retry, 20s backoff
sha_ok=0
for attempt in 1 2 3; do
  raw=$(timeout 15 curl -fsSL "$REPO_RAW/compliance-bundle/errors.py" 2>/dev/null || true)
  if [ -n "$raw" ]; then
    got=$(printf '%s' "$raw" | shasum -a 256 | awk '{print substr($1,1,8)}')
    if [ "$got" = "$ERRORS_PY_EXPECTED_SHA" ]; then
      ok "raw errors.py sha $got matches $ERRORS_PY_EXPECTED_SHA"
      sha_ok=1; break
    else
      [ $attempt -eq 3 ] && bad "raw errors.py sha $got ≠ $ERRORS_PY_EXPECTED_SHA — content drift"
    fi
  fi
  [ $attempt -lt 3 ] && sleep 20
done
[ $sha_ok -eq 0 ] && [ -z "${raw:-}" ] && bad "raw errors.py unreachable after 3x retry (CDN >60s or path wrong)"

# (5) Grep stale aegis-evidence-pubkey URL (catches per-org-namespace regression)
if grep -rIn "aegis-evidence-pubkey\.pem" "$CLONE_DIR" 2>/dev/null \
     | grep -v "/.well-known/aegis-evidence-pubkey/" \
     | grep -v "post_push_verify\.sh" >/tmp/postpush_grep.log; then
  if [ -s /tmp/postpush_grep.log ]; then
    bad "stale aegis-evidence-pubkey.pem path (non-namespaced) — see /tmp/postpush_grep.log"
  else
    ok "no stale aegis-evidence-pubkey.pem path"
  fi
else
  ok "no stale aegis-evidence-pubkey.pem path"
fi

echo "── RESULT: $([ $fail -eq 0 ] && echo PASS || echo FAIL) ($pass pass / $fail fail) verified-sha=$EXPECTED_SHA ──"
[ $fail -eq 0 ] && exit 0 || exit 1
