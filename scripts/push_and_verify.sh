#!/usr/bin/env bash
# push_and_verify.sh — push the current branch + immediately verify the public mirror.
# Wraps `git push` so the operator never has to remember to pass the just-pushed sha
# to post_push_verify.sh.
#
# Usage: bash scripts/push_and_verify.sh [remote] [branch]
#   defaults: remote=origin, branch=main
#
# Composes with: scripts/post_push_verify.sh (which we invoke with the captured sha)
set -uo pipefail

REMOTE="${1:-origin}"
BRANCH="${2:-main}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERIFIER="$SCRIPT_DIR/post_push_verify.sh"

if [ ! -x "$VERIFIER" ]; then
  echo "missing or non-executable: $VERIFIER" >&2; exit 2
fi

# Capture the local HEAD sha BEFORE pushing — that is the sha we want verified.
LOCAL_SHA="$(git rev-parse HEAD 2>/dev/null || true)"
if [ -z "$LOCAL_SHA" ]; then
  echo "git rev-parse HEAD failed — not in a git repo or no commits" >&2; exit 2
fi
echo "→ local HEAD: $LOCAL_SHA"

# Auth preflight: confirm we can reach github with credentials BEFORE pushing.
# Fails fast with actionable message instead of cryptic "Permission denied" from git.
if ! git ls-remote "$REMOTE" HEAD >/dev/null 2>/tmp/push_auth.log; then
  echo "auth preflight failed — git ls-remote $REMOTE could not authenticate" >&2
  echo "  see /tmp/push_auth.log; common fixes:" >&2
  echo "    gh auth login            # if you use HTTPS + gh CLI" >&2
  echo "    ssh -T git@github.com    # if you use SSH (should print your username)" >&2
  echo "    git remote -v            # confirm $REMOTE points where you expect" >&2
  exit 3
fi

# Push, capturing stdout+stderr so we can cross-check the sha range git reports.
echo "→ git push $REMOTE $BRANCH"
PUSH_OUT="$(git push "$REMOTE" "$BRANCH" 2>&1)"
PUSH_EXIT=$?
echo "$PUSH_OUT"
if [ $PUSH_EXIT -ne 0 ]; then
  echo "git push failed (exit $PUSH_EXIT) — skipping verify; nothing to clone" >&2
  exit "$PUSH_EXIT"
fi

# Cross-check: git push reports "old..new" or "new" (for new branch). Grep for LOCAL_SHA prefix.
# If git push didn't echo our sha, that's a signal something unexpected happened (force-push, hook rewrite, etc).
if ! printf '%s\n' "$PUSH_OUT" | grep -qE "${LOCAL_SHA:0:7}"; then
  echo "warning: git push output did not reference local sha ${LOCAL_SHA:0:12}; verifying anyway against local HEAD" >&2
fi

echo ""
echo "→ post_push_verify.sh $LOCAL_SHA"
exec bash "$VERIFIER" "$LOCAL_SHA"
