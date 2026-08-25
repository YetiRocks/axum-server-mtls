#!/usr/bin/env bash
# push_tag.sh — verified tag push for Claude Code remote sessions.
#
# In the remote execution environment the HTTPS proxy tears down the
# connection after forwarding the packfile, causing git-send-pack to exit 1
# with HTTP 403 even when GitHub has already accepted the ref. This wrapper
# treats a non-zero exit as inconclusive and verifies via ls-remote instead.
#
# Usage: .github/scripts/push_tag.sh <tagname>
#   e.g. .github/scripts/push_tag.sh v0.1.112
#
# NOTE: Prefer letting .github/workflows/auto-tag.yml handle tagging after
# a main-branch push. Use this script only when a direct tag push is required.

set -euo pipefail

TAG="${1:?Usage: push_tag.sh <tagname>}"
MAX_WAIT=30   # seconds total
INTERVAL=5    # seconds between ls-remote retries

push_output=$(git push origin "$TAG" 2>&1) && rc=0 || rc=$?

if [ "$rc" -eq 0 ]; then
  echo "push_tag: $TAG pushed (exit 0)"
  exit 0
fi

echo "push_tag: git push exited $rc — verifying via ls-remote (proxy may have disconnected after successful upload)"
echo "$push_output"

elapsed=0
while [ "$elapsed" -le "$MAX_WAIT" ]; do
  if git ls-remote --tags origin | grep -q "refs/tags/${TAG}$"; then
    echo "push_tag: $TAG confirmed on origin after ${elapsed}s (proxy false-negative)"
    exit 0
  fi
  sleep "$INTERVAL"
  elapsed=$((elapsed + INTERVAL))
done

echo "push_tag: ERROR — $TAG not found on origin after ${MAX_WAIT}s; genuine failure"
exit 1
