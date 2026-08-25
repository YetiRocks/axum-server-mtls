# Tag-Push Diagnostic Notes

## Observed Error (2026-08-25)

When pushing a tag to `origin` via HTTPS in the Claude Code remote execution
environment, `git push origin <tagname>` exits non-zero with:

```
error: RPC failed; HTTP 403 curl 22 The requested URL returned error: 403
send-pack: unexpected disconnect while reading sideband packet
fatal: the remote end hung up unexpectedly
Everything up-to-date
```

Exit code: **1**

### Key detail

Despite the error output, the tag **does land on the remote**. A subsequent
`git ls-remote --tags origin` confirms the tag ref and its dereferenced commit
SHA are present on GitHub. The fallback push
(`git push origin refs/tags/<tag>:refs/tags/tag>`) then fails with
`(already exists)`, which is further confirmation the first push succeeded.

### Pattern

| Observation | Value |
|---|---|
| `remote.origin.url` | `https://github.com/YetiRocks/axum-server-mtls` |
| `remote.origin.pushurl` | *(not set)* |
| `credential.helper` | *(not set)* |
| Main branch push | succeeds cleanly (exit 0) |
| Tag push exit code | 1 (non-zero) |
| Tag actually on remote? | **Yes** |

### Confirmed behavior (second run, v0.1.111)

Run 2 (same session) reproduced the exact same error. `git ls-remote`
immediately after the push returned **empty** — but after a 5-second delay
the tag appeared. This rules out a pure false-negative (where the tag lands
instantly) and instead points to a **propagation delay** on GitHub's side, or
more likely the proxy forwarding the packfile and then closing the connection
before GitHub has finished writing the ref and sending the sideband
acknowledgment back.

Timeline in run 2:

1. `git push origin v0.1.111` → exit 1, HTTP 403
2. `git ls-remote --tags origin | grep v0.1.111` → *empty*
3. `sleep 5`
4. `git ls-remote --tags origin | grep v0.1.111` → tag present ✓

### Root cause hypothesis

The HTTPS proxy in the remote execution environment closes the TCP connection
after forwarding the pack data to GitHub, before GitHub finishes writing the
ref and streaming the sideband acknowledgment back to the client. Git's
send-pack treats the abrupt disconnect as an HTTP error (403 from the proxy's
error page on close) and exits 1. GitHub has already accepted and committed the
ref update server-side.

The `Everything up-to-date` line that appears alongside the fatal error is the
tell: Git's local ref-tracking (FETCH_HEAD / packed-refs) was updated
successfully — it "knows" the remote already has the tag — even though the RPC
layer reported a failure.

## Run history

| Date | Version | Main push | Tag push exit | ls-remote immediate | ls-remote +5s |
|---|---|---|---|---|---|
| 2026-08-25 | v0.1.110 | exit 0 | exit 1 (HTTP 403) | present | — |
| 2026-08-25 | v0.1.111 | exit 0 | exit 1 (HTTP 403) | **empty** | present ✓ |

## Proposed Fix

Do not treat a non-zero exit code from `git push origin <tag>` as a definitive
failure in this environment. Instead, after any tag-push that exits non-zero,
**verify via `git ls-remote` with a short retry loop** before deciding whether
to escalate.

### Shell wrapper (drop-in replacement for tag push steps)

```bash
push_tag_verified() {
  local tag="$1"
  local max_wait=30  # seconds
  local interval=5

  # Attempt the push; capture output regardless of exit code.
  local output
  output=$(git push origin "$tag" 2>&1)
  local rc=$?

  if [ $rc -eq 0 ]; then
    echo "push_tag: pushed $tag (exit 0)"
    return 0
  fi

  # Non-zero exit — check whether GitHub actually received the tag.
  echo "push_tag: git push exited $rc; verifying via ls-remote..."
  echo "$output"

  local elapsed=0
  while [ $elapsed -le $max_wait ]; do
    if git ls-remote --tags origin | grep -q "refs/tags/${tag}$"; then
      echo "push_tag: $tag confirmed on origin after ${elapsed}s delay (proxy disconnect false-negative)"
      return 0
    fi
    sleep $interval
    elapsed=$((elapsed + interval))
  done

  echo "push_tag: $tag NOT found on origin after ${max_wait}s — genuine failure"
  return 1
}
```

### Usage

```bash
push_tag_verified v0.1.112
```

### Why not just ignore exit codes?

Blindly ignoring exit 1 would mask a genuine auth failure (e.g. a token that
truly lacks `write:packages` or `repo` scope). The ls-remote check is the
discriminator: if the tag is on origin, the push worked. If it is not, the
failure is real.

### Alternative: GitHub MCP / API

If the proxy behavior worsens (e.g. ls-remote also starts returning stale
data), the clean escape hatch is to create the tag ref directly via the GitHub
API (`POST /repos/{owner}/{repo}/git/refs`) instead of `git push`. This
bypasses the proxy's send-pack path entirely. The GitHub MCP server tools
available in Claude Code sessions can do this without any extra credentials.
