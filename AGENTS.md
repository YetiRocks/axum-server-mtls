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

### Root cause

The HTTPS proxy in the remote execution environment tears down the TCP
connection after forwarding the packfile to GitHub, before GitHub finishes
writing the ref and streaming the sideband acknowledgment back to the client.
`git-send-pack` treats the abrupt disconnect as an HTTP error and exits 1.
GitHub has already accepted and committed the ref update server-side.

The `Everything up-to-date` line that appears alongside the fatal error is the
tell: Git's local ref-tracking was updated successfully — it "knows" the remote
already has the tag — even though the RPC layer reported a failure.

### Confirmed pattern across two runs

| Run | Version | Tag push exit | `ls-remote` immediate | `ls-remote` +5 s |
|-----|---------|---------------|-----------------------|------------------|
| 1   | v0.1.110 | 1 (HTTP 403) | present               | —                |
| 2   | v0.1.111 | 1 (HTTP 403) | **empty**             | present ✓        |

Run 2 shows there is a propagation delay: `ls-remote` returned empty
immediately after the push, then showed the tag after 5 seconds. This rules
out a simple false-negative and confirms the proxy closes the connection before
GitHub finishes processing.

### Remote auth config

| Setting | Value |
|---|---|
| `remote.origin.url` | `https://github.com/YetiRocks/axum-server-mtls` |
| `remote.origin.pushurl` | *(not set)* |
| `credential.helper` | *(not set)* |
| Main branch push | exit 0 (clean — commit pushes work fine) |
| Tag push exit code | 1 (non-zero, spurious) |

---

## Fix (implemented 2026-08-25)

### Layer 1 — preferred: let GitHub Actions handle tagging

`.github/workflows/auto-tag.yml` was already in the repo for exactly this
reason. It fires on every push to `main` that bumps `Cargo.toml`, and creates
the annotated tag using `GITHUB_TOKEN` (`contents: write`), which is not
subject to the proxy disconnect. Remote agent sessions should push to `main`
and stop there.

### Layer 2 — fallback: `push_tag_verified.sh`

For cases where a direct tag push from a remote session is unavoidable,
`.github/scripts/push_tag.sh` wraps `git push` with an `ls-remote` retry loop
(5-second intervals, 30-second timeout). It exits 0 if the tag appears on
origin within the window — discriminating a proxy false-negative from a genuine
auth failure without ignoring exit codes blindly.

```bash
bash .github/scripts/push_tag.sh v<version>
```

### Why not just ignore the exit code?

A real auth failure (wrong token scope, branch protection, etc.) also exits 1.
The `ls-remote` check is the discriminator. If the tag is on origin, the push
worked; if not after the retry window, the failure is genuine.

---

## Run history

| Date       | Version  | Main push | Tag push source    | Tag on remote? |
|------------|----------|-----------|--------------------|----------------|
| 2026-08-25 | v0.1.110 | exit 0    | agent (direct)     | Yes (via proxy false-negative) |
| 2026-08-25 | v0.1.111 | exit 0    | agent (direct)     | Yes (5-second delay)           |
| 2026-08-25 | v0.1.112 | exit 0    | auto-tag.yml (GHA) | *see workflow run*             |
