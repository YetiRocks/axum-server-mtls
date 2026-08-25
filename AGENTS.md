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
(`git push origin refs/tags/<tag>:refs/tags/<tag>`) then fails with
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

### Hypothesis

The HTTPS proxy in the remote execution environment closes the TCP connection
after forwarding the pack data to GitHub. Git's send-pack receives an abrupt
disconnect on the sideband reply channel and surfaces it as HTTP 403, but
GitHub has already accepted and applied the ref update. This is a
connection-teardown race, not an authorization failure.

The `Everything up-to-date` line appearing alongside the fatal error is unusual
and supports this: Git's local ref tracking was updated (it "knows" the tag is
already at origin) even though the RPC error fired.

## Run history

| Date | Version | Main push | Tag push exit | Tag on remote? |
|---|---|---|---|---|
| 2026-08-25 | v0.1.110 | exit 0 | exit 1 (HTTP 403) | Yes |

## Proposed Fix

See bottom of this file after the next monitored run.
