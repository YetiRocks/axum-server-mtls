# Claude Code — Session Notes

## Tag pushing

**Do not push tags directly from a remote session.** The workflow
`.github/workflows/auto-tag.yml` fires on every push to `main` that bumps
`Cargo.toml`, and creates the annotated tag via `GITHUB_TOKEN` (which has the
required `contents: write` scope). The remote agent's HTTPS proxy tears down
the connection before git receives the sideband acknowledgment, causing a
spurious HTTP 403 exit-1 even when the push succeeded — unreliable.

**Correct release flow for maintenance tasks:**
1. Bump `version` in `Cargo.toml`.
2. Run `cargo build` (refreshes `Cargo.lock`).
3. `git add -A && git commit && git push origin HEAD:main`
4. Done — `auto-tag.yml` handles the tag; `publish.yml` handles crates.io.

**If a direct tag push is unavoidable**, use the verified wrapper:
```bash
bash .github/scripts/push_tag.sh v<version>
```
It tolerates the proxy false-negative and confirms via `ls-remote`.

## Diagnostic notes

See [AGENTS.md](./AGENTS.md) for the full write-up of the HTTP 403 proxy
disconnect error and the run history that characterised it.
