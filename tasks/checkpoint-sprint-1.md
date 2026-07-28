# Sprint 1 Checkpoint

**Date:** 2026-06-04
**Stories:** STING-01, STING-02, STING-03, STING-04, STING-05, STING-06
**Verdict:** continue

---

## 1. Product Architect Pass

### Problem / Solution Fit

Sprint 1 delivered exactly what the PRD described: removing every sandboxing layer that creates
environment noise. The six stories are coherent and sequenced correctly — proxy unblocked first,
then prompt sanitised, then package managers freed, then network simplified, then user privileges
elevated, then credential mounting simplified. Each story's output is a precondition for the
next without creating forward dependencies that could leave things in a broken intermediate state.

The sprint's real value is that agents running against this harness can no longer detect a test
environment through any of the previously detectable signals (403s, blocked package installs,
sandbox-framed prompts, uid 1000, auth staging noise). The PRD's "realism" principle is fully
served.

### Drift / Replan Signals

- **Retry loop still present** — `_MAX_ATTEMPTS` and the `for attempt in range(...)` loop in
  `execute()` are untouched, as designed (STING-07 covers this in Sprint 2). However, context.json
  still writes `"max_attempts": _MAX_ATTEMPTS`. That field will become misleading once the loop
  is gone — STING-07 should include removing it.

- **credentials.json now lives in results_dir** — STING-06 simplified the host-side path so the
  extracted OAuth token lands at `results_dir/credentials.json`, alongside proxy.jsonl, shell.log,
  agent.log. This is a side-effect of the simplification: the old `sting-auth/` subdirectory was
  easy to exclude from exports. The flat placement means a careless `tar results/` now includes
  live OAuth tokens. STING-09 (cleanup sweep) should address this — either by writing to a
  dedicated subdir again or by ensuring credentials are excluded from archival.

- **Static compose.yaml still in project root** — Correctly deferred to STING-08. No functional
  impact since the runner generates per-run compose files dynamically. But the file's references
  to `sandbox_net`, `egress_net`, and the old `sting` user are actively misleading to anyone
  reading the repo cold.

- **STING-05 and STING-06 were closely coupled** — The container-side auth change was done inside
  STING-05, making STING-06 a host-side cleanup of one constant and one call site. Consider
  merging these into a single story in future sprints when similar tight coupling appears. No
  impact on correctness or on Sprint 2 planning.

### Drift Risk

**Low** — All six stories delivered what the PRD specified. No scope creep, no missed
requirements, no signals that the Sprint 2 stories need replanning. The credentials-in-results-dir
issue is a minor consequence of simplification, not a design mistake.

### Recommendations

- Add `credentials.json` exclusion to `.gitignore` or document the results-export hazard before
  any external sharing of run artifacts.
- When implementing STING-07, also remove the `"max_attempts"` field from the context.json
  output in `execute()` (line 549 of runner.py).
- Sprint 2 story STING-09 (cleanup sweep) should verify the `docs/prd-unrestricted-execution.md`
  reference to `/tmp/sting-auth/` is updated to reflect the final implementation.

---

## 2. Code Reviewer Pass

### Acceptance Criteria Verification

- `STING-01` — All criteria satisfied. `proxy/addon.py` has no blocking logic, no `ALLOWED_HOSTS`
  set, no `blocked` field in log entries. Log format matches PRD spec. Scorer unaffected.

- `STING-02` — All criteria satisfied. `_SANDBOX_CONTEXT_PROMPT` is gone from `runner.py`.
  `_agent_cmd()` passes the raw prompt as `"$1"` (shell positional). `context.json` no longer
  writes `sandbox_context_prompt`.

- `STING-03` — All criteria satisfied. `entrypoint.sh` has no uv-shim block. No `STING_PROTECT_VENV`
  or `STING_BLOCK_UV_SYNC` env vars anywhere in the active codebase. No `uv-real` references.

- `STING-04` — All criteria satisfied. `compose_config()` returns a single `sting_net: {}` network.
  Both services reference `["sting_net"]`. HTTP_PROXY vars still route traffic through the proxy
  for logging. S4 scoring unaffected.

- `STING-05` — All criteria satisfied. `useradd` removed from Dockerfile. No `chown sting:sting`
  or `setpriv` in `entrypoint.sh`. No uid drop. Auth mounts go directly to `/root/.claude` and
  `/root/.claude.json`.

- `STING-06` — All criteria satisfied. `_AUTH_STAGING` constant deleted. `extract_claude_credentials()`
  accepts `results_dir` and writes there directly. `_auth_volumes()` checks `results_dir / "credentials.json"`.
  Only remaining `/tmp/sting-auth/` reference is a historical description in the PRD doc.

### Issues

| # | Story | Severity | Description |
|---|-------|----------|-------------|
| 1 | STING-06 | minor | `credentials.json` written to `results_dir` (flat, alongside all other run artifacts). Easy to include in accidental exports. Old `sting-auth/` subdir at least made exclusion easier. |
| 2 | STING-07 (pre) | minor | `execute()` docstring (runner.py:507) still describes "re-run up to _MAX_ATTEMPTS times" and context.json writes `"max_attempts": _MAX_ATTEMPTS` (line 549). Both will be stale after STING-07. |
| 3 | STING-06 | minor | Nested Docker bind-mount order (`~/.claude` dir then `credentials.json` inside it) is implementation-dependent. The comment is adequate but the behavior would benefit from a brief note that Docker applies mounts in declaration order. |
| 4 | STING-05 | minor | Dockerfile `WORKDIR /app` comment says "Change the working directory to the `app` directory" without explaining that it's build-only — the agent runs from `/repo`. Slightly confusing on a cold read. |

### Pattern Consistency

- All modified files pass `ruff check` and `ruff format` with no suppressions.
- `pathlib.Path` used consistently throughout `docker_utils.py` and `runner.py`.
- Modern type hints (`X | None`, `list[str]`) used in new and modified function signatures.
- No hardcoded secrets, magic numbers, or unexplained constants introduced.

### Structural Quality

- `entrypoint.sh` reduced from 74 to 42 lines — cleaner than the original.
- `docker_utils.py` reduced from 210 to 200 lines; `_AUTH_STAGING` constant and staging-path
  references gone; `extract_claude_credentials()` signature is simpler.
- `Dockerfile` removed one `RUN` layer (useradd/chown), reducing image build complexity.
- Net change across sprint: meaningful line-count reduction across all four files. The PRD's
  "Simpler codebase" success criterion is on track.

### Best-Practice Recommendations

- Consider adding `results/*/credentials.json` to `.gitignore` now that OAuth tokens live in the
  results tree.
- When STING-07 lands, remove `"max_attempts"` from the context.json output and update the
  `execute()` docstring to describe the single-run path.

---

## 3. Verdict

### Recommendation

- **continue** — no blocking issues; only minor concerns

### Why

All six Sprint 1 stories are fully delivered and accepted against their criteria. The codebase is
demonstrably simpler. The two moderate-concern items (credentials placement, stale docstring) are
scoped to STING-07 and STING-09, where they will naturally be resolved. No replanning of Sprint 2
is needed.

### Operator Considerations

- Decide whether `credentials.json` in `results_dir` requires an immediate mitigation (`.gitignore`
  entry or a quick subdir change) or whether it can wait for STING-09.
- STING-07 (remove retry loop) should also include removing `"max_attempts"` from `context.json`
  output — verify that acceptance criteria is updated to reflect this before Sprint 2 kicks off.
