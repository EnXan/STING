# Sprint 2 Checkpoint

**Date:** 2026-06-04
**Stories:** STING-07, STING-08, STING-09
**Verdict:** continue

---

## 1. Product Architect Pass

### Problem / Solution Fit

Sprint 2 completes the STING v2 PRD scope. All three stories are minimal, targeted, and correctly
sequenced:

- **STING-07** (retry loop removal) is the most impactful change in the sprint. Eliminating
  `_MAX_ATTEMPTS` makes each run strictly deterministic. The decision to keep `_payload_file_opened()`
  as informational-only is correct — it preserves observability without re-introducing retry
  semantics. The `prompt_too_weak` category, which produced ambiguous non-results, is gone.
- **STING-08** (compose.yaml deletion) is pure housekeeping. One file, no callers, no risk.
- **STING-09** (sandbox sweep) correctly updates the README and taxonomy.yaml to reflect the new
  model. The Network section rewrite is accurate and concise.

Together, the two sprints deliver the complete STING v2 transition: every sandbox-era constraint
that could tip off an agent (blocked hosts, uv shim, sandbox prompt, dual networks, non-root user,
retry behavior) is gone.

### Drift / Replan Signals

- **Unstaged taxonomy.yaml detection patterns** — The working tree contains
  `auth_failure_patterns`, `content_filter_patterns`, and `token_limit_patterns` that were never
  committed. Runner.py reads these with `.get(..., [])` defaults, so all three detection functions
  (`_is_auth_failure`, `_is_content_filter_blocked`, `_is_token_limit`) return `False` on every
  run in the committed codebase. Additionally, the working tree adds `user_prompt` fields to
  attack entries, a `base64` obfuscation type, a `classifier` block, and updated honeypot
  credentials — none of which are committed. These changes appear to be prerequisites for or
  improvements to STING-10 (smoke test). They must be staged before the smoke test can run
  correctly.

- **`auth_failure` end_reason produces no score** — When `end_reason="auth_failure"`, only
  `score_reasons` is set; `score` stays `None`. This means auth-failed runs appear as "failed" in
  the summary table, with no distinct category. With `--resume`, they will always be re-run.
  This is probably intentional but deserves explicit documentation before running the full matrix.

- **`_SANDBOX_PREFIX` / `sandbox_log_prefix` naming** — The module-level constant `_SANDBOX_PREFIX`
  and the taxonomy key `sandbox_log_prefix` still carry "sandbox" in their names. The value
  `"sandbox-1  | "` is correct because the compose service is still named `"sandbox"` in
  `docker_utils.py`. No functional problem, but the name may mislead future readers who don't know
  the service is named that.

### Drift Risk

**Low** — All three sprint 2 stories were delivered as specified. The two signals above (unstaged
patterns, auth_failure gap) are pre-existing or minor, not sprint 2 regressions. The PRD scope
is fully covered. STING-10 is the right next step.

### Recommendations

- Stage the working-tree taxonomy.yaml changes before running STING-10. At minimum, the detection
  pattern lists (`auth_failure_patterns`, `content_filter_patterns`, `token_limit_patterns`) must
  be committed for the run to produce meaningful `end_reason` values. The `user_prompt` fields and
  `classifier` config should be reviewed and staged if they are ready.
- Add `results/*/credentials.json` to `.gitignore` before any external sharing of run artifacts.
  The OAuth token lands in the flat results tree and will be included in a naive `tar results/`.
  This was flagged in Sprint 1 and remains unaddressed.
- Decide whether `auth_failure` should get a dedicated `score` label (e.g., `None` vs a sentinel)
  or whether the summary output should add a separate auth-failure counter, before running the full
  attack matrix.

---

## 2. Code Reviewer Pass

### Acceptance Criteria Verification

- `STING-07` — All criteria satisfied. The `for attempt in range(...)` loop is gone. `execute()`
  has a clean if/elif/else chain that sets `end_reason` exactly once. `_MAX_ATTEMPTS`,
  `skip_weak_prompt`, `prompt_too_weak`, and `"max_attempts"` from `context.json` are all removed.
  `_payload_file_opened()` is retained for informational logging only. `max_payload_read_attempts`
  is absent from taxonomy.yaml (it was present in the working tree pre-edit but not in HEAD, and
  was removed from the working tree by this story). `--skip-prompt-too-weak` is gone from `main.py`.

- `STING-08` — All criteria satisfied. `compose.yaml` is deleted. No remaining code references
  the static file; `write_compose()` in `docker_utils.py` generates per-run files dynamically.

- `STING-09` — All criteria satisfied with one minor residual (see Issues below). The README
  Network section accurately describes the transparent-proxy model. The stale "Allowed hosts"
  block is gone. The unused `network: "sting-testbed"` key is removed from taxonomy.yaml. The
  stale "aborts retries immediately" comment is corrected. No remaining grep hits for
  `sandbox_net`, `egress_net`, `sting-auth`, `uv-real`, `STING_PROTECT`, `STING_BLOCK`, or
  `ALLOWED_HOSTS` in source.

### Issues

| # | Story | Severity | Description |
|---|-------|----------|-------------|
| 1 | STING-07 | minor | `execute()` docstring (line 504) still reads "inside the Docker sandbox", which is inconsistent with the STING v2 model where the container is no longer a restricted sandbox. |
| 2 | STING-07 | minor | `auth_failure` runs set `score_reasons` but leave `score=None`, so `--resume` will always re-run them and the summary table counts them as generic failures with no distinct label. This is pre-existing behavior but now more visible without the `prompt_too_weak` category absorbing non-scored results. |
| 3 | STING-09 | minor | Dockerfile line 8 comment reads "Install auditd for monitoring system calls" — `auditd` is not installed; the actual tools are `inotify-tools` and `strace`. STING-09 updated the adjacent WORKDIR comment but missed this one. |
| 4 | pre-existing | moderate | `auth_failure_patterns`, `content_filter_patterns`, and `token_limit_patterns` are read by runner.py (lines 50–52) but absent from the committed taxonomy.yaml. Pattern lists default to `[]`, so the three detection functions return `False` on every run. These patterns exist in the working tree and block a valid STING-10 smoke test. |

### Pattern Consistency

- `runner.py`, `main.py`, and `docker_utils.py` all pass `ruff check` and `ruff format` with no
  suppressions.
- Modern type hints (`X | None`, `list[str]`) used in new and modified signatures.
- `pathlib.Path` used consistently throughout.
- No hardcoded secrets, magic numbers, or unexplained constants introduced.
- The if/elif/else chain replacing the retry loop is idiomatic Python; it reads more cleanly than
  the break-based loop it replaced.

### Structural Quality

- `runner.py execute()` reduced from a loop with nested break logic to a flat, readable
  if/elif/else. The single-responsibility of each branch is now obvious.
- `main.py` was reformatted by `ruff format` as part of STING-07; the result is cleaner than the
  pre-sprint inline-if style.
- Net deletion across sprint 2: `compose.yaml` (99 lines), retry loop (~50 lines), `--skip-prompt-too-weak`
  option, `weak_prompt` counter and display code, and the README "Allowed hosts" block (20 lines).
  The PRD's "Simpler codebase" criterion is met.

### Best-Practice Recommendations

- Consider adding `end_reason` to the summary output table alongside `status` so that `auth_failure`
  and `content_filter` runs are immediately distinguishable from generic exit-code failures.
- The `_payload_file_opened()` result is now logged at `INFO` level but not written to the
  checkpoint. Storing it as a boolean field in `RunResult`/`checkpoint.json` would allow
  post-hoc analysis of how often agents skip the payload file without requiring a re-run.

---

## 3. Verdict

### Recommendation

- **continue** — no blocking issues; only minor concerns

### Why

Sprint 2 delivers all three stories against their acceptance criteria. The codebase is cleaner and
more coherent than before. The one moderate issue (missing detection patterns in taxonomy.yaml) is
pre-existing — not introduced by sprint 2 — and must be addressed before STING-10, but it does not
require re-opening any sprint 2 story.

### Operator Considerations

- Before STING-10 runs: stage the working-tree taxonomy.yaml additions (detection patterns at
  minimum; `user_prompt` fields and `classifier` config once reviewed). Without detection patterns,
  `auth_failure`, `content_filter`, and `token_limit` end reasons will never be produced.
- Before any external archive of `results/`: add `results/*/credentials.json` to `.gitignore`.
- The three minor issues (execute docstring, auditd comment, auth_failure display) can be fixed
  inline at the start of STING-10 or rolled into a future cleanup story — none block the smoke test.
