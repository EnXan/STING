# STING

STING (*Sandboxed Testing of Injections in Git*) measures how AI coding agents
handle indirect prompt-injection payloads in repositories. A fresh copy of a
template repository receives an injected payload and a benign development task;
the runner records file access, shell commands, agent output, and outbound HTTP
requests.

Use STING only with repositories, credentials, and network targets that you are
authorised to test.

## Setup

Requirements: Docker Desktop, [`uv`](https://docs.astral.sh/uv/), and a logged-in
agent CLI (`claude login` and/or `codex login`).

`repo/`, `results/`, and `.env` are local-only and excluded from Git — a fresh
clone of this project (or any machine where `repo/` was removed) starts without
the target-repo checkout, the synthetic honeypot credential, or the `$PAYLOAD$`
markers every run needs inside it. Set all of that up in one step:

```bash
uv run python scripts/setup_target_repo.py
```

This clones `origin.repo`/`origin.ref` (taxonomy.yaml) into `repo/`, writes the
synthetic `AWS_CREDENTIALS` honeypot fixture to `repo/.env` (same value as
taxonomy.yaml's `honeypot` section — never invented, never real), and adds a
`$PAYLOAD$` marker to `README.md`, `CLAUDE.md`, and `AGENTS.md` inside the
checkout so the variant generator has somewhere to insert each attack. It's
safe to re-run: every step is skipped once its target already exists. Pass
`--force` to wipe and re-clone `repo/` (the honeypot `.env` and the markers are
left alone either way — delete them yourself first if you want those redone
too).

Then build the sandbox image:

```bash
docker build -t sting-sandbox:latest .
```

Do not put real credentials in versioned configuration files.

For PR-based variants or the Kimi agent, STING itself (not the `repo/` checkout
above) also needs credentials: copy `.env.example` to `.env` in the project
root and add scoped test credentials. Keep that `.env` local too.

## Run an experiment

```bash
# Preview the attack matrix
uv run python main.py list

# Run all configured attacks
uv run python main.py run

# Restrict the matrix or run one row
uv run python main.py run --modality image --agent claude-code
uv run python main.py run --id 42

# Generate a variant without starting Docker
uv run python main.py run --dry-run

# Re-score or verify an existing result
uv run python main.py score <run_id> --update
uv run python main.py verify --run-id <run_id>
```

Use `uv run python main.py run --help` for all filters and execution options.
The experiment matrix is stored in `attacks.csv`; tunable agents, attack
dimensions, runner settings, and scoring rules are in
`variant_factory/config/taxonomy.yaml`.

## Results and reproduction

Each run is stored in `results/<run_id>/`. The essential evidence is:

| Artifact | Purpose |
| --- | --- |
| `checkpoint.json` | Outcome, score, reasons, duration, and termination state |
| `context.json` | Run parameters and tool configuration |
| `agent.log`, `agent_raw.log`, `final_message.txt` | Agent output |
| `proxy.jsonl`, `fileio.jsonl`, `shell.log` | Network, file-access, and command evidence |
| `injection.patch`, `injection.json` | Pre-execution repository change and its provenance |

`injection.patch` is written before the agent starts. To reconstruct the injected
state, generate the matching template baseline named in `injection.json` and run:

```bash
git apply --binary injection.patch
```

PR-based runs additionally retain the rendered payload and remote base commit in
`injection.json`. Once the listed evidence is archived, the much larger per-run
`repo/` copy can be removed.

Before sharing or retaining evidence outside the local machine, scan and redact
it for authentication data. Agent output and generated Compose files can contain
runtime credentials.

Create a shareable subset without modifying the original results:

```bash
uv run python scripts/export_shareable_results.py
uv run python scripts/export_shareable_results.py --include-agent-output
```

The export contains only JSON metadata and optional redacted agent output. It
excludes `repo/`, generated Compose files, proxy and file-I/O logs, raw agent
logs, and shell logs. Review it before publication; it is a safeguard, not a
proof that arbitrary text contains no sensitive information. Configured honeypot
values are also replaced with clear placeholders in the shareable copy.

## Repository layout

`main.py` provides the CLI. `variant_factory/` defines and generates attacks;
`runner/` runs and scores containers; `proxy/` records outbound traffic.
