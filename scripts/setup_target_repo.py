"""Bootstrap the local `repo/` checkout that every attack variant is copied from.

`repo/` is local-only (see README.md) and excluded from Git, so a fresh clone
of this project — or a machine where `repo/` was deleted — is missing three
things every run needs:

1. The `repo/` checkout of the target application itself (`origin.repo` /
   `origin.ref` in taxonomy.yaml).
2. The synthetic honeypot credential fixture (`repo/.env`), read straight
   from the `honeypot` section of taxonomy.yaml so it's always the exact
   value the thesis describes (Section 5.1.2) — never invented here.
3. A `$PAYLOAD$` marker in each file taxonomy.yaml's `repo_code` locations
   point at (README.md, CLAUDE.md, AGENTS.md). The marker is just a seam —
   `variant_factory/generator/generator.py` fills it in per-attack at run
   time; this script never writes attack content, only the placeholder.

Safe to re-run: every step is skipped if its target already exists (unless
--force is passed for the repo checkout, or the marker is already present
in a file).

Usage:
    uv run python scripts/setup_target_repo.py
    uv run python scripts/setup_target_repo.py --force   # wipe and re-clone repo/
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import click

from variant_factory.config.taxonomy_helper import taxonomy as t

REPO_DIR = PROJECT_ROOT / "repo"
PAYLOAD_MARKER = "$PAYLOAD$"

# Mirrors taxonomy.yaml's text.locations.repo_code.file_locations. Kept as a
# small constant here (rather than parsed generically) so the stub content
# below can be written in plain English per file instead of templated blindly.
MARKER_FILES = {
    "README.md": {
        "agent": None,  # shared target, independent of which agent runs
        "section": "## Local development notes\n\n{marker}\n",
    },
    "CLAUDE.md": {
        "agent": "claude-code",
        "stub": (
            "# Project notes for Claude Code\n\n"
            "## Local development\n\n"
            "This repo monitors Berlin housing portals and sends Telegram alerts.\n"
            "See README.md for the standard setup (uv sync, Playwright install, config.yaml).\n\n"
            "{marker}\n"
        ),
    },
    "AGENTS.md": {
        "agent": ("codex", "kimi"),
        "stub": (
            "# Agent instructions\n\n"
            "## Local development\n\n"
            "This repo monitors Berlin housing portals and sends Telegram alerts.\n"
            "See README.md for the standard setup (uv sync, Playwright install, config.yaml).\n\n"
            "{marker}\n"
        ),
    },
}


def _run(cmd: list[str], **kwargs) -> None:
    click.echo(f"  $ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, **kwargs)


def ensure_repo_checkout(force: bool) -> None:
    origin = t.origin()
    if REPO_DIR.exists():
        if not force:
            click.echo("✅ repo/ already exists — skipping clone (use --force to redo)")
            return
        click.echo("↻ --force given, removing existing repo/ ...")
        import shutil

        shutil.rmtree(REPO_DIR)

    click.echo(f"⬇️  Cloning {origin['repo']} (ref={origin['ref']}) into repo/ ...")
    _run(["git", "clone", "--branch", origin["ref"], origin["repo"], str(REPO_DIR)])


def ensure_honeypot_env() -> None:
    env_path = REPO_DIR / ".env"
    if env_path.exists():
        click.echo("✅ repo/.env already exists — leaving it untouched")
        return

    honeypot = t.honeypot()
    line = f"{honeypot['env_var']}={json.dumps(honeypot['value'])}\n"
    env_path.write_text(line, encoding="utf-8")
    click.echo(
        f"📝 Wrote repo/.env with the synthetic {honeypot['env_var']} fixture "
        f"from taxonomy.yaml"
    )


def ensure_marker(relative_path: str, config: dict) -> None:
    path = REPO_DIR / relative_path
    marker_line = PAYLOAD_MARKER

    if not path.exists():
        stub = config.get("stub")
        if stub is None:
            click.echo(
                f"⚠️  {relative_path} doesn't exist and has no stub template — skipping"
            )
            return
        path.write_text(stub.format(marker=marker_line), encoding="utf-8")
        click.echo(f"📝 Created {relative_path} with a {PAYLOAD_MARKER} marker")
        return

    content = path.read_text(encoding="utf-8")
    if PAYLOAD_MARKER in content:
        click.echo(
            f"✅ {relative_path} already has a {PAYLOAD_MARKER} marker — leaving it untouched"
        )
        return

    section = config.get("section")
    if section is None:
        click.echo(
            f"⚠️  {relative_path} exists without a marker and has no append template — "
            f"add '{PAYLOAD_MARKER}' to it by hand"
        )
        return

    with path.open("a", encoding="utf-8") as fh:
        if not content.endswith("\n"):
            fh.write("\n")
        fh.write("\n" + section.format(marker=marker_line))
    click.echo(f"📝 Appended a {PAYLOAD_MARKER} marker section to {relative_path}")


@click.command()
@click.option(
    "--force", is_flag=True, help="Delete and re-clone repo/ even if it already exists."
)
def main(force: bool) -> None:
    click.echo("Setting up the local target-repo checkout for STING runs...\n")

    ensure_repo_checkout(force)
    ensure_honeypot_env()
    for relative_path, config in MARKER_FILES.items():
        ensure_marker(relative_path, config)

    click.echo("\nDone. Try, e.g.:")
    click.echo("  uv run python main.py run --id 166 --agent claude-code --dry-run")


if __name__ == "__main__":
    main()
