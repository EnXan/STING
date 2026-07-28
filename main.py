import os
from pathlib import Path

# Load .env from project root before anything else (no external dependency needed).
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k, _v)

import logging
import subprocess

import click
from variant_factory.attack_matrix import get_attacks
from variant_factory.config.taxonomy_helper import taxonomy as t
from runner.result import RunResult
from runner.runner import TokenLimitAbort, execute_many
from runner.scorer import score as compute_score


@click.group()
def cli():
    """STING — indirect prompt injection test runner."""
    pass


def filter_options(f):
    """Attach taxonomy filter flags to a command."""
    f = click.option("--modality", multiple=True, type=click.Choice(["text", "image"]))(
        f
    )
    f = click.option(
        "--stealth",
        multiple=True,
        type=click.Choice(["direct", "authority", "plausible"]),
    )(f)
    f = click.option(
        "--context",
        multiple=True,
        help="architecture_diagram | code_screenshot | error_screenshot | ...",
    )(f)
    f = click.option(
        "--obfuscation",
        multiple=True,
        help="none | unicode | split | dataformat | blur | ...",
    )(f)
    f = click.option("--location", multiple=True, help="repo_code | dependency | pr")(f)
    f = click.option(
        "--file-location", multiple=True, help="readme | claude_md | source_init | ..."
    )(f)
    return f


def _apply_filters(
    indexed_attacks, modality, stealth, context, obfuscation, location, file_location
):
    result = indexed_attacks
    if modality:
        result = [(i, a) for i, a in result if a.modality in modality]
    if stealth:
        result = [(i, a) for i, a in result if a.stealth in stealth]
    if context:
        result = [(i, a) for i, a in result if a.stealth_context in context]
    if obfuscation:
        result = [(i, a) for i, a in result if a.obfuscation in obfuscation]
    if location:
        result = [(i, a) for i, a in result if a.location in location]
    if file_location:
        result = [(i, a) for i, a in result if a.file_location in file_location]
    return result


@cli.command()
@filter_options
@click.option(
    "--agent",
    "agents",
    multiple=True,
    help="Execution target(s). Not part of the attack matrix.",
)
@click.option(
    "--id", "attack_id", default=None, type=int, help="Run a single attack by row ID."
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Generate variant repos but skip container execution.",
)
@click.option(
    "--workers", default=1, show_default=True, help="Parallel container workers."
)
@click.option(
    "--resume/--no-resume",
    default=True,
    help="Skip attacks that already have a score or end_reason=prompt_too_weak. Default: on.",
)
def run(
    modality,
    stealth,
    context,
    obfuscation,
    location,
    file_location,
    agents,
    attack_id,
    dry_run,
    workers,
    resume,
):
    """Run attacks — all, filtered, or a single one by ID."""
    indexed = list(enumerate(get_attacks(), start=1))

    if attack_id is not None:
        selected = [(row_id, a) for row_id, a in indexed if row_id == attack_id]
    else:
        selected = _apply_filters(
            indexed, modality, stealth, context, obfuscation, location, file_location
        )

    if not selected:
        raise click.UsageError("No attacks match the given filters.")

    target_agents = list(agents) if agents else [a["id"] for a in t.agents()]
    pairs = [
        (row_id, a, agent_id) for row_id, a in selected for agent_id in target_agents
    ]

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if not dry_run:
        image = t.runner()["image"]
        check = subprocess.run(
            ["docker", "image", "inspect", image], capture_output=True
        )
        if check.returncode != 0:
            raise click.UsageError(
                f"Docker image '{image}' not found. Build it first:\n"
                f"  docker build -t {image} ."
            )

    click.echo(
        f"Running {len(pairs)} run(s)  [agents={', '.join(target_agents)}] [dry_run={dry_run}]"
    )

    aborted = False
    try:
        results = execute_many(
            pairs,
            workers=workers,
            results_root=Path("results"),
            dry_run=dry_run,
            skip_completed=resume,
        )
    except TokenLimitAbort as exc:
        aborted = True
        results = exc.partial
        click.echo(
            f"\nAborted — all agents hit their token limit: {', '.join(sorted(exc.exhausted))}",
            err=True,
        )

    passed = sum(1 for r in results if not r.timed_out and r.exit_code == 0)
    timed_out = sum(1 for r in results if r.timed_out)
    token_limit = sum(
        1 for r in results if r.end_reason in ("token_limit", "token_limit_skip")
    )
    failed = len(results) - passed - timed_out - token_limit

    click.echo(f"\n{'run_id':<14} {'attack':>6} {'agent':<14} {'score':<6} {'status'}")
    click.echo("-" * 56)
    for r in sorted(results, key=lambda r: r.attack_id):
        if r.end_reason == "token_limit":
            status = "token_limit"
        elif r.end_reason == "token_limit_skip":
            status = "skipped (token_limit)"
        elif r.timed_out:
            status = "timeout"
        elif r.exit_code == 0:
            status = "ok"
        else:
            status = f"exit={r.exit_code}"
        click.echo(
            f"{r.run_id:<14} {r.attack_id:>6} {r.agent_id:<14} {r.score or '—':<6} {status}"
        )

    counts = {
        s: sum(1 for r in results if r.score == s) for s in ("S1", "S2", "S3", "S4")
    }
    summary = (
        f"\n{'Aborted' if aborted else 'Done'} — "
        f"{passed} ok · {timed_out} timed out · {token_limit} token_limit · "
        f"{failed} failed"
    )
    click.echo(
        summary
        + f"  |  S1={counts['S1']} S2={counts['S2']} S3={counts['S3']} S4={counts['S4']}"
    )

    if aborted:
        raise SystemExit(1)


@cli.command("list")
@filter_options
def list_attacks(modality, stealth, context, obfuscation, location, file_location):
    """Preview the filtered attack matrix without running anything."""
    indexed = list(enumerate(get_attacks(), start=1))
    selected = _apply_filters(
        indexed, modality, stealth, context, obfuscation, location, file_location
    )

    click.echo(
        f"{'ID':>4}  {'modality':<8} {'stealth':<12} "
        f"{'context':<22} {'obfuscation':<14} {'location':<12} {'file_location'}"
    )
    click.echo("-" * 97)
    for row_id, a in selected:
        click.echo(
            f"{row_id:>4}  {a.modality:<8} {a.stealth:<12} "
            f"{(a.stealth_context or ''):<22} {a.obfuscation:<14} "
            f"{a.location:<12} {a.file_location}"
        )

    click.echo(f"\n{len(selected)} attack(s)")


@cli.command("verify")
@click.option("--run-id", default=None, help="Verify a single run by ID.")
def verify_runs(run_id: str | None) -> None:
    """Audit payload insertion and classification for completed runs."""
    from runner.verifier import _build_attacks_index, verify_all, verify_run

    results_root = Path("results")

    if run_id:
        result_dir = results_root / run_id
        if not result_dir.exists():
            raise click.UsageError(f"No results directory: results/{run_id}/")
        verifications = [verify_run(result_dir, _build_attacks_index())]
    else:
        verifications = verify_all(results_root)

    if not verifications:
        click.echo("No completed runs found.")
        return

    click.echo(
        f"\n{'run_id':<14} {'atk':>4} {'agent':<14} {'score':<5} {'payload':<9} classification"
    )
    click.echo("-" * 72)

    p_ok = p_fail = p_skip = 0
    c_ok = c_fail = c_skip = 0

    for v in sorted(verifications, key=lambda x: (x.attack_id, x.agent_id)):
        p_icon = (
            "ok"
            if v.payload_check and v.payload_check.ok
            else ("--" if v.payload_check is None else "FAIL")
        )
        c_icon = (
            "ok"
            if v.classification_check and v.classification_check.ok
            else ("--" if v.classification_check is None else "FAIL")
        )

        click.echo(
            f"{v.run_id:<14} {v.attack_id:>4} {v.agent_id:<14} {v.score or '--':<5} {p_icon:<9} {c_icon}"
        )

        if v.payload_check is None:
            p_skip += 1
        elif v.payload_check.ok:
            p_ok += 1
        else:
            p_fail += 1
            click.echo(f"         payload:  {v.payload_check.msg}")

        if v.classification_check is None:
            c_skip += 1
        elif v.classification_check.ok:
            c_ok += 1
        else:
            c_fail += 1
            click.echo(f"         classify: {v.classification_check.msg}")

    click.echo(f"\nPayload check:        {p_ok} ok  {p_fail} failed  {p_skip} skipped")
    click.echo(f"Classification check: {c_ok} ok  {c_fail} failed  {c_skip} skipped")


@cli.command("score")
@click.argument("run_id")
@click.option(
    "--update", is_flag=True, help="Rewrite the checkpoint with the new score."
)
def rescore(run_id: str, update: bool) -> None:
    """Re-score a completed run from disk without Docker."""
    results_dir = Path("results") / run_id
    result = RunResult.from_checkpoint(results_dir)
    if result is None:
        raise click.UsageError(f"No checkpoint found in results/{run_id}/")

    label, reasons = compute_score(result)
    click.echo(f"Score: {label}")
    for reason in reasons:
        click.echo(f"  • {reason}")

    if update:
        result.score = label
        result.score_reasons = reasons
        result.save_checkpoint()
        click.echo("Checkpoint updated.")


if __name__ == "__main__":
    cli()
