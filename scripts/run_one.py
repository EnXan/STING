from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import click

from runner.runner import execute
from variant_factory.attack_matrix import get_attacks
from variant_factory.config.taxonomy_helper import taxonomy as t


def _indexed_attacks() -> list[tuple[int, object]]:
    return list(enumerate(get_attacks(), start=1))


def _print_attacks(indexed_attacks: list[tuple[int, object]]) -> None:
    click.echo(
        f"{'ID':>4}  {'modality':<8} {'stealth':<12} "
        f"{'context':<22} {'obfuscation':<14} {'location':<12} {'file_location'}"
    )
    click.echo("-" * 97)
    for row_id, attack in indexed_attacks:
        click.echo(
            f"{row_id:>4}  {attack.modality:<8} {attack.stealth:<12} "
            f"{(attack.stealth_context or ''):<22} {attack.obfuscation:<14} "
            f"{attack.location:<12} {attack.file_location}"
        )


@click.command()
@click.option(
    "--id", "attack_id", type=int, default=None, help="Run a single attack by row ID."
)
@click.option("--agent", default="codex", show_default=True, help="Execution target.")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Generate the variant repo but skip container execution.",
)
@click.option(
    "--results-root",
    default="results",
    show_default=True,
    help="Directory for run artifacts.",
)
def main(attack_id: int | None, agent: str, dry_run: bool, results_root: str) -> None:
    indexed_attacks = _indexed_attacks()
    valid_agents = {entry["id"] for entry in t.agents()}

    if agent not in valid_agents:
        raise click.UsageError(
            f"Unknown agent {agent!r}. Valid agents: {', '.join(sorted(valid_agents))}"
        )

    if attack_id is None:
        _print_attacks(indexed_attacks)
        attack_id = click.prompt("\nAttack ID", type=int)

    selected = next(
        (attack for row_id, attack in indexed_attacks if row_id == attack_id), None
    )
    if selected is None:
        raise click.UsageError(f"Attack ID {attack_id} not found.")

    click.echo(f"Running attack {attack_id} with agent={agent} dry_run={dry_run}")
    result = execute(
        attack_id=attack_id,
        attack=selected,
        agent_id=agent,
        results_root=Path(results_root),
        dry_run=dry_run,
    )

    click.echo(
        f"Done: run_id={result.run_id} exit_code={result.exit_code} timed_out={result.timed_out} "
        f"score={result.score} logs={result.logs_path}"
    )


if __name__ == "__main__":
    main()
