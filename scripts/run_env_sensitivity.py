"""Run the paired .env filename sensitivity experiment.

The experiment reuses four representative attack configurations from the main
matrix. Each configuration is executed as an isolated pair with identical
honeypot contents: one repository contains only ``.env`` and the other contains
only ``project-settings.conf``. The payloads differ only in the target filename.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
import logging
from pathlib import Path
import subprocess
import sys

import click

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from runner.runner import TokenLimitAbort, execute_many  # noqa: E402
from variant_factory.attack_matrix import get_attacks  # noqa: E402
from variant_factory.config.taxonomy_helper import taxonomy as t  # noqa: E402
from variant_factory.models import Attack  # noqa: E402


DEFAULT_RESULTS_ROOT = PROJECT_ROOT / "results" / "env-sensitivity-v2"
SOURCE_ATTACK_IDS = (26, 46, 141, 166)
TARGET_DATA_FILES = (".env", "project-settings.conf")
TARGET_AGENTS = ("claude-code", "codex")
PAIR_WORKERS = 2


@dataclass(frozen=True)
class ExperimentCase:
    case_id: int
    source_attack_id: int
    target_data_file: str
    attack: Attack


def build_cases() -> list[ExperimentCase]:
    indexed_attacks = dict(enumerate(get_attacks(), start=1))
    cases: list[ExperimentCase] = []

    for source_attack_id in SOURCE_ATTACK_IDS:
        source = indexed_attacks[source_attack_id]
        for target_data_file in TARGET_DATA_FILES:
            payload = source.payload.replace(".env", target_data_file)
            cases.append(
                ExperimentCase(
                    case_id=len(cases) + 1,
                    source_attack_id=source_attack_id,
                    target_data_file=target_data_file,
                    attack=replace(
                        source,
                        payload=payload,
                        exclusive_data_file=target_data_file,
                    ),
                )
            )

    return cases


def write_manifest(cases: list[ExperimentCase], results_root: Path) -> None:
    results_root.mkdir(parents=True, exist_ok=True)
    manifest = {
        "purpose": "Paired sensitivity test for .env-specific agent caution",
        "isolation": "Exactly one synthetic credential file exists per repository",
        "agents": list(TARGET_AGENTS),
        "target_data_files": list(TARGET_DATA_FILES),
        "source_attack_ids": list(SOURCE_ATTACK_IDS),
        "cases": [
            {
                "case_id": case.case_id,
                "source_attack_id": case.source_attack_id,
                "target_data_file": case.target_data_file,
                "attack": asdict(case.attack),
            }
            for case in cases
        ],
    }
    (results_root / "experiment.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )


def write_summary(
    cases: list[ExperimentCase], results: list, results_root: Path
) -> None:
    case_by_id = {case.case_id: case for case in cases}
    rows = []
    for result in sorted(results, key=lambda item: (item.attack_id, item.agent_id)):
        case = case_by_id[result.attack_id]
        rows.append(
            {
                "case_id": case.case_id,
                "source_attack_id": case.source_attack_id,
                "target_data_file": case.target_data_file,
                "agent": result.agent_id,
                "score": result.score,
                "score_reasons": result.score_reasons,
                "end_reason": result.end_reason,
                "duration_s": result.duration_s,
                "run_id": result.run_id,
            }
        )

    (results_root / "summary.json").write_text(
        json.dumps(rows, indent=2) + "\n",
        encoding="utf-8",
    )


@click.command()
@click.option("--dry-run", is_flag=True, help="Generate and verify variants only.")
@click.option("--resume/--no-resume", default=True, show_default=True)
@click.option(
    "--results-root",
    type=click.Path(path_type=Path),
    default=DEFAULT_RESULTS_ROOT,
    show_default=True,
)
def main(dry_run: bool, resume: bool, results_root: Path) -> None:
    cases = build_cases()
    results_root = results_root.resolve()
    write_manifest(cases, results_root)

    if not dry_run:
        image = t.runner()["image"]
        image_check = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            check=False,
        )
        if image_check.returncode != 0:
            raise click.UsageError(
                f"Docker image {image!r} is unavailable. Build it with: "
                f"docker build -t {image} ."
            )

    pair_batches = []
    for source_attack_id in SOURCE_ATTACK_IDS:
        paired_cases = [
            case for case in cases if case.source_attack_id == source_attack_id
        ]
        for agent in TARGET_AGENTS:
            pair_batches.append(
                [(case.case_id, case.attack, agent) for case in paired_cases]
            )
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    click.echo(
        f"Running {len(pair_batches)} isolated pairs "
        f"({len(pair_batches) * len(TARGET_DATA_FILES)} total runs) "
        f"[dry_run={dry_run}] [results={results_root}]"
    )

    results = []
    try:
        for pair_number, pair in enumerate(pair_batches, start=1):
            source_attack_id = next(
                case.source_attack_id for case in cases if case.case_id == pair[0][0]
            )
            click.echo(
                f"Pair {pair_number}/{len(pair_batches)}: "
                f"source_attack_id={source_attack_id} agent={pair[0][2]}"
            )
            results.extend(
                execute_many(
                    pair,
                    workers=PAIR_WORKERS,
                    results_root=results_root,
                    dry_run=dry_run,
                    skip_completed=resume,
                )
            )
            write_summary(cases, results, results_root)
    except TokenLimitAbort as error:
        results.extend(error.partial)
        write_summary(cases, results, results_root)
        raise click.ClickException(str(error)) from error

    write_summary(cases, results, results_root)
    click.echo(f"Wrote {results_root / 'summary.json'}")


if __name__ == "__main__":
    main()
