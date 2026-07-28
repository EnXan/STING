"""Create a credential-safe, shareable subset of STING results.

The exporter never changes ``results/``.  It intentionally excludes generated
Compose files, repository copies, raw agent logs, and shell logs because those
artifacts can contain runtime credentials.  Optional agent output is redacted
using local credential values and common token formats.

Usage:
    uv run python scripts/export_shareable_results.py
    uv run python scripts/export_shareable_results.py --include-agent-output
    uv run python scripts/export_shareable_results.py --out /path/to/export
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_ROOT = PROJECT_ROOT / "results"
DEFAULT_EXPORT_ROOT = PROJECT_ROOT / "shared-results"
METADATA_FILES = ("checkpoint.json", "context.json", "injection.json")
AGENT_OUTPUT_FILES = ("agent.log", "final_message.txt")
TOKEN_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
)
ASSIGNMENT_PATTERN = re.compile(
    r"(?im)(\b(?:api[_-]?key|token|password|secret(?:_access_key)?|"
    r"access[_-]?token|credentials?_json|authorization)\b\s*[:=]\s*)"
    r"([\"']?)([^\s\"']+)(\2)"
)
BEARER_PATTERN = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)\S+")


@dataclass(frozen=True)
class ExportOptions:
    results_root: Path
    export_root: Path
    include_agent_output: bool


def _load_redaction_values() -> dict[str, str]:
    """Load local credentials and configured honeypot values to redact."""
    dotenv_path = PROJECT_ROOT / ".env"
    values: dict[str, str] = {}
    if dotenv_path.exists():
        for line in dotenv_path.read_text(encoding="utf-8").splitlines():
            if not line or line.lstrip().startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name not in {"GITHUB_TOKEN", "KIMI_API_KEY"}:
                continue
            value = value.strip().strip('"').strip("'")
            if value:
                values[name] = value

    taxonomy_path = PROJECT_ROOT / "variant_factory/config/taxonomy.yaml"
    taxonomy = yaml.safe_load(taxonomy_path.read_text(encoding="utf-8"))
    for name, value in taxonomy.get("honeypot", {}).get("value", {}).items():
        if isinstance(value, str) and value:
            values[f"HONEYPOT_{name.upper()}"] = value
    return values


def _redact_text(text: str, known_secrets: dict[str, str]) -> str:
    for name, value in sorted(known_secrets.items(), key=lambda item: -len(item[1])):
        text = text.replace(value, f"[REDACTED:{name}]")

    text = BEARER_PATTERN.sub(r"\1[REDACTED]", text)
    text = ASSIGNMENT_PATTERN.sub(r"\1\2[REDACTED]\4", text)
    for pattern in TOKEN_PATTERNS:
        text = pattern.sub("[REDACTED:TOKEN]", text)
    return text


def _redact_json(value: Any, known_secrets: dict[str, str]) -> Any:
    if isinstance(value, str):
        return _redact_text(value, known_secrets)
    if isinstance(value, list):
        return [_redact_json(item, known_secrets) for item in value]
    if isinstance(value, dict):
        return {key: _redact_json(item, known_secrets) for key, item in value.items()}
    return value


def _copy_sanitized_json(
    source: Path, destination: Path, known_secrets: dict[str, str]
) -> None:
    data = json.loads(source.read_text(encoding="utf-8"))
    destination.write_text(
        json.dumps(_redact_json(data, known_secrets), ensure_ascii=False, indent=2)
        + "\n",
        encoding="utf-8",
    )


def _copy_sanitized_text(
    source: Path, destination: Path, known_secrets: dict[str, str]
) -> None:
    text = source.read_text(encoding="utf-8", errors="replace")
    destination.write_text(_redact_text(text, known_secrets), encoding="utf-8")


def _run_summary(run_dir: Path, known_secrets: dict[str, str]) -> dict[str, Any] | None:
    checkpoint_path = run_dir / "checkpoint.json"
    context_path = run_dir / "context.json"
    if not checkpoint_path.exists() or not context_path.exists():
        return None

    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    context = json.loads(context_path.read_text(encoding="utf-8"))
    summary = {
        "run_id": checkpoint.get("run_id") or context.get("run_id"),
        "attack_id": checkpoint.get("attack_id") or context.get("attack_id"),
        "agent": checkpoint.get("agent_id") or context.get("agent_id"),
        "modality": context.get("modality"),
        "stealth": context.get("stealth"),
        "stealth_context": context.get("stealth_context"),
        "obfuscation": context.get("obfuscation"),
        "location": context.get("location"),
        "file_location": context.get("file_location"),
        "score": checkpoint.get("score"),
        "score_reasons": checkpoint.get("score_reasons") or [],
        "end_reason": checkpoint.get("end_reason"),
        "duration_s": checkpoint.get("duration_s"),
        "exit_code": checkpoint.get("exit_code"),
    }
    return {
        key: _redact_json(value, known_secrets)
        for key, value in summary.items()
        if value is not None and value != ""
    }


def export(options: ExportOptions) -> tuple[int, int]:
    if not options.results_root.is_dir():
        raise FileNotFoundError(
            f"Results directory does not exist: {options.results_root}"
        )
    if options.export_root.exists():
        raise FileExistsError(
            f"Export directory already exists: {options.export_root}. "
            "Choose a new --out path."
        )

    known_secrets = _load_redaction_values()
    metadata_root = options.export_root / "runs"
    metadata_root.mkdir(parents=True)
    summaries: list[dict[str, Any]] = []
    exported_runs = 0

    for run_dir in sorted(options.results_root.iterdir()):
        if not run_dir.is_dir() or not run_dir.name[:1].isdigit():
            continue
        summary = _run_summary(run_dir, known_secrets)
        if summary is None:
            continue

        export_run_dir = metadata_root / run_dir.name
        export_run_dir.mkdir()
        for filename in METADATA_FILES:
            source = run_dir / filename
            if source.exists():
                _copy_sanitized_json(source, export_run_dir / filename, known_secrets)

        if options.include_agent_output:
            for filename in AGENT_OUTPUT_FILES:
                source = run_dir / filename
                if source.exists():
                    _copy_sanitized_text(
                        source, export_run_dir / filename, known_secrets
                    )

        summaries.append(summary)
        exported_runs += 1

    summaries.sort(key=lambda item: (item.get("attack_id", 0), item.get("agent", "")))
    (options.export_root / "runs.json").write_text(
        json.dumps(summaries, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (options.export_root / "README.md").write_text(
        "# Shareable STING results\n\n"
        "This export contains JSON metadata and optional redacted agent output "
        "only. It excludes `repo/`, generated Compose files, proxy and file-I/O "
        "logs, raw agent logs, and shell logs. Included content has been "
        "redacted for configured credentials, honeypot values, and common token "
        "formats. Review the export before external publication.\n",
        encoding="utf-8",
    )
    return exported_runs, len(known_secrets)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a credential-safe subset of STING results."
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_EXPORT_ROOT,
        help=f"New export directory (default: {DEFAULT_EXPORT_ROOT.name}/)",
    )
    parser.add_argument(
        "--include-agent-output",
        action="store_true",
        help="Include redacted agent.log and final_message.txt.",
    )
    args = parser.parse_args()
    options = ExportOptions(
        results_root=DEFAULT_RESULTS_ROOT,
        export_root=args.out.resolve(),
        include_agent_output=args.include_agent_output,
    )

    try:
        exported_runs, local_secret_count = export(options)
    except (FileExistsError, FileNotFoundError, json.JSONDecodeError) as error:
        raise SystemExit(f"Export failed: {error}") from error

    print(f"Exported {exported_runs} runs to {options.export_root}")
    print(f"Redacted {local_secret_count} configured credential or honeypot value(s).")


if __name__ == "__main__":
    main()
