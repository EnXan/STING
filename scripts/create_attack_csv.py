"""
generate_attacks_csv.py — Generates attacks.csv with all taxonomy combinations.

Usage:
    python -m variant_factory.generate_attacks_csv
    python -m variant_factory.generate_attacks_csv --out /path/to/attacks.csv
"""

from __future__ import annotations

import argparse
import csv
import itertools
import sys
from pathlib import Path
from typing import Iterator

# Allow running this file directly via `uv run scripts/create_attack_csv.py`.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from variant_factory.config.taxonomy_helper import taxonomy as t
from variant_factory.models import DEFAULT_USER_PROMPT

FIELDNAMES = [
    "origin",
    "modality",
    "location",
    "file_location",
    "stealth",
    "stealth_context",
    "obfuscation",
    "goal",
    "user_prompt",
    "payload",
]


def _text_rows() -> Iterator[dict]:
    origin = t.origin()["repo"]
    goal_ids = [g["id"] for g in t.goals()]

    for fl in t.text_file_locations():
        user_prompt = fl.get("user_prompt", DEFAULT_USER_PROMPT)
        for stealth in t.text_stealth():
            contexts = stealth.get("context", [None])
            for ctx in contexts:
                for obf in t.text_obfuscation():
                    # split obfuscation spans two files; PR targets are single-field
                    if fl["location"] == "pr" and obf["id"] == "split":
                        continue
                    for goal in goal_ids:
                        yield {
                            "origin": origin,
                            "modality": "text",
                            "location": fl["location"],
                            "file_location": fl["id"],
                            "stealth": stealth["id"],
                            "stealth_context": ctx or "",
                            "obfuscation": obf["id"],
                            "goal": goal,
                            "user_prompt": user_prompt,
                            "payload": "",
                        }


def _image_rows() -> Iterator[dict]:
    # Images are injected in the same canonical file locations as text.
    origin = t.origin()["repo"]
    goal_ids = [g["id"] for g in t.goals()]

    for fl in t.text_file_locations():
        user_prompt = fl.get("user_prompt", DEFAULT_USER_PROMPT)
        for stealth in t.image_stealth():
            contexts = stealth.get("context", [None])
            for ctx in contexts:
                for obf in t.image_obfuscation():
                    # split obfuscation spans two files; PR targets are single-field
                    if fl["location"] == "pr" and obf["id"] == "split":
                        continue
                    # commit messages are plain text; image payloads can't go there
                    if fl["location"] == "pr" and fl["id"] == "commit_message":
                        continue
                    for goal in goal_ids:
                        yield {
                            "origin": origin,
                            "modality": "image",
                            "location": fl["location"],
                            "file_location": fl["id"],
                            "stealth": stealth["id"],
                            "stealth_context": ctx or "",
                            "obfuscation": obf["id"],
                            "goal": goal,
                            "user_prompt": user_prompt,
                            "payload": "",
                        }


_MERGE_KEY = (
    "origin",
    "modality",
    "location",
    "file_location",
    "stealth",
    "stealth_context",
    "obfuscation",
    "goal",
)


def _load_existing(out_path: Path) -> dict[tuple, dict]:
    if not out_path.exists():
        return {}
    with open(out_path, newline="", encoding="utf-8") as f:
        return {tuple(r[k] for k in _MERGE_KEY): r for r in csv.DictReader(f)}


def generate(out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    existing = _load_existing(out_path)
    rows = list(itertools.chain(_text_rows(), _image_rows()))

    # First pass: restore user_prompt and payload from existing rows.
    for row in rows:
        key = tuple(row[k] for k in _MERGE_KEY)
        if key in existing:
            existing_row = existing[key]
            existing_prompt = existing_row.get("user_prompt", "")
            # Restore a user_prompt only when it was manually customised.
            # PR prompts are always taxonomy-derived so the CSV never overrides them.
            if existing_prompt and existing_prompt != DEFAULT_USER_PROMPT and row["location"] != "pr":
                row["user_prompt"] = existing_prompt
            row["payload"] = existing_row.get("payload") or row["payload"]

    # Second pass: for base64 rows with no payload, copy from the none variant.
    # base64 obfuscation encodes the raw payload at generation time, so the CSV
    # should store the same raw payload as the none variant.
    none_payloads = {
        tuple(r[k] for k in _MERGE_KEY if k != "obfuscation"): r["payload"]
        for r in rows
        if r["obfuscation"] == "none"
    }
    for row in rows:
        if row["obfuscation"] == "base64" and not row["payload"]:
            base_key = tuple(row[k] for k in _MERGE_KEY if k != "obfuscation")
            row["payload"] = none_payloads.get(base_key, "")

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate attacks.csv from taxonomy")
    parser.add_argument(
        "--out",
        default="attacks.csv",
        help="Output path for attacks.csv (default: attacks.csv)",
    )
    args = parser.parse_args()
    out_path = Path(args.out)
    count = generate(out_path)
    print(f"[attacks] {count} rows → {out_path}")


if __name__ == "__main__":
    main()
