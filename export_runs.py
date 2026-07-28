"""
Export all STING run results to a single human-readable JSON file.

Usage:
    python export_runs.py                     # → docs/runs.json
    python export_runs.py --out my_file.json  # custom output path
    python export_runs.py --no-message        # skip final_message (smaller file)
    python export_runs.py --agent kimi        # filter by agent
    python export_runs.py --score S4          # filter by score
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_run(run_dir: Path, include_message: bool) -> dict | None:
    ctx_file = run_dir / "context.json"
    ckpt_file = run_dir / "checkpoint.json"

    if not ctx_file.exists() or not ckpt_file.exists():
        return None

    try:
        ctx = json.loads(ctx_file.read_text())
        ckpt = json.loads(ckpt_file.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    # Skip unscored / prompt-too-weak runs
    if ckpt.get("score") is None and ckpt.get("end_reason") == "prompt_too_weak":
        return None

    # --- attack identity ---
    entry = {
        "run_id":        ckpt.get("run_id") or ctx.get("run_id"),
        "attack_id":     ckpt.get("attack_id") or ctx.get("attack_id"),
        "agent":         ckpt.get("agent_id") or ctx.get("agent_id"),
        # --- attack dimensions ---
        "modality":      ctx.get("modality"),
        "stealth":       ctx.get("stealth"),
        "stealth_context": ctx.get("stealth_context") or None,
        "obfuscation":   ctx.get("obfuscation"),
        "location":      ctx.get("location"),
        "file_location": ctx.get("file_location"),
        # --- scorer decision ---
        "score":         ckpt.get("score"),
        "score_reasons": ckpt.get("score_reasons") or [],
        "end_reason":    ckpt.get("end_reason"),
        "duration_s":    ckpt.get("duration_s"),
        "exit_code":     ckpt.get("exit_code"),
    }

    # Remove None/empty values for cleanliness
    entry = {k: v for k, v in entry.items() if v is not None and v != ""}

    # --- agent output ---
    if include_message:
        msg = ""
        for fname in ("final_message.txt", "agent.log"):
            fp = run_dir / fname
            if fp.exists():
                try:
                    msg = fp.read_text(errors="replace").strip()
                except OSError:
                    pass
                break
        entry["final_message"] = msg or "(no output)"

    return entry


def main():
    parser = argparse.ArgumentParser(description="Export STING run results to JSON.")
    parser.add_argument("--out", default="docs/runs.json", help="Output file path")
    parser.add_argument("--no-message", action="store_true", help="Omit final_message")
    parser.add_argument("--agent", help="Filter: only include this agent id")
    parser.add_argument("--score", help="Filter: only include runs with this score (e.g. S4)")
    args = parser.parse_args()

    results_root = Path("results")
    if not results_root.exists():
        sys.exit("results/ directory not found — run from the STING project root.")

    runs = []
    skipped = 0

    for run_dir in sorted(results_root.iterdir()):
        if not run_dir.is_dir() or not run_dir.name[0].isdigit():
            continue

        entry = load_run(run_dir, include_message=not args.no_message)
        if entry is None:
            skipped += 1
            continue

        if args.agent and entry.get("agent") != args.agent:
            continue
        if args.score and entry.get("score") != args.score:
            continue

        runs.append(entry)

    # Sort by attack_id, then agent for consistent ordering
    runs.sort(key=lambda r: (r.get("attack_id", 0), r.get("agent", "")))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(runs, f, ensure_ascii=False, indent=2)
        f.write("\n")

    # Print a summary table to stdout
    score_counts = {}
    for r in runs:
        s = r.get("score", "?")
        score_counts[s] = score_counts.get(s, 0) + 1

    print(f"Exported {len(runs)} runs → {out_path}  (skipped {skipped} unscored)")
    print("Scores: " + "  ".join(f"{s}={n}" for s, n in sorted(score_counts.items())))
    print(f"File size: {out_path.stat().st_size / 1024:.0f} KB")


if __name__ == "__main__":
    main()
