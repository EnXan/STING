from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

_CHECKPOINT_FILE = "checkpoint.json"


@dataclass
class RunResult:
    run_id: str
    attack_id: int
    agent_id: str

    logs_path: Path  # results/{run_id}/
    repo_path: Path  # results/{run_id}/repo/
    final_message: Path | None  # agent's final response text
    proxy_log: Path | None  # mitmproxy JSONL log
    shell_log: Path | None
    agent_log: Path | None

    duration_s: float
    timed_out: bool
    exit_code: int | None

    score: str | None = None  # S1–S4
    score_reasons: list[str] = field(
        default_factory=list
    )  # why this score was assigned
    end_reason: str = "unknown"  # exit | sentinel | timeout | killed | dry_run

    def save_checkpoint(self) -> None:
        data = {
            "run_id": self.run_id,
            "attack_id": self.attack_id,
            "agent_id": self.agent_id,
            "score": self.score,
            "score_reasons": self.score_reasons,
            "end_reason": self.end_reason,
            "duration_s": self.duration_s,
            "timed_out": self.timed_out,
            "exit_code": self.exit_code,
        }
        (self.logs_path / _CHECKPOINT_FILE).write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    @classmethod
    def from_checkpoint(cls, results_dir: Path) -> RunResult | None:
        cp = results_dir / _CHECKPOINT_FILE
        if not cp.exists():
            return None
        try:
            data = json.loads(cp.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, KeyError):
            return None

        def maybe(name: str) -> Path | None:
            p = results_dir / name
            return p if p.exists() else None

        return cls(
            run_id=data["run_id"],
            attack_id=data["attack_id"],
            agent_id=data["agent_id"],
            logs_path=results_dir,
            repo_path=results_dir / "repo",
            final_message=maybe("final_message.txt"),
            proxy_log=maybe("proxy.jsonl"),
            shell_log=maybe("shell.log"),
            agent_log=maybe("agent.log"),
            duration_s=data["duration_s"],
            timed_out=data["timed_out"],
            exit_code=data["exit_code"],
            score=data.get("score"),
            score_reasons=data.get("score_reasons", []),
            end_reason=data.get("end_reason", "unknown"),
        )
