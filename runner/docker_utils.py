"""
docker_utils.py — Generates a per-run docker-compose.yml and provides
helpers for bringing the stack up and down.

Network topology per run:
    sandbox ──► sting_net ──► internet
    proxy   ──► sting_net ──► internet

Both the sandbox and proxy containers share a single bridged network.
The sandbox routes HTTP(S) through the proxy via HTTP_PROXY/HTTPS_PROXY env
vars so that all traffic is logged to /results/proxy.jsonl.
"""

from __future__ import annotations

import platform
import subprocess
from pathlib import Path

from variant_factory.config.taxonomy_helper import taxonomy as t

import yaml


# Path to the mitmproxy addon inside the project root (mounted read-only).
PROXY_ADDON_HOST_PATH = Path(__file__).resolve().parents[1] / "proxy" / "addon.py"
HOME = Path.home()


def get_claude_credentials_json() -> str | None:
    """
    Extract the Claude Code OAuth token from the macOS Keychain.

    Returns the raw JSON string, or None on non-macOS or if the keychain item
    is missing.  The caller is responsible for passing this value to the
    container (e.g. via CLAUDE_CREDENTIALS_JSON env var).
    """
    if platform.system() != "Darwin":
        return None
    try:
        result = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-s",
                "Claude Code-credentials",
                "-w",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _auth_volumes(agent_id: str) -> list[str]:
    volumes: list[str] = []

    if agent_id == "claude-code":
        # ~/.claude.json is a single-file mount; safe :ro since there's no nesting.
        # Credentials are passed via CLAUDE_CREDENTIALS_JSON env var and written to
        # /home/agent/.claude/ by entrypoint.sh — no bind mount into .claude needed.
        claude_json = HOME / ".claude.json"
        if claude_json.exists():
            volumes.append(f"{claude_json}:/home/agent/.claude.json:ro")
        return volumes

    if agent_id == "codex":
        codex_dir = HOME / ".codex"
        if codex_dir.exists():
            volumes.append(f"{codex_dir}:/root/.codex")
        return volumes

    if agent_id == "kimi":
        # Auth via KIMI_API_KEY env var — no volume mount needed.
        return volumes

    raise KeyError(f"Unknown agent '{agent_id}'.")


def compose_config(
    run_id: str,
    agent_id: str,
    variant_dir: Path,
    results_dir: Path,
    certs_dir: Path,
    agent_cmd: list[str],
    extra_env: dict[str, str] | None = None,
) -> dict:
    """
    Return a Docker Compose v3.8 config dict for a single STING run.

    Args:
        run_id:      Unique identifier for this run (used as project name).
        variant_dir: Path to the generated repo variant (mounted as /repo).
        results_dir: Path where logs will be written (mounted as /results).
        agent_cmd:   Full shell command to run the agent inside the sandbox,
                     e.g. 'claude --non-interactive -p "Fix the linting errors"'.
    """
    return {
        "version": "3.8",
        "services": {
            "proxy": {
                "image": "mitmproxy/mitmproxy:latest",
                # mitmdump runs the custom addon that filters + logs egress.
                "environment": {
                    "STING_PROXY_LOG_PATH": "/results/proxy.jsonl",
                },
                "command": [
                    "mitmdump",
                    "-s",
                    "/proxy/addon.py",
                    "--listen-port",
                    "8080",
                    "--set",
                    "confdir=/tmp/mitmproxy",
                ],
                "volumes": [
                    f"{PROXY_ADDON_HOST_PATH.parent}:/proxy:ro",
                    f"{results_dir}:/results",
                    f"{certs_dir}:/tmp/mitmproxy",
                ],
                "networks": ["sting_net"],
                # Kill immediately when sandbox exits so compose up doesn't
                # hang waiting for mitmdump to drain after --abort-on-container-exit.
                "stop_grace_period": "0s",
            },
            "sandbox": {
                "image": t.runner()["image"],
                "pull_policy": "never",
                "cap_add": ["SYS_PTRACE"],
                "environment": {
                    # Route all HTTP(S) traffic through the proxy.
                    # Both uppercase and lowercase forms are set because curl on
                    # Linux prefers lowercase, and agent subshells may not inherit
                    # the uppercase variants.
                    "HTTP_PROXY": "http://proxy:8080",
                    "HTTPS_PROXY": "http://proxy:8080",
                    "http_proxy": "http://proxy:8080",
                    "https_proxy": "http://proxy:8080",
                    # Empty NO_PROXY ensures nothing bypasses the proxy.
                    "NO_PROXY": "",
                    "no_proxy": "",
                    "SSL_CERT_FILE": "/mitmproxy/mitmproxy-ca-cert.pem",
                    "REQUESTS_CA_BUNDLE": "/mitmproxy/mitmproxy-ca-cert.pem",
                    "CURL_CA_BUNDLE": "/mitmproxy/mitmproxy-ca-cert.pem",
                    "NODE_EXTRA_CA_CERTS": "/mitmproxy/mitmproxy-ca-cert.pem",
                    # Browser runtime is preinstalled in the sandbox image so
                    # agents do not burn run time on Playwright/CDN downloads.
                    "PLAYWRIGHT_BROWSERS_PATH": "/ms-playwright",
                    "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
                    "CHROME_BIN": "/usr/bin/chromium",
                    "CHROMIUM_PATH": "/usr/bin/chromium",
                    **(extra_env or {}),
                },
                "command": agent_cmd,
                "working_dir": "/repo",
                "volumes": [
                    f"{variant_dir}:/repo",
                    f"{results_dir}:/var/log/sting",
                    f"{certs_dir}:/mitmproxy:ro",
                    *_auth_volumes(agent_id),
                ],
                "networks": ["sting_net"],
                "depends_on": ["proxy"],
            },
        },
        "networks": {
            "sting_net": {},
        },
    }


def write_compose(config: dict, directory: Path) -> Path:
    """
    Serialise *config* to a docker compose file.

    If *directory* ends in .yml/.yaml, it is treated as the full output path.
    Otherwise the file is written to docker-compose.yml inside *directory*.
    """
    if directory.suffix in {".yml", ".yaml"}:
        compose_path = directory
        compose_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        directory.mkdir(parents=True, exist_ok=True)
        compose_path = directory / "docker-compose.yml"
    compose_path.write_text(
        yaml.dump(config, default_flow_style=False), encoding="utf-8"
    )
    return compose_path
