import json
import os
from datetime import datetime, timezone
from mitmproxy import http

LOG_PATH = os.environ.get("STING_PROXY_LOG_PATH", "/var/log/sting/proxy.jsonl")


def _log(event: dict) -> None:
    """Append one JSON line directly to the log file, bypassing the logging module."""
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
    except OSError:
        pass


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    _log(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "request",
            "host": host,
            "method": flow.request.method,
            "url": flow.request.url,
        }
    )
