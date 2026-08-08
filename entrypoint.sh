#!/bin/bash
set -e

mkdir -p /var/log/sting
mkdir -p /repo

# Write Claude Code OAuth credentials for the agent user.
# Using an env var avoids the Docker Desktop macOS limitation where a file
# cannot be bind-mounted inside a parent directory already mounted read-only.
if [ -n "${CLAUDE_CREDENTIALS_JSON:-}" ]; then
  mkdir -p /home/agent/.claude
  printf '%s' "$CLAUDE_CREDENTIALS_JSON" > /home/agent/.claude/.credentials.json
  chmod 600 /home/agent/.claude/.credentials.json
  chown -R agent:agent /home/agent/.claude
fi

# Write kimi-code config for the kimi agent.
if [ -n "${KIMI_CONFIG_TOML:-}" ]; then
  mkdir -p /root/.kimi-code
  printf '%s' "$KIMI_CONFIG_TOML" > /root/.kimi-code/config.toml
  chmod 600 /root/.kimi-code/config.toml
fi

# Give the agent user write access so it can create final_message.txt and
# run dev setup tasks (uv sync, pip install, etc.) inside /repo.
chown agent:agent /var/log/sting
chown agent:agent /repo

# Pre-create log files so inotifywait redirects never fail on first write
touch /var/log/sting/fileio.jsonl /var/log/sting/shell.log

# Start file watcher (exclude venv and cache noise)
inotifywait -m -r --format '{"ts":"%T","event":"%e","path":"%w%f"}' \
  --timefmt '%Y-%m-%dT%H:%M:%SZ' \
  --exclude '/(\.venv|__pycache__|\.git)(/|$)' \
  /repo >> /var/log/sting/fileio.jsonl 2>/dev/null &
INOTIFY_PIDS="$!"

# Secondary watcher: track METADATA access inside .venv for dependency attacks.
# The main watcher excludes .venv to avoid uv-sync noise, but the payload for
# metadata_readme attacks lives at .venv/**/*.dist-info/METADATA and must be
# detected so _payload_file_opened() does not incorrectly return False.
if [ -d /repo/.venv ]; then
  inotifywait -m -r --format '{"ts":"%T","event":"%e","path":"%w%f"}' \
    --timefmt '%Y-%m-%dT%H:%M:%SZ' \
    --include 'METADATA$' \
    /repo/.venv >> /var/log/sting/fileio.jsonl 2>/dev/null &
  INOTIFY_PIDS="$INOTIFY_PIDS $!"
fi

# Wait for the proxy CA bundle on first boot so HTTPS clients can trust the
# mitmproxy certificate before the agent starts.
if [ -n "${SSL_CERT_FILE:-}" ] && [ ! -f "${SSL_CERT_FILE}" ]; then
  for _ in $(seq 1 30); do
    if [ -f "${SSL_CERT_FILE}" ]; then
      break
    fi
    sleep 1
  done
fi

# Point uv at the pre-built venv so `uv sync` is a ~1s audit, not an 86s copy.
export UV_PROJECT_ENVIRONMENT=/opt/repo-venv

# Hand off to agent, trace all shell commands.
# The agent command (in $@) wraps claude with 'su -p agent' so claude runs as
# non-root (required — claude blocks --dangerously-skip-permissions for root).
# Strace runs as root with CAP_SYS_PTRACE, tracing the su'd child processes.
# Note: exec is intentionally avoided so the inotifywait background jobs can be
# cleaned up after the agent exits (exec would leave them as orphans that keep
# the container alive indefinitely).
strace -f \
  -e trace=execve,openat,connect \
  -o /var/log/sting/shell.log \
  "$@"
_exit=$?

# Kill background file watchers so the container exits cleanly.
# shellcheck disable=SC2086
kill $INOTIFY_PIDS 2>/dev/null || true
# shellcheck disable=SC2086
wait $INOTIFY_PIDS 2>/dev/null || true

exit $_exit
