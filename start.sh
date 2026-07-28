#!/bin/bash
set -e

echo "Extracting Claude credentials from macOS Keychain..."

CREDS=$(security find-generic-password -s "Claude Code-credentials" -w 2>/dev/null)

if [ -z "$CREDS" ]; then
  echo "No Claude credentials found in Keychain. Run 'claude login' first."
  exit 1
fi

mkdir -p ~/.claude
echo "$CREDS" > ~/.claude/.credentials.json
chmod 600 ~/.claude/.credentials.json

echo "Credentials written to ~/.claude/.credentials.json"
echo "Starting STING sandbox..."

docker compose up "$@"