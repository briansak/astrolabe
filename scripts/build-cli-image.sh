#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ZIP="${ANTARES_CLI_ZIP:-}"
IMAGE="${ASTROLABE_CLI_IMAGE:-astrolabe-antares-cli:1}"

if [[ -z "$ZIP" || ! -f "$ZIP" ]]; then
  echo "Set ANTARES_CLI_ZIP to antares-cli.zip in the weights directory" >&2
  exit 1
fi

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp "$ZIP" "$stage/antares-cli.zip"
cp "$ROOT/container/Dockerfile" "$ROOT/container/entrypoint.sh" "$ROOT/container/long_completion.py" "$ROOT/container/constraints.txt" "$stage/"
docker build -t "$IMAGE" "$stage"
echo "built $IMAGE"
