#!/usr/bin/env bash
# Stage Antares-1B with a resumable download. HF_TOKEN is read from the environment.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${ANTARES_MODEL_PATH:-"$ROOT/models/1b"}"
REPO="fdtn-ai/antares-1b"
EXPECTED="6ba4155a50cd0cede3e10285b0d84b460dcc3caa0175a424e14d3bb606fda675"

if [[ -z "${HF_TOKEN:-}" ]]; then
  echo "HF_TOKEN is required in the environment" >&2
  exit 1
fi

mkdir -p "$DEST"

fetch() {
  local name="$1"
  local url="https://huggingface.co/${REPO}/resolve/main/${name}"
  curl --fail --location --continue-at - \
    --header "Authorization: Bearer ${HF_TOKEN}" \
    --output "${DEST}/${name}" \
    "$url"
}

fetch config.json
fetch generation_config.json
fetch tokenizer.json
fetch tokenizer_config.json
fetch chat_template.jinja
fetch model.safetensors

actual="$(python3 - "$DEST/model.safetensors" <<'PY'
import hashlib, sys
path = sys.argv[1]
digest = hashlib.sha256()
with open(path, "rb") as handle:
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
print(digest.hexdigest())
PY
)"

if [[ "$actual" != "$EXPECTED" ]]; then
  echo "SHA256 mismatch: expected $EXPECTED got $actual" >&2
  exit 1
fi

echo "staged $DEST/model.safetensors $actual"
