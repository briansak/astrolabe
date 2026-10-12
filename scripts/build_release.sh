#!/usr/bin/env bash
# Build wheels and sdists into dist/ and write SHA256SUMS. Does not upload.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-python3}"
"$PYTHON" -m pip install --quiet build
rm -rf dist
mkdir -p dist

"$PYTHON" -m pip wheel --no-deps -w dist .
"$PYTHON" -m pip wheel --no-deps -w dist services/antares-server
"$PYTHON" -m build --sdist --outdir dist .
"$PYTHON" -m build --sdist --outdir dist services/antares-server

(
  cd dist
  shasum -a 256 -- * > SHA256SUMS
)

check="$(mktemp -d)"
"$PYTHON" -m venv "$check/venv"
"$check/venv/bin/pip" install --no-deps "$ROOT"/dist/astrolabe-0.1.0-*.whl
home="$(mktemp -d)"
(
  unset ANTARES_MODEL_PATH ANTARES_SOCKET ASTROLABE_INFERENCE_SOCKET ANTARES_TOKEN_DIR ASTROLABE_TOKEN_DIR
  unset ASTROLABE_ENGAGEMENTS_DIR ASTROLABE_AUDIT_LOG ASTROLABE_ADVISORY_CACHE
  export HOME="$home"
  version="$("$check/venv/bin/astrolabe" --version)"
  test "$version" = "astrolabe 0.1.0"
  set +e
  "$check/venv/bin/astrolabe" doctor >/dev/null
  doctor_status=$?
  set -e
  test "$doctor_status" -eq 0 -o "$doctor_status" -eq 1
)
rm -rf "$check" "$home"

echo "Wrote dist/SHA256SUMS"
