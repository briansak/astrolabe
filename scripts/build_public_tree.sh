#!/usr/bin/env bash
# Copy the public-tree allowlist into an empty directory. Does not publish.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:?usage: scripts/build_public_tree.sh DEST}"

if [[ -e "$DEST" ]] && [[ -n "$(find "$DEST" -mindepth 1 -print -quit)" ]]; then
  echo "destination is not empty: $DEST" >&2
  exit 1
fi
mkdir -p "$DEST"

allow_files=(
  astrolabe
  README.md
  LICENSE
  THIRD_PARTY_NOTICES.md
  SECURITY.md
  CONTRIBUTING.md
  CODE_OF_CONDUCT.md
  pyproject.toml
  setup.py
  MANIFEST.in
  .gitignore
)

for name in "${allow_files[@]}"; do
  cp "$ROOT/$name" "$DEST/$name"
done

copy_tree() {
  local rel="$1"
  shift
  mkdir -p "$DEST/$rel"
  rsync -a "$@" "$ROOT/$rel/" "$DEST/$rel/"
}

copy_tree data/schemas --exclude '__pycache__/' --exclude '*.pyc'
copy_tree src --exclude '__pycache__/' --exclude '*.pyc' --exclude '*.egg-info' --exclude '*.egg-info/***'
copy_tree tests --exclude '__pycache__/' --exclude '*.pyc' --exclude '*.egg-info' --exclude '*.egg-info/***'
copy_tree scripts --exclude '__pycache__/' --exclude '*.pyc' --exclude '*.egg-info' --exclude '*.egg-info/***'
copy_tree .github
copy_tree docs --exclude 'HANDOFF.md' --exclude '__pycache__/'
copy_tree container --exclude '.build/' --exclude '__pycache__/'
copy_tree services/antares-server \
  --exclude 'build/' \
  --exclude '*.egg-info' \
  --exclude '*.egg-info/***' \
  --exclude '__pycache__/' \
  --exclude '*.pyc'

forbidden="$(
  find "$DEST" \( \
    -name HANDOFF.md -o \
    -name AGENTS.md -o \
    -name .cursor -o \
    -name validation -o \
    -name engagements -o \
    -name var -o \
    -name models -o \
    -name dist -o \
    -name build -o \
    -name .venv -o \
    -name vendor -o \
    -name '*.egg-info' -o \
    -path '*/data/advisories' -o \
    -path '*/container/.build' \
  \) -print
)"
if [[ -n "$forbidden" ]]; then
  echo "public tree contains a forbidden path:" >&2
  echo "$forbidden" >&2
  exit 1
fi

echo "public tree: $DEST"
