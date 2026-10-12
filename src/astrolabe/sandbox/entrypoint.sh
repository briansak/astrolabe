#!/bin/sh
set -eu

if [ -z "${ANTARES_DATA_DIR:-}" ]; then
  echo "ANTARES_DATA_DIR must be set for every container run" >&2
  exit 1
fi

socat TCP-LISTEN:8000,bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:/run/astrolabe/inference.sock &
exec "$@"
