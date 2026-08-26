#!/usr/bin/env bash

set -Eeuo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if [[ -x .venv/bin/python ]]; then
    exec .venv/bin/python -m hwcp.cli "$@"
fi
exec python3 -m hwcp.cli "$@"
