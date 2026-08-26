#!/usr/bin/env bash

set -Eeuo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if [[ ! -f .venv/.hwcp-setup-v1 ]]; then
    printf 'Setup is missing or incomplete; running install.sh.\n'
    "$ROOT/install.sh"
fi
exec "$ROOT/.venv/bin/python" -m hwcp.gui "$@"
