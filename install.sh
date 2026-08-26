#!/usr/bin/env bash

set -Eeuo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
MODE="${1:-gui}"
if [[ "$MODE" != 'gui' && "$MODE" != '--worker-only' ]]; then
    printf 'Usage: ./install.sh [--worker-only]\n' >&2
    exit 2
fi

printf '[DISCOVER] checking Python and project files\n'
command -v python3 >/dev/null 2>&1 || { printf 'ERROR: Python 3.11+ is required.\n' >&2; exit 1; }
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || { printf 'ERROR: Python 3.11+ is required.\n' >&2; exit 1; }

printf '[INSTALL] creating or repairing the local virtual environment\n'
python3 -m venv .venv
if [[ "$MODE" == '--worker-only' ]]; then
    .venv/bin/python -m pip install --disable-pip-version-check -e .
else
    .venv/bin/python -m pip install --disable-pip-version-check -e '.[gui]'
fi

printf '[VERIFY] running syntax, core tests, and offscreen GUI import\n'
.venv/bin/python -m compileall -q hwcp tests
.venv/bin/python -m unittest discover -s tests -v
if [[ "$MODE" != '--worker-only' ]]; then
    QT_QPA_PLATFORM=offscreen HWCP_GUI_SMOKE=1 .venv/bin/python -m hwcp.gui
    printf 'schema=1\nversion=0.1.0\n' >.venv/.hwcp-setup-v1.tmp
    mv -f .venv/.hwcp-setup-v1.tmp .venv/.hwcp-setup-v1
    printf 'Setup complete. run.sh launches the control room; cli.sh provides automation.\n'
else
    printf 'schema=1\nversion=0.1.0\n' >.venv/.hwcp-worker-v1.tmp
    mv -f .venv/.hwcp-worker-v1.tmp .venv/.hwcp-worker-v1
    printf 'Worker-only setup complete. cli.sh provides the pull worker.\n'
fi
