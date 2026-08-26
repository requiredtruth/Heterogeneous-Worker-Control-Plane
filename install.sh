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

if [[ "$MODE" != '--worker-only' && "$(uname -s)" == 'Linux' ]] && ! ldconfig -p 2>/dev/null | grep -q 'libEGL\.so\.1'; then
    printf '[INSTALL] PySide6 requires the system EGL runtime\n'
    if command -v apt-get >/dev/null 2>&1; then
        if [[ "$(id -u)" -eq 0 ]]; then
            apt-get update
            apt-get install -y --no-install-recommends libegl1
        elif command -v sudo >/dev/null 2>&1; then
            sudo apt-get update
            sudo apt-get install -y --no-install-recommends libegl1
        else
            printf 'ERROR: install libegl1 with your system package manager, then rerun install.sh.\n' >&2
            exit 1
        fi
    else
        printf 'ERROR: libEGL.so.1 is missing; install your distribution EGL runtime, then rerun install.sh.\n' >&2
        exit 1
    fi
fi

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
