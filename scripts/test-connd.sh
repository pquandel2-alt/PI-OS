#!/usr/bin/env bash
# Connectivity daemon tests. The BlueZ tests run a GLib main loop thread for the whole process; libdbus aborts when other tests
# open further D-Bus connections next to it, so they run in their own pytest process.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
"$PY" -m pytest -q tests/connd/test_bluez.py -p no:cacheprovider "$@"
"$PY" -m pytest -q tests/connd --ignore=tests/connd/test_bluez.py tests/shield/test_sysops.py -p no:cacheprovider "$@"
