#!/usr/bin/env bash
set -euo pipefail
[ -f .env ] && source .env || true
PKG="${1:-${PKG_DEFAULT:-com.android.settings}}"
. .venv/bin/activate
python scripts/control/control.py -p "$PKG" -s scripts/js/native_template.js --spawn
