#!/usr/bin/env bash
set -euo pipefail
[ -f .env ] && source .env || true
PKG="${1:-${PKG_DEFAULT:-com.android.settings}}"
if [ ! -f .venv/bin/activate ]; then
  echo "Erro: ambiente virtual não disponível" >&2
  exit 1
fi
. .venv/bin/activate
python scripts/control/control.py -p "$PKG" -s scripts/js/hook_onresume.js --spawn
