#!/usr/bin/env bash
set -euo pipefail
# source .env se existir
[ -f .env ] && source .env || true

ADB_BIN="${ADB_BIN:-adb}"
FRIDA_SERVER_BIN="${FRIDA_SERVER_BIN:-$HOME/tools/frida/frida-server-17.2.16-android-x86_64}"

if [ ! -f "$FRIDA_SERVER_BIN" ]; then
  echo "[!] Ajuste FRIDA_SERVER_BIN no .env (binário não encontrado)"
  exit 1
fi

$ADB_BIN root || true
$ADB_BIN remount || true
$ADB_BIN push "$FRIDA_SERVER_BIN" /data/local/tmp/frida-server
$ADB_BIN shell "chmod 755 /data/local/tmp/frida-server"
$ADB_BIN shell "/data/local/tmp/frida-server &"
echo "[+] frida-server iniciado. Teste: frida-ps -U"
