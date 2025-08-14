#!/usr/bin/env bash
set -euo pipefail
AVD_NAME="${AVD_NAME:-emu-bugbounty}"
exec emulator -avd "$AVD_NAME" -writable-system -no-snapshot -no-boot-anim -gpu swiftshader_indirect
