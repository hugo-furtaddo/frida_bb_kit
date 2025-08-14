# Frida Bug Bounty MiniKit

Ambiente mínimo para estudos/bug bounty (Android) com **Frida**.

## Requisitos
- Ubuntu 22.04+
- `adb` com emulador/dispositivo acessível
- `python3-venv` e `xz-utils`
- `frida-server` correspondente ao `frida --version` do host (já baixado no seu `~/tools/frida/` ou similar)

## Setup rápido
```bash
# 1) criar venv só para os scripts Python de controle
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install frida==17.2.16

# 2) configurar variáveis (opcional)
cp config/env.example .env
# edite .env conforme seu ambiente (FRIDA_SERVER_BIN, PKG default, etc.)

# 3) subir frida-server no device/emulador (em outro terminal com o AVD ligado)
bin/frida-up.sh

# 4) teste um hook Java (onResume) no Settings
bin/hook-java.sh
# ou:
. .venv/bin/activate && python scripts/control/control.py -p com.android.settings -s scripts/js/hook_onresume.js --spawn
```

## Scripts principais
- `scripts/js/hook_onresume.js`: hook Java para confirmar injeção (onResume).
- `scripts/js/hook_overload.js`: exemplo de overloads (Class.forName).
- `scripts/js/native_template.js`: template de hook nativo (open/openat).
- `scripts/js/rpc_template.js`: exemplo de `rpc.exports` + mensagens.
- `scripts/control/control.py`: controlador Python (spawn/attach, mensagens, RPC, spawn-gating).

## Comandos úteis
- `bin/run-emulator.sh` — exemplo de inicialização com `-gpu swiftshader_indirect`.
- `bin/frida-up.sh` — empurra e inicia `frida-server` no device.
- `bin/hook-java.sh` — executa hook mínimo contra Settings.
- `bin/hook-native.sh` — executa template nativo contra Settings (para demonstração).

## Avisos
- Use **apenas** em ambientes autorizados.
- Scripts são ruidosos por padrão; refine filtros/limites antes de um relatório.


---

## Modos de operação

Use `--mode` no controlador:

- `recon` (padrão): amostragem reduzida, logs essenciais, filtros conservadores.
- `precision`: logs focados, ideal para reproduzir um achado; ativa `--attach` por padrão.
- `aggressive`: ativa `--spawn` + `--spawn-gating`, aumenta amostragem e traça mais eventos (cuidado com volume).

Exemplos:
```bash
# Recon (rápido) em Settings
python scripts/control/control.py -p com.android.settings -s scripts/js/network_policy.js --mode recon

# Precision para reproduzir caso de cripto
python scripts/control/control.py -p com.android.settings -s scripts/js/crypto_policy.js --mode precision

# Aggressive com watchers adicionais (classloader/binder) encadeados
python scripts/control/control.py -p com.android.settings -s scripts/js/network_policy.js --mode aggressive   --also scripts/js/classloader_watch.js --also scripts/js/binder_watch.js
```

## Saída estruturada
O controlador pode gravar NDJSON com `--outfile out/sessão.ndjson`. Cada linha contém `ts`, `pkg`, `pid`, `ev` e `payload`.

## Watchers extras
- `classloader_watch.js`: observa classes carregadas dinamicamente (DexClassLoader/PathClassLoader).
- `webview_watch.js`: registra navegações em WebView e pontes JS (quando presentes).
- `binder_watch.js`: loga códigos de transação em `BinderProxy.transact` (telemetria leve).
- `native_autoprobe.js`: tenta anexar funções comuns de crypto (boringssl/openssl/mbedtls) se carregadas.
