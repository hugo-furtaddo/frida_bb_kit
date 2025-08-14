# Políticas de uso (rede & cripto)

**Objetivo**: observar comportamento para validar hipóteses em *lab autorizado*, sem vazar segredos.

## Regras
1. **Allowlist** de hosts obrigatória para exercício sério. Ajuste `policy.allowHosts` no `network_policy.js`.
2. **Redação** de cabeçalhos sensíveis (`authorization`, `cookie`, `set-cookie`). Amplie se necessário.
3. **Amostragem limitada** de dados (`sampleBodyBytes`, `sampleBytes`) — nunca logar payload completo sem motivo.
4. **Sem chaves**: não logue material de chave (apenas metadados como algoritmo e formato).
5. **Rate-limit/volume**: evite *flood* de mensagens; desabilite logs verbosos depois de validar a hipótese.
6. **RPC para controle**: use `script.exports.setpolicy(JSON)` / `enable()` / `disable()` para alternar em tempo real.
7. **Relatório**: inclua sempre mitigação (pinning robusto, atestação, uso correto de Keystore/Keychain).

## Quando usar qual script
- `network_policy.js`: triagem de rede (OkHttp/HttpsURLConnection). Primeiro passo para confirmar rotas, hosts e cabeçalhos.
- `crypto_policy.js`: identificar algoritmos/fluxos Java (`Cipher`, `MessageDigest`, `Mac`, `Signature`).
- `native_crypto_template.js`: quando suspeitar de **NDK/OpenSSL** (criptografia em C/C++).



## Módulos LAB-ONLY (bypasses controlados)
- `bypass_lab.js`: motor de regras para forçar retornos de métodos em pacotes permitidos (ex.: apps de laboratório). Exige `pkgAllow` e ativação explícita.
- `webview_ssl_lab.js`: demonstração de sobrescrita do tratamento de erros SSL em `WebViewClient`, com `pkgAllow` + `hostAllow` obrigatórios.
- `binder_mutate_lab.js`: observação de `BinderProxy.transact` com opções de mutação **somente** para códigos lab definidos via RPC.

**Importante**: estes módulos existem para validar hipóteses em ambientes de teste; não use contra terceiros. Mantenha allowlists estritas.
