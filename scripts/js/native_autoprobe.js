// scripts/js/native_autoprobe.js
'use strict';
function attach(mod, sym) {
  var addr = Module.findExportByName(mod, sym);
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) { this.args = args; },
    onLeave: function (ret) {
      send({ev:'native.call', mod: mod, sym: sym});
    }
  });
  send({ev:'native.hooked', mod: mod, sym: sym});
  return true;
}
var libs = ['libssl.so', 'libboringssl.so', 'libcrypto.so', 'libmbedtls.so'];
var syms = ['SSL_read', 'SSL_write', 'EVP_EncryptUpdate', 'EVP_DecryptUpdate'];
libs.forEach(function (m) { syms.forEach(function (s) { attach(m, s); }); });
