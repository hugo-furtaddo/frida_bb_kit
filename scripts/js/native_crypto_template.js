// scripts/js/native_crypto_template.js
'use strict';

function safeHex(addr, size, max) {
  if (addr.isNull()) return null;
  var n = size.toInt32 ? size.toInt32() : size|0;
  var len = Math.min(n, max);
  try {
    var bytes = Memory.readByteArray(addr, len);
    var u8 = new Uint8Array(bytes);
    var out = [];
    for (var i = 0; i < u8.length; i++) {
      var b = u8[i] & 0xff;
      out.push((b < 16 ? "0" : "") + b.toString(16));
    }
    return out.join("");
  } catch (e) { return null; }
}

var maxSample = 64;

function attachIfExport(mod, name, handler) {
  var addr = Module.findExportByName(mod, name);
  if (!addr) return false;
  Interceptor.attach(addr, handler);
  send({ev:"native.hook", where: name, module: mod});
  return true;
}

// EVP_EncryptUpdate/DecryptUpdate: (ctx, out, outl, in, inl)
attachIfExport("libcrypto.so", "EVP_EncryptUpdate", {
  onEnter: function (args) { this.inp = args[3]; this.inl = args[4]; },
  onLeave: function (ret) { try { send({ev:"EVP_EncryptUpdate", inSample: safeHex(this.inp, this.inl, maxSample)}); } catch (e) {} }
});

attachIfExport("libcrypto.so", "EVP_DecryptUpdate", {
  onEnter: function (args) { this.inp = args[3]; this.inl = args[4]; },
  onLeave: function (ret) { try { send({ev:"EVP_DecryptUpdate", inSample: safeHex(this.inp, this.inl, maxSample)}); } catch (e) {} }
});

// PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, digest, keylen, out)
attachIfExport("libcrypto.so", "PKCS5_PBKDF2_HMAC", {
  onEnter: function (args) {
    this.pass = args[0]; this.passlen = args[1];
    this.salt = args[2]; this.saltlen = args[3];
    this.iter = args[4];
  },
  onLeave: function (ret) {
    try {
      send({ev:"PKCS5_PBKDF2_HMAC",
            passSample: safeHex(this.pass, this.passlen, maxSample),
            saltSample: safeHex(this.salt, this.saltlen, maxSample),
            iter: (this.iter.toInt32?this.iter.toInt32():this.iter)|0});
    } catch (e) {}
  }
});
