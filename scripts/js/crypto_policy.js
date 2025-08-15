// scripts/js/crypto_policy.js
// Observa operações criptográficas de alto nível (Java): Cipher, MessageDigest, Mac, Signature.
// Políticas: amostragem limitada, sem exposição de chaves.

'use strict';

var policy = {
  enabled: true,
  sampleBytes: 64,    // captura no máximo N bytes de entrada/saída
  logStack: false
};

rpc.exports = {
  setpolicy: function (json) {
    try { Object.assign(policy, JSON.parse(json)); return true; } catch (e) { return false; }
  },
  enable: function () { policy.enabled = true; return true; },
  disable: function () { policy.enabled = false; return true; }
};

function bytesToHex(arr, nmax) {
  if (!arr) return null;
  var len = Math.min(arr.length, nmax);
  var out = [];
  for (var i = 0; i < len; i++) {
    var b = arr[i] & 0xff;
    out.push((b < 16 ? "0" : "") + b.toString(16));
  }
  return out.join("");
}

Java.perform(function () {
  // Cipher
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    var Key = Java.use('java.security.Key');
    var Arrays = Java.use('java.util.Arrays');

    var Cipher_init = Cipher.init.overload('int', 'java.security.Key');
    Cipher_init.implementation = function (opmode, key) {
      var algo = this.getAlgorithm();
      var ret = Cipher_init.call(this, opmode, key);
      send({ev:"cipher.init", algorithm: algo, opmode: opmode, keyAlgo: key.getAlgorithm()+"", keyFormat: key.getFormat()+""});
      return ret;
    };

    var Cipher_doFinal = Cipher.doFinal.overload('[B');
    Cipher_doFinal.implementation = function (input) {
      var algo = this.getAlgorithm();
      var out = Cipher_doFinal.call(this, input);
      if (policy.enabled) {
        send({ev:"cipher.doFinal", algorithm: algo,
              inSample: bytesToHex(input, policy.sampleBytes),
              outSample: bytesToHex(out, policy.sampleBytes)});
        if (policy.logStack) {
          send({ev:"stack", where:"Cipher.doFinal", stack: Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())});
        }
      }
      return out;
    };
  } catch (e) {}

  // MessageDigest
  try {
    var MD = Java.use('java.security.MessageDigest');
    var MD_getInstance = MD.getInstance.overload('java.lang.String');
    MD_getInstance.implementation = function (alg) {
      var md = MD_getInstance.call(MD, alg);
      send({ev:"md.getInstance", algorithm: ""+alg});
      return md;
    };
    var MD_digest = MD.digest.overload('[B');
    MD_digest.implementation = function (input) {
      var res = MD_digest.call(this, input);
      if (policy.enabled) {
        send({ev:"md.digest", algorithm: ""+this.getAlgorithm(),
              inSample: bytesToHex(input, policy.sampleBytes),
              outSample: bytesToHex(res, policy.sampleBytes)});
      }
      return res;
    };
  } catch (e) {}

  // Mac
  try {
    var Mac = Java.use('javax.crypto.Mac');
    var Mac_getInstance = Mac.getInstance.overload('java.lang.String');
    Mac_getInstance.implementation = function (alg) {
      var m = Mac_getInstance.call(Mac, alg);
      send({ev:"mac.getInstance", algorithm: ""+alg});
      return m;
    };
    var Mac_doFinal = Mac.doFinal.overload('[B');
    Mac_doFinal.implementation = function (input) {
      var res = Mac_doFinal.call(this, input);
      if (policy.enabled) {
        send({ev:"mac.doFinal", algorithm: ""+this.getAlgorithm(),
              inSample: bytesToHex(input, policy.sampleBytes),
              outSample: bytesToHex(res, policy.sampleBytes)});
      }
      return res;
    };
  } catch (e) {}

  // Signature
  try {
    var Sig = Java.use('java.security.Signature');
    var Sig_getInstance = Sig.getInstance.overload('java.lang.String');
    Sig_getInstance.implementation = function (alg) {
      var s = Sig_getInstance.call(Sig, alg);
      send({ev:"sig.getInstance", algorithm: ""+alg});
      return s;
    };
    var Sig_sign = Sig.sign.overload();
    Sig_sign.implementation = function () {
      var res = Sig_sign.call(this);
      if (policy.enabled) {
        send({ev:"sig.sign", algorithm: ""+this.getAlgorithm(),
              outSample: bytesToHex(res, policy.sampleBytes)});
      }
      return res;
    };
  } catch (e) {}
});
