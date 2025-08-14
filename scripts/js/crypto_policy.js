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

    // init(int, Key)
    Cipher.init.overload('int', 'java.security.Key').implementation = function (opmode, key) {
      var algo = this.getAlgorithm();
      // NUNCA vaze material de chave
      send({ev:"cipher.init", algorithm: algo, opmode: opmode, keyAlgo: key.getAlgorithm()+"", keyFormat: key.getFormat()+""});
      return this.init(opmode, key);
    };

    // doFinal(byte[])
    Cipher.doFinal.overload('[B').implementation = function (input) {
      var algo = this.getAlgorithm();
      var out = this.doFinal(input);
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
    MD.getInstance.overload('java.lang.String').implementation = function (alg) {
      var md = this.getInstance(alg);
      send({ev:"md.getInstance", algorithm: ""+alg});
      return md;
    };
    MD.digest.overload('[B').implementation = function (input) {
      var res = this.digest(input);
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
    Mac.getInstance.overload('java.lang.String').implementation = function (alg) {
      var m = this.getInstance(alg);
      send({ev:"mac.getInstance", algorithm: ""+alg});
      return m;
    };
    Mac.doFinal.overload('[B').implementation = function (input) {
      var res = this.doFinal(input);
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
    Sig.getInstance.overload('java.lang.String').implementation = function (alg) {
      var s = this.getInstance(alg);
      send({ev:"sig.getInstance", algorithm: ""+alg});
      return s;
    };
    Sig.sign.implementation = function () {
      var res = this.sign();
      if (policy.enabled) {
        send({ev:"sig.sign", algorithm: ""+this.getAlgorithm(),
              outSample: bytesToHex(res, policy.sampleBytes)});
      }
      return res;
    };
  } catch (e) {}
});
