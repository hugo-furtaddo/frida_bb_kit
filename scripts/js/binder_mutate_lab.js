// scripts/js/binder_mutate_lab.js
// LAB-ONLY: observe Binder transactions; mutate only marked codes via RPC.
'use strict';

var mode = 'observe';
var labCodes = {};

rpc.exports = {
  addcode: function (code) { labCodes[parseInt(code)] = true; return true; },
  clearcodes: function () { labCodes = {}; return true; },
  mode: function (m) { if (['observe','drop','flipflag'].indexOf(m)>=0) { mode = m; return true; } return false; }
};

Java.perform(function () {
  try {
    var BP = Java.use('android.os.BinderProxy');
    var orig = BP.transact.overload('int','android.os.Parcel','android.os.Parcel','int');
    orig.implementation = function (code, data, reply, flags) {
      var c = code|0, f = flags|0, mutate = !!labCodes[c];
      send({ev:"binder.tx", code:c, flags:f, mode:mode, mutate:mutate});
      if (!mutate || mode==='observe') return orig.call(this, code, data, reply, flags);
      if (mode === 'drop') return false;
      if (mode === 'flipflag') return orig.call(this, code, data, reply, (f ^ 0x01)|0);
      return orig.call(this, code, data, reply, flags);
    };
    send({ev:"binder.hook","ok":true});
  } catch (e) {
    send({ev:"binder.err", error:e.toString()});
  }
});
