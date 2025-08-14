// scripts/js/binder_watch.js
'use strict';
Java.perform(function () {
  try {
    var BP = Java.use('android.os.BinderProxy');
    var orig = BP.transact.overload('int', 'android.os.Parcel', 'android.os.Parcel', 'int');
    orig.implementation = function (code, data, reply, flags) {
      send({ev:'binder.transact', code: code|0, flags: flags|0});
      return orig.call(this, code, data, reply, flags);
    };
  } catch (e) {}
});
