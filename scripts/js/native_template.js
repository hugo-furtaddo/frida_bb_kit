// scripts/js/native_template.js
'use strict';

function hook(sym, reader) {
  var addr = Module.findExportByName(null, sym);
  if (!addr) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      try {
        var path = reader(args);
        if (path) send({ev: sym, path: path});
      } catch (e) {}
    }
  });
  return true;
}

hook('open',   function (args) { return Memory.readUtf8String(args[0]); });
hook('open64', function (args) { return Memory.readUtf8String(args[0]); });
hook('openat', function (args) { return Memory.readUtf8String(args[1]); });
