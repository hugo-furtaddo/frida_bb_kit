// scripts/js/bypass_lab.js
// LAB-ONLY: force return values of specific Java methods with explicit type list.
// Requires pkgAllow via RPC config. Disabled by default.

'use strict';

var cfg = { pkgAllow: [], dryRun: true };
var rules = []; // {class, method, types: [], ret}

function allowedPkg() {
  try {
    var app = Java.use('android.app.ActivityThread').currentApplication();
    var ctx = app.getApplicationContext();
    return cfg.pkgAllow.indexOf(ctx.getPackageName()+"") >= 0;
  } catch (e) { return false; }
}

rpc.exports = {
  config: function (json) { try { Object.assign(cfg, JSON.parse(json)); return true; } catch (e) { return false; } },
  rule: function (json) {
    try {
      var r = JSON.parse(json);
      if (!r.class || !r.method || !Array.isArray(r.types) || typeof r.ret === 'undefined') return false;
      rules.push(r);
      if (!cfg.dryRun && allowedPkg()) applyRule(r);
      return true;
    } catch (e) { return false; }
  },
  list: function () { return JSON.stringify(rules); },
  clear: function () { rules = []; return true; },
  enable: function () {
    if (!allowedPkg()) { send({ev:"bypass.warn", msg:"pkg not allowed"}); return false; }
    cfg.dryRun = false;
    rules.forEach(applyRule);
    return true;
  },
  disable: function () { cfg.dryRun = true; return true; }
};

function applyRule(r) {
  Java.perform(function () {
    try {
      var C = Java.use(r.class);
      var m = C[r.method].overload.apply(C[r.method], r.types);
      m.implementation = function () {
        send({ev:"bypass.hit", cls:r.class, m:r.method, types:r.types, ret:r.ret});
        return r.ret;
      };
      send({ev:"bypass.apply", cls:r.class, m:r.method, count:1});
    } catch (e) {
      send({ev:"bypass.error", rule:r, error:e.toString()});
    }
  });
}
