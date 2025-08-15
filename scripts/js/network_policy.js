// scripts/js/network_policy.js
'use strict';

var policy = {
  enabled: true,
  allowHosts: [".*"],
  redactHeaders: ["authorization", "cookie", "set-cookie"],
  sampleBodyBytes: 512,
  maxHeaders: 40,
  logStack: false
};

function matchHost(host) {
  try {
    for (var i = 0; i < policy.allowHosts.length; i++) {
      var re = new RegExp(policy.allowHosts[i], "i");
      if (re.test(host)) return true;
    }
  } catch (e) {}
  return false;
}

function redactHeader(name, value) {
  var lower = (name || "").toLowerCase();
  for (var i = 0; i < policy.redactHeaders.length; i++) {
    if (lower === policy.redactHeaders[i].toLowerCase()) return "***redacted***";
  }
  return value;
}

rpc.exports = {
  setpolicy: function (json) { try { Object.assign(policy, JSON.parse(json)); return true; } catch (e) { return false; } },
  enable: function () { policy.enabled = true; return true; },
  disable: function () { policy.enabled = false; return true; }
};

Java.perform(function () {
  try {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var origNewCall = OkHttpClient.newCall.overload('okhttp3.Request');

    origNewCall.implementation = function (req) {
      try {
        if (policy.enabled) {
          var url = req.url().toString();
          var host = req.url().host();
          if (matchHost(host)) {
            var method = req.method();
            var headers = req.headers();
            var hdrs = {};
            var count = Math.min(headers.size(), policy.maxHeaders);
            for (var i = 0; i < count; i++) {
              var name = headers.name(i);
              var value = headers.value(i);
              var val = redactHeader(name, value+"");
              if (hdrs[name]) {
                if (Array.isArray(hdrs[name])) {
                  hdrs[name].push(val);
                } else {
                  hdrs[name] = [hdrs[name], val];
                }
              } else {
                hdrs[name] = val;
              }
            }
            send({ev:"okhttp.request", method: method, url: url, host: host, headers: hdrs});
            if (policy.logStack) {
              var Log = Java.use("android.util.Log");
              var Ex = Java.use("java.lang.Exception");
              send({ev:"stack", where:"okhttp.newCall",
                    stack: Log.getStackTraceString(Ex.$new())+""});
            }
          }
        }
      } catch (e) {}
      return origNewCall.call(this, req);
    };
  } catch (e) {}

  try {
    var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
    var origSet = HUC.setRequestProperty.overload('java.lang.String', 'java.lang.String');
    var origConn = HUC.connect;

    origSet.implementation = function (k, v) {
      try {
        if (policy.enabled) {
          var u = this.getURL();
          var host = u.getHost();
          if (matchHost(host)) {
            var key = "" + k;
            var val = redactHeader(key, "" + v);
            send({ev:"huc.header", url: u.toString()+"", host: host+"", header: key, value: val});
          }
        }
      } catch (e) {}
      return origSet.call(this, k, v);
    };
    origConn.implementation = function () {
      try {
        if (policy.enabled) {
          var u = this.getURL();
          var host = u.getHost();
          if (matchHost(host)) {
            send({ev:"huc.connect", url: u.toString()+"", host: host+""});
          }
        }
      } catch (e) {}
      return origConn.call(this);
    };
  } catch (e) {}
});
