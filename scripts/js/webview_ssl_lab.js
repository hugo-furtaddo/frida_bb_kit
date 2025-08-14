// scripts/js/webview_ssl_lab.js
'use strict';

var cfg = { pkgAllow: [], hostAllow: [], enabled: false };

rpc.exports = {
  config: function (json) { try { Object.assign(cfg, JSON.parse(json)); return true; } catch (e) { return false; } },
  enable: function () { cfg.enabled = true; return true; },
  disable: function () { cfg.enabled = false; return true; }
};

function allowedPkg() {
  try {
    var app = Java.use('android.app.ActivityThread').currentApplication();
    var ctx = app.getApplicationContext();
    var pkg = ctx.getPackageName().toString();
    return cfg.pkgAllow.indexOf(pkg) >= 0;
  } catch (e) { return false; }
}

function allowedHost(h) {
  for (var i=0; i<cfg.hostAllow.length; i++) {
    try { if (new RegExp(cfg.hostAllow[i], 'i').test(h)) return true; } catch (e) {}
  }
  return false;
}

Java.perform(function () {
  var WVC;
  try { WVC = Java.use('android.webkit.WebViewClient'); } catch (e) { return; }
  var URL = Java.use('java.net.URL');

  if (WVC.onReceivedSslError) {
    var orig = WVC.onReceivedSslError;
    orig.implementation = function (view, handler, error) {
      var url = "(unknown)", host = "(unknown)";
      try { url = error.getUrl()+""; host = URL.$new(url).getHost()+""; } catch (e) {}

      if (cfg.enabled && allowedPkg() && allowedHost(host)) {
        send({ev:"webview.ssl.override", url: url, host: host});
        try { handler.proceed(); } catch (e) { send({ev:"webview.ssl.err", error: e.toString()}); }
        return;
      }
      return orig.call(this, view, handler, error);
    };
    send({ev:"webview.ssl.hook","ok":true});
  }
});
