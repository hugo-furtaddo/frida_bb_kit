// scripts/js/webview_watch.js
'use strict';
Java.perform(function () {
  try {
    var WebView = Java.use('android.webkit.WebView');
    var origLoadUrl = WebView.loadUrl.overload('java.lang.String');
    origLoadUrl.implementation = function (u) {
      send({ev:'webview.loadUrl', url: u+""});
      return origLoadUrl.call(this, u);
    };
  } catch (e) {}
  try {
    var WV = Java.use('android.webkit.WebView');
    var origJSI = WV.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String');
    origJSI.implementation = function (obj, name) {
      send({ev:'webview.jsbridge', name: name+""});
      return origJSI.call(this, obj, name);
    };
  } catch (e) {}
});
