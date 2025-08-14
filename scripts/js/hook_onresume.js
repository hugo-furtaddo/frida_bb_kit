// scripts/js/hook_onresume.js
Java.perform(function () {
  console.log("[*] Java.available =", Java.available);
  var Activity = Java.use("android.app.Activity");
  Activity.onResume.implementation = function () {
    var cls = this.getClass().getName();
    var ret = this.onResume();
    send({ev: "onResume", cls: cls});
    return ret;
  };
});
