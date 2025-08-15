Java.perform(function () {
  console.log("[*] Java.available =", Java.available);
  var Activity = Java.use("android.app.Activity");
  var onResume = Activity.onResume;
  onResume.implementation = function () {
    var cls = this.getClass().getName();
    var ret = onResume.call(this);
    send({ev: "onResume", cls: cls});
    return ret;
  };
});
