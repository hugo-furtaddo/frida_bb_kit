rpc.exports = {
  ping: function () { return "pong"; },
  toggle: function (flag) {
    enabled = !!flag;
    return enabled;
  }
};

var enabled = true;

Java.perform(function () {
  var Log = Java.use('android.util.Log');
  var Log_d = Log.d.overload('java.lang.String', 'java.lang.String');
  Log_d.implementation = function (tag, msg) {
    var out = Log_d.call(Log, tag, msg);
    if (enabled) send({ev: 'Log.d', tag: tag.toString(), msg: msg.toString()});
    return out;
  };
});
