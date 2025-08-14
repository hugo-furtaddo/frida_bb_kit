// scripts/js/rpc_template.js
// Exemplo de RPC + mensagens
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
  Log.d.overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
    var out = this.d(tag, msg);
    if (enabled) send({ev: 'Log.d', tag: tag.toString(), msg: msg.toString()});
    return out;
  };
});
