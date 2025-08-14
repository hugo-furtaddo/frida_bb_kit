// scripts/js/hook_overload.js
Java.perform(function () {
  var Cls = Java.use('java.lang.Class');

  Cls.forName.overload('java.lang.String').implementation = function (name) {
    var out = this.forName(name);
    send({ev: 'forName(String)', name: name});
    return out;
  };

  Cls.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader')
    .implementation = function (name, init, loader) {
      var out = this.forName(name, init, loader);
      send({ev: 'forName(String,boolean,ClassLoader)', name: name, init: init,
            loader: loader ? loader.toString() : 'null' });
      return out;
    };
});
