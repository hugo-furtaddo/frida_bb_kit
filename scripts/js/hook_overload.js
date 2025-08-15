Java.perform(function () {
  var Cls = Java.use('java.lang.Class');
  var forName1 = Cls.forName.overload('java.lang.String');
  var forName2 = Cls.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader');

  forName1.implementation = function (name) {
    var out = forName1.call(Cls, name);
    send({ev: 'forName(String)', name: name});
    return out;
  };

  forName2.implementation = function (name, init, loader) {
    var out = forName2.call(Cls, name, init, loader);
    send({ev: 'forName(String,boolean,ClassLoader)', name: name, init: init, loader: loader ? loader.toString() : 'null'});
    return out;
  };
});
