// scripts/js/classloader_watch.js
'use strict';
Java.perform(function () {
  try {
    var PCL = Java.use('java.lang.ClassLoader');
    var origLoad = PCL.loadClass.overload('java.lang.String');
    origLoad.implementation = function (name) {
      var cls = origLoad.call(this, name);
      send({ev:'classloader.loadClass', loader: this.toString()+"", name: name+""});
      return cls;
    };
  } catch (e) {}
  try {
    var DCL = Java.use('dalvik.system.DexClassLoader');
    var origInit = DCL.$init.overload('java.lang.String','java.lang.String','java.lang.String','java.lang.ClassLoader');
    origInit.implementation = function (dexPath, odex, libPath, parent) {
      send({ev:'dex.new', dexPath: dexPath+""});
      return origInit.call(this, dexPath, odex, libPath, parent);
    };
  } catch (e) {}
});
