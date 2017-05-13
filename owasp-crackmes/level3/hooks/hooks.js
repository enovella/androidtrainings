function stringToHex (s) {
    var _hex = '';
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i);
        _hex += ( ((c < 16) ? "0" : "") + c.toString(16));
    }
    return _hex.toLowerCase();
};


send("Placing native hooks....");

var offset_anti_debug_x64   = 0x000075f0;
var offset_anti_debug_x32   = 0x00005e90;
var offset_protect_secret64 = 0x0000779c;
var offset_strncmp_xor64    = 0x000077ec;

var arch = Process.arch;
send("arch: " + arch);

//var modules = Process.enumerateModulesSync();
//send(modules);

/***************************************************
*
*                  NATIVE HOOKS
*
***************************************************/

// char *strstr(const char *haystack, const char *needle);
/*Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {

    onEnter: function (args) {

        this.haystack = args[0];
        this.needle   = args[1];
        this.frida    = Boolean(0);

        haystack = Memory.readUtf8String(this.haystack);
        needle   = Memory.readUtf8String(this.needle);

        //send("onEnter() strstr(\"" + haystack + "\",\"" + needle + "\");");
        if ( haystack.indexOf("frida") != -1 || haystack.indexOf("xposed") != -1 ) {
        	//send("onEnter() strstr(\"" + haystack + "\",\"" + needle + "\");");
			//send("onEnter() Frida/Xposed hooked!");
			this.frida = Boolean(1);
        }
    },

    onLeave: function (retval) {

        if (this.frida) {
        	var fakeRet = ptr(0);
        	//send("onLeave() Frida real retval = " + retval );
        	//send("onLeave() Frida fake retval = " + fakeRet );
        	//send("strstr(frida) was patched!! :) " + haystack);
        	retval.replace(0);
        }

        //send("onLeave() strstr ret: " + retval);
        return retval;
    }
});
*/

function do_native_hooks_libfoo(){

	var p_foo = Module.findBaseAddress('libfoo.so');
	if (!p_foo) {
		send("p_foo is null (libfoo.so). Returning now...");
		return 0;
	}
    var p_protect_secret = p_foo.add(offset_protect_secret64);
	var p_strncmp_xor64  = p_foo.add(offset_strncmp_xor64);
	send("libfoo.so          @ " + p_foo.toString());
	send("ptr_protect_secret @ " + p_protect_secret.toString());
	send("ptr_strncmp_xor64  @ " + p_strncmp_xor64.toString());


	Interceptor.attach( p_protect_secret, {
	    onEnter: function (args) {
	        send("onEnter() p_protect_secret");
	        send("args[0]: " + args[0]);
	    },

	    onLeave: function (retval) {
	        send("onLeave() p_protect_secret");
	     }
	});

	Interceptor.attach( p_strncmp_xor64, {
	    onEnter: function (args) {
	        send("onEnter() p_strncmp_xor64");
	        send("args[0]: " + args[0]);
	        send(hexdump(args[0], {
	            offset: 0,
	            length: 24,
	            header: false,
	            ansi: true
        	}));

	        send("args[1]: " + args[1]);
	        var secret = hexdump(args[1], {
	            offset: 0,
	            length: 24,
	            header: false,
	            ansi: true
        	})
        	send(secret);
	    },

	    onLeave: function (retval) {
	        send("onLeave() p_strncmp_xor64");
            send(retval);
	     }
	});
}


// int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
var p_pthread_create = Module.findExportByName("libc.so", "pthread_create");
var pthread_create = new NativeFunction( p_pthread_create, 'int', ['pointer','pointer','pointer','pointer']);
send("NativeFunction pthread_create() replaced @ " + pthread_create);

Interceptor.replace( p_pthread_create, new NativeCallback(function (ptr0, ptr1, ptr2, ptr3) {
    send("pthread_create() overloaded");
    var ret = ptr(0);
    if (ptr1.isNull() && ptr3.isNull()) {
    	send("loading fake pthread_create because ptr1 and ptr3 are equal to 0!");
    } else {
    	send("loading real pthread_create()");
    	ret = pthread_create(ptr0,ptr1,ptr2,ptr3);
    }

    do_native_hooks_libfoo();

    send("ret: " + ret);

}, 'int', ['pointer','pointer','pointer','pointer']));



// int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
/*var p_pthread_create = Module.findExportByName("libc.so","pthread_create");
Interceptor.attach(ptr(p_pthread_create), {
    onEnter: function (args) {
        this.thread        = args[0];
        this.attr          = args[1];
        this.start_routine = args[2];
        this.arg           = args[3];
        this.fakeRet       = Boolean(0);
        send("onEnter() pthread_create(" + this.thread.toString() + ", " + this.attr.toString() + ", "
        	+ this.start_routine.toString() + ", " + this.arg.toString() + ");");

        if (parseInt(this.attr) == 0 && parseInt(this.arg) == 0)
        	this.fakeRet = Boolean(1);

    },
    onLeave: function (retval) {
    	send(retval);
        send("onLeave() pthread_create");
        if (this.fakeRet == 1) {
        	var fakeRet = ptr(0);
        	send("pthread_create real ret: " + retval);
            send("pthread_create fake ret: " + fakeRet);
            return fakeRet;
        }
        return retval;
    }
});*/






//= Module.findExportByName("libfoo.so", "Java_sg_vantagepoint_uncrackable3_MainActivity_init");
//var ptr_main_init1 = ptr(Process.enumerateModulesSync().filter(x=> x.name.indexOf("libfoo")>=0)[0].base).add(0x5f78);
/*var ptr_main_init = Module.findBaseAddress("libfoo.so").add(0x5f78);  //"Java_sg_vantagepoint_uncrackable3_MainActivity_init"
send(ptr_main_init.toString());

Interceptor.attach(ptr(ptr_main_init), {
    onEnter: function (args) {
        this.env    = args[0];
        this.this   = args[1];
        this.xorkey = args[2];

        xorkey = Memory.readUtf8String(this.xorkey);
        send("onEnter() Java_sg_vantagepoint_uncrackable3_MainActivity_init();");
        send(xorkey);
    },
    onLeave: function (retval) {
        return retval;
    }
});*/

send("Done with native hooks....");



/***************************************************
*
*                  JAVA HOOKS
*
***************************************************/
Java.perform(function () {
	send("Placing Java hooks...");

	var sys = Java.use("java.lang.System");
	sys.exit.overload("int").implementation = function(var_0) {
		send("java.lang.System.exit(I)V  // We avoid exiting the application  :)");
	};

	/**
		if ((RootDetection.checkRoot1()) || (RootDetection.checkRoot2()) || (RootDetection.checkRoot3()) ||
				(IntegrityCheck.isDebuggable(getApplicationContext())) || (tampered != 0))
		      	showDialog("Rooting or tampering detected.")
	*/
	var rootchecks = Java.use("sg.vantagepoint.util.RootDetection");
	rootchecks.checkRoot1.overload().implementation = function() {
		send("sg.vantagepoint.util.RootDetection.checkRoot1()Z  Root check 1 HIT!  su.exists()");
		return Boolean(0);
	};
	rootchecks.checkRoot2.overload().implementation = function() {
		send("sg.vantagepoint.util.RootDetection.checkRoot2()Z  Root check 2 HIT!  test-keys");
		return Boolean(0);
	};
	rootchecks.checkRoot3.overload().implementation = function() {
		send("sg.vantagepoint.util.RootDetection.checkRoot3()Z  Root check 3 HIT!  Root packages");
		return Boolean(0);
	};

	var debugcheck = Java.use("sg.vantagepoint.util.IntegrityCheck");
	debugcheck.isDebuggable.overload("android.content.Context").implementation = function(var_0) {
		send("sg.vantagepoint.util.IntegrityCheck.isDebuggable(Landroid/content/Context;)Z  Debug check HIT! ");
		return Boolean(0);
	};


	// MainActivity
	var mainactivity = Java.use("sg.vantagepoint.uncrackable3.MainActivity");
	mainactivity.onStart.overload().implementation = function() {
		send("MainActivity.onStart() HIT!!!");
		var ret = this.onStart.overload().call(this);
	};
	mainactivity.onCreate.overload("android.os.Bundle").implementation = function(var_0) {
		send("MainActivity.onCreate() HIT!!!");
		var ret = this.onCreate.overload("android.os.Bundle").call(this,var_0);
	};
	mainactivity.verifyLibs.overload().implementation = function() {
		send("sg.vantagepoint.uncrackable3.MainActivity.verifyLibs()V");
		var ret = this.verifyLibs.overload().call(this);
	};
	mainactivity.baz.overload().implementation = function() {
		send("sg.vantagepoint.uncrackable3.MainActivity.baz()J");
		var ret = this.baz.overload().call(this);
		send(ret);
		return ret;
	};
	mainactivity.init.overload("[B").implementation = function(var_0) {
		send("sg.vantagepoint.uncrackable3.MainActivity.init([B)V");
		send(var_0);
		var ret = this.init.overload("[B").call(this, var_0);
	};


	// Call to native hooks to get the flag
	do_native_hooks_libfoo();

	send("Done Java hooks installed.");
});
