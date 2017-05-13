
Java.perform(function () {
	send("Starting hooks OWASP uncrackable1...");

	var sysexit = Java.use("java.lang.System");
	sysexit.exit.overload("int").implementation = function(var_0) {
		send("java.lang.System.exit(I)V  // We avoid exiting the application  :)");
	};

	var aes_decrypt = Java.use("sg.vantagepoint.a.a");
	aes_decrypt.a.overload("[B","[B").implementation = function(var_0,var_1) {
		send("sg.vantagepoint.a.a.a([B[B)[B   doFinal(enc)  // AES/ECB/PKCS7Padding");
		send("Key       : " + var_0);
		send("Encrypted : " + var_1);
		var ret = this.a.overload("[B","[B").call(this,var_0,var_1);
		send("Decrypted : " + ret);

		flag = "";
		for (var i=0; i < ret.length; i++){
			flag += String.fromCharCode(ret[i]);
		}
		send("Decrypted flag: " + flag);
		return ret; //[B
	};


/*	var mainactivity = Java.use("sg.vantagepoint.uncrackable1.MainActivity");
	mainactivity.onStart.overload().implementation = function() {
		send("MainActivity.onStart() HIT!!!");
		var ret = this.onStart.overload().call(this);
	};
	//var mainactivity = Java.use("sg.vantagepoint.uncrackable1.MainActivity");
	mainactivity.onCreate.overload("android.os.Bundle").implementation = function(var_0) {
		send("MainActivity.onCreate() HIT!!!");
		var ret = this.onCreate.overload("android.os.Bundle").call(this,var_0);
	};


	var activity = Java.use("android.app.Activity");
	activity.onCreate.overload("android.os.Bundle").implementation = function(var_0) {
		send("Activity HIT!!!");
		var ret = this.onCreate.overload("android.os.Bundle").call(this,var_0);
	};
*/

/*	var rootcheck1 = Java.use("sg.vantagepoint.a.c");
	rootcheck1.a.overload().implementation = function() {
		send("sg.vantagepoint.a.c.a()Z   Root check 1 HIT! su.exists()");
		return 0;
	};

	var rootcheck2 = Java.use("sg.vantagepoint.a.c");
	rootcheck2.b.overload().implementation = function() {
		send("sg.vantagepoint.a.c.b()Z  Root check 2 HIT!  test-keys");
		return 0;
	};

	var rootcheck3 = Java.use("sg.vantagepoint.a.c");
	rootcheck3.c.overload().implementation = function() {
		send("sg.vantagepoint.a.c.c()Z  Root check 3 HIT! Root packages");
		return 0;
	};

	var debugcheck = Java.use("sg.vantagepoint.a.b");
	debugcheck.a.overload("android.content.Context").implementation = function(var_0) {
		send("sg.vantagepoint.a.b.a(Landroid/content/Context;)Z  Debug check HIT! ");
		return 0;
	};
*/

	send("Hooks installed.");
});
