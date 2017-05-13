
Java.perform(function () {
	send("Starting hooks OWASP uncrackable2...");

	var codecheck = Java.use("sg.vantagepoint.uncrackable2.CodeCheck");
	codecheck.bar.overload("[B").implementation = function(var_0) {
		send("sg.vantagepoint.uncrackable2.CodeCheck.bar([B)Z");
		s = "";
		for (var i=0; i< var_0.length; i++){
			s += String.fromCharCode(var_0[i]);
		}
		send(s);
		var ret = this.bar.overload("[B").call(this,var_0);
		send(ret);
		return ret; //Z
	};

	var sysexit = Java.use("java.lang.System");
	sysexit.exit.overload("int").implementation = function(var_0) {
		send("java.lang.System.exit(I)V  // We avoid exiting the application  :)");
	};

/*	var rootcheck1 = Java.use("sg.vantagepoint.a.c");
	rootcheck1.a.overload().implementation = function() {
		send("sg.vantagepoint.a.c.a()Z   Root check 1 HIT!  su.exists()");
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
