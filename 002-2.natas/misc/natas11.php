<?php
	// ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw%3D ==> array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

	function xor_encrypt($in) {
	    $key = 'qw8J';//qw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jq';
	    $text = $in;
	    $outText = '';

	    // Iterate through each character
	    for($i=0;$i<strlen($text);$i++) {
	    	$outText .= $text[$i] ^ $key[$i % strlen($key)];
	    }

	    return $outText;
	}

	function xor_reverse($text, $outText) {
	    $key = '';
	    $text = $text;
	    $outText = $outText;

	    // Iterate through each character
	    for($i=0;$i<strlen($text);$i++) {
	    	$key .= $text[$i] ^ $outText[$i % strlen($outText)];
	    	// $outText .= $text[$i] ^ $key[$i % strlen($key)];
	    }

	    return $key;
	}

	function decrypt_data($data) {
		return xor_encrypt(base64_decode($data));
	}

	function loadData($def) {
	    global $_COOKIE;
	    $mydata = $def;
	    if(array_key_exists("data", $_COOKIE)) {
	    $tempdata = json_decode(decrypt_data($_COOKIE["data"]), true);
	    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
	        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
	        $mydata['showpassword'] = $tempdata['showpassword'];
	        $mydata['bgcolor'] = $tempdata['bgcolor'];
	        }
	    }
	    }
	    return $mydata;
	}

	function do_encrypt($data) {
		return base64_encode(xor_encrypt(json_encode($data)));
	}

	function saveData($d) {
	    setcookie("data", do_encrypt($d));
	}

	// echo json_encode(array( "showpassword"=>"no", "bgcolor"=>"#ffffff"));

	// echo xor_reverse(json_encode(array( "showpassword"=>"no", "bgcolor"=>"#ffffff")), base64_decode('ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw='));

	echo do_encrypt(array( "showpassword"=>"yes", "bgcolor"=>"#ffffff"));

	// echo decrypt_data('ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=')."\n===\n";
	// echo decrypt_data('ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFZaAw=');