<?php
$key = $argv[1];
echo "grep -i \"$key\" dictionary.txt";
passthru("grep -i \"$key\" dictionary.txt");

