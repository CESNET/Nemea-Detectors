<?php

// This is default autoload.php. It can be overwritten by Composer.

if (!is_file(dirname(__FILE__) . '/Nette/loader.php')) {
	die("Nette Framework is expected in directory '" . dirname(__FILE__) . "/Nette' but not found. Check if the path is correct or edit file '" . __FILE__ . "'.");
}

require dirname(__FILE__) . '/Nette/loader.php';
