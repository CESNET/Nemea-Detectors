<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Application\UI
 */



/**
 * Component with ability to receive signal.
 *
 * @author     David Grudl
 * @package Nette\Application\UI
 */
interface ISignalReceiver
{

	/**
	 * @param  string
	 * @return void
	 */
	function signalReceived($signal); // handleSignal

}
