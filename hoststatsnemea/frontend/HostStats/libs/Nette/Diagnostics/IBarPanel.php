<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Diagnostics
 */



/**
 * Custom output for Debugger.
 *
 * @author     David Grudl
 * @package Nette\Diagnostics
 */
interface IBarPanel
{

	/**
	 * Renders HTML code for custom tab.
	 * @return string
	 */
	function getTab();

	/**
	 * Renders HTML code for custom panel.
	 * @return string
	 */
	function getPanel();

}
