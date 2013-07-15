<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Security
 */



/**
 * Represents the user of application.
 *
 * @author     David Grudl
 * @package Nette\Security
 */
interface IIdentity
{

	/**
	 * Returns the ID of user.
	 * @return mixed
	 */
	function getId();

	/**
	 * Returns a list of roles that the user is a member of.
	 * @return array
	 */
	function getRoles();

}
