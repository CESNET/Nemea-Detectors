<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Database
 */



/**
 * SQL literal value.
 *
 * @author     Jakub Vrana
 * @package Nette\Database
 */
class SqlLiteral extends Object
{
	/** @var string */
	private $value = '';


	public function __construct($value)
	{
		$this->value = (string) $value;
	}



	/**
	 * @return string
	 */
	public function __toString()
	{
		return $this->value;
	}

}
