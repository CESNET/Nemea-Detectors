<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\DI
 */



/**
 * Assignment or calling statement.
 *
 * @author     David Grudl
 * @package Nette\DI
 */
class DIStatement extends Object
{
	/** @var string  class|method|$property */
	public $entity;

	/** @var array */
	public $arguments;



	public function __construct($entity, array $arguments = array())
	{
		$this->entity = $entity;
		$this->arguments = $arguments;
	}

}
