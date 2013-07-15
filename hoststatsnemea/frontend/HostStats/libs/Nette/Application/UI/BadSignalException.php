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
 * Signal exception.
 *
 * @author     David Grudl
 * @package Nette\Application\UI
 */
class BadSignalException extends BadRequestException
{
	/** @var int */
	protected $defaultCode = 403;

}
