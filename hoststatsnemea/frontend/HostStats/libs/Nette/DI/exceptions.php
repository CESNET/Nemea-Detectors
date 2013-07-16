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
 * Service not found exception.
 * @package Nette\DI
 */
class MissingServiceException extends InvalidStateException
{
}



/**
 * Service creation exception.
 * @package Nette\DI
 */
class ServiceCreationException extends InvalidStateException
{
}
