<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette
 */



/**
 * The exception that is thrown when the value of an argument is
 * outside the allowable range of values as defined by the invoked method.
 * @package Nette
 */
class ArgumentOutOfRangeException extends InvalidArgumentException
{
}



/**
 * The exception that is thrown when a method call is invalid for the object's
 * current state, method has been invoked at an illegal or inappropriate time.
 * @package Nette
 */
class InvalidStateException extends RuntimeException
{
	public function __construct($message = '', $code = 0, Exception $previous = NULL)
	{
		if (PHP_VERSION_ID < 50300) {
			$this->previous = $previous;
			parent::__construct($message, $code);
		} else {
			parent::__construct($message, $code, $previous);
		}
	}
}



/**
 * The exception that is thrown when a requested method or operation is not implemented.
 * @package Nette
 */
class NotImplementedException extends LogicException
{
}



/**
 * The exception that is thrown when an invoked method is not supported. For scenarios where
 * it is sometimes possible to perform the requested operation, see InvalidStateException.
 * @package Nette
 */
class NotSupportedException extends LogicException
{
}



/**
 * The exception that is thrown when a requested method or operation is deprecated.
 * @package Nette
 */
class DeprecatedException extends NotSupportedException
{
}



/**
 * The exception that is thrown when accessing a class member (property or method) fails.
 * @package Nette
 */
class MemberAccessException extends LogicException
{
}



/**
 * The exception that is thrown when an I/O error occurs.
 * @package Nette
 */
class IOException extends RuntimeException
{
}



/**
 * The exception that is thrown when accessing a file that does not exist on disk.
 * @package Nette
 */
class FileNotFoundException extends IOException
{
}



/**
 * The exception that is thrown when part of a file or directory cannot be found.
 * @package Nette
 */
class DirectoryNotFoundException extends IOException
{
}


/**
 * The exception that is thrown when static class is instantiated.
 * @package Nette
 */
class StaticClassException extends LogicException
{
}



/**
 * The exception that indicates errors that can not be recovered from. Execution of
 * the script should be halted.
 * @package Nette
 */
class FatalErrorException extends Exception // ErrorException is corrupted in PHP < 5.3
{
	private $severity;

	public function __construct($message, $code, $severity, $file, $line, $context, Exception $previous = NULL)
	{
		if (PHP_VERSION_ID < 50300) {
			$this->previous = $previous;
			parent::__construct($message, $code);
		} else {
			parent::__construct($message, $code, $previous);
		}
		$this->severity = $severity;
		$this->file = $file;
		$this->line = $line;
		$this->context = $context;
	}

	public function getSeverity()
	{
		return $this->severity;
	}

}
