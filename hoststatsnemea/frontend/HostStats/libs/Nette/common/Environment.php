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
 * Nette environment and configuration.
 *
 * @author     David Grudl
 * @deprecated
 * @package Nette
 */
final class Environment
{
	/** environment name */
	const DEVELOPMENT = 'development',
		PRODUCTION = 'production',
		CONSOLE = 'console';

	/** @var bool */
	private static $productionMode;

	/** @var string */
	private static $createdAt;

	/** @var DIContainer */
	private static $context;



	/**
	 * Static class - cannot be instantiated.
	 */
	final public function __construct()
	{
		throw new StaticClassException;
	}



	/********************* environment modes ****************d*g**/



	/**
	 * Detects console (non-HTTP) mode.
	 * @return bool
	 */
	public static function isConsole()
	{
		return PHP_SAPI === 'cli';
	}



	/**
	 * Determines whether a server is running in production mode.
	 * @return bool
	 */
	public static function isProduction()
	{
		if (self::$productionMode === NULL) {
			self::$productionMode = !Configurator::detectDebugMode();
		}
		return self::$productionMode;
	}



	/**
	 * Enables or disables production mode.
	 * @param  bool
	 * @return void
	 */
	public static function setProductionMode($value = TRUE)
	{
		self::$productionMode = (bool) $value;
	}



	/********************* environment variables ****************d*g**/



	/**
	 * Sets the environment variable.
	 * @param  string
	 * @param  mixed
	 * @param  bool
	 * @return void
	 */
	public static function setVariable($name, $value, $expand = TRUE)
	{
		if ($expand && is_string($value)) {
			$value = self::getContext()->expand($value);
		}
		self::getContext()->parameters[$name] = $value;
	}



	/**
	 * Returns the value of an environment variable or $default if there is no element set.
	 * @param  string
	 * @param  mixed  default value to use if key not found
	 * @return mixed
	 * @throws InvalidStateException
	 */
	public static function getVariable($name, $default = NULL)
	{
		if (isset(self::getContext()->parameters[$name])) {
			return self::getContext()->parameters[$name];
		} elseif (func_num_args() > 1) {
			return $default;
		} else {
			throw new InvalidStateException("Unknown environment variable '$name'.");
		}
	}



	/**
	 * Returns the all environment variables.
	 * @return array
	 */
	public static function getVariables()
	{
		return self::getContext()->parameters;
	}



	/**
	 * Returns expanded variable.
	 * @param  string
	 * @return string
	 * @throws InvalidStateException
	 */
	public static function expand($s)
	{
		return self::getContext()->expand($s);
	}



	/********************* context ****************d*g**/



	/**
	 * Sets initial instance of context.
	 * @return void
	 */
	public static function setContext(DIContainer $context)
	{
		if (self::$createdAt) {
			throw new InvalidStateException('Configurator & SystemContainer has already been created automatically by Environment at ' . self::$createdAt);
		}
		self::$context = $context;
	}



	/**
	 * Get initial instance of context.
	 * @return SystemContainer|DIContainer
	 */
	public static function getContext()
	{
		if (self::$context === NULL) {
			self::loadConfig();
		}
		return self::$context;
	}



	/**
	 * Gets the service object of the specified type.
	 * @param  string service name
	 * @return object
	 */
	public static function getService($name)
	{
		return self::getContext()->getService($name);
	}



	/**
	 * Calling to undefined static method.
	 * @param  string  method name
	 * @param  array   arguments
	 * @return object  service
	 */
	public static function __callStatic($name, $args)
	{
		if (!$args && strncasecmp($name, 'get', 3) === 0) {
			return self::getContext()->getService(lcfirst(substr($name, 3)));
		} else {
			throw new MemberAccessException("Call to undefined static method Environment::$name().");
		}
	}



	/**
	 * @return HttpRequest
	 */
	public static function getHttpRequest()
	{
		return self::getContext()->getByType('IHttpRequest');
	}



	/**
	 * @return HttpContext
	 */
	public static function getHttpContext()
	{
		return self::getContext()->getByType('HttpContext');
	}



	/**
	 * @return HttpResponse
	 */
	public static function getHttpResponse()
	{
		return self::getContext()->getByType('IHttpResponse');
	}



	/**
	 * @return Application
	 */
	public static function getApplication()
	{
		return self::getContext()->getByType('Application');
	}



	/**
	 * @return User
	 */
	public static function getUser()
	{
		return self::getContext()->getByType('User');
	}



	/**
	 * @return RobotLoader
	 */
	public static function getRobotLoader()
	{
		return self::getContext()->getByType('RobotLoader');
	}



	/********************* service factories ****************d*g**/



	/**
	 * @param  string
	 * @return Cache
	 */
	public static function getCache($namespace = '')
	{
		return new Cache(self::getContext()->cacheStorage, $namespace);
	}



	/**
	 * Returns instance of session or session namespace.
	 * @param  string
	 * @return Session
	 */
	public static function getSession($namespace = NULL)
	{
		return $namespace === NULL
			? self::getContext()->session
			: self::getContext()->session->getSection($namespace);
	}



	/********************* global configuration ****************d*g**/



	/**
	 * Loads global configuration from file and process it.
	 * @param  string
	 * @param  string
	 * @return ArrayHash
	 */
	public static function loadConfig($file = NULL, $section = NULL)
	{
		if (self::$createdAt) {
			throw new InvalidStateException('Configurator has already been created automatically by Environment at ' . self::$createdAt);
		}
		$configurator = new Configurator;
		$configurator
			->setDebugMode(!self::isProduction())
			->setTempDirectory(defined('TEMP_DIR') ? TEMP_DIR : '');
		if ($file) {
			$configurator->addConfig($file, $section);
		}
		self::$context = $configurator->createContainer();

		self::$createdAt = '?';
		foreach (PHP_VERSION_ID < 50205 ? debug_backtrace() :debug_backtrace(FALSE) as $row) {
			if (isset($row['file']) && is_file($row['file']) && strpos($row['file'], NETTE_DIR . DIRECTORY_SEPARATOR) !== 0) {
				self::$createdAt = "$row[file]:$row[line]";
				break;
			}
		}
		return self::getConfig();
	}



	/**
	 * Returns the global configuration.
	 * @param  string key
	 * @param  mixed  default value
	 * @return mixed
	 */
	public static function getConfig($key = NULL, $default = NULL)
	{
		$params = ArrayHash::from(self::getContext()->parameters);
		if (func_num_args()) {
			return isset($params[$key]) ? $params[$key] : $default;
		} else {
			return $params;
		}
	}

}
