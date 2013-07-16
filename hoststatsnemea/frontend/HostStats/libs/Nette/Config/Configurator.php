<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Config
 */



/**
 * Initial system DI container generator.
 *
 * @author     David Grudl
 *
 * @property   bool $debugMode
 * @property-write $tempDirectory
 * @package Nette\Config
 */
class Configurator extends Object
{
	/** config file sections */
	const AUTO = NULL,
		NONE = FALSE;

	/** @deprecated */
	const DEVELOPMENT = 'development',
		PRODUCTION = 'production';

	/** @var array of function(Configurator $sender, Compiler $compiler); Occurs after the compiler is created */
	public $onCompile;

	/** @var array */
	protected $parameters;

	/** @var array */
	protected $files = array();



	public function __construct()
	{
		$this->parameters = $this->getDefaultParameters();
	}



	/**
	 * Set parameter %debugMode%.
	 * @param  bool|string|array
	 * @return Configurator  provides a fluent interface
	 */
	public function setDebugMode($value = TRUE)
	{
		$this->parameters['debugMode'] = is_bool($value) ? $value : self::detectDebugMode($value);
		$this->parameters['productionMode'] = !$this->parameters['debugMode']; // compatibility
		return $this;
	}



	/**
	 * @return bool
	 */
	public function isDebugMode()
	{
		return !$this->parameters['productionMode'];
	}



	/**
	 * Sets path to temporary directory.
	 * @return Configurator  provides a fluent interface
	 */
	public function setTempDirectory($path)
	{
		$this->parameters['tempDir'] = $path;
		if (($cacheDir = $this->getCacheDirectory()) && !is_dir($cacheDir)) {
			mkdir($cacheDir, 0777);
		}
		return $this;
	}



	/**
	 * Adds new parameters. The %params% will be expanded.
	 * @return Configurator  provides a fluent interface
	 */
	public function addParameters(array $params)
	{
		$this->parameters = ConfigHelpers::merge($params, $this->parameters);
		return $this;
	}



	/**
	 * @return array
	 */
	protected function getDefaultParameters()
	{
		$trace = PHP_VERSION_ID < 50205 ? debug_backtrace() :debug_backtrace(FALSE);
		$debugMode = self::detectDebugMode();
		return array(
			'appDir' => isset($trace[1]['file']) ? dirname($trace[1]['file']) : NULL,
			'wwwDir' => isset($_SERVER['SCRIPT_FILENAME']) ? dirname($_SERVER['SCRIPT_FILENAME']) : NULL,
			'debugMode' => $debugMode,
			'productionMode' => !$debugMode,
			'environment' => $debugMode ? 'development' : 'production',
			'consoleMode' => PHP_SAPI === 'cli',
			'container' => array(
				'class' => 'SystemContainer',
				'parent' => 'DIContainer',
			)
		);
	}



	/**
	 * @param  string        error log directory
	 * @param  string        administrator email
	 * @return void
	 */
	public function enableDebugger($logDirectory = NULL, $email = NULL)
	{
		Debugger::$strictMode = TRUE;
		Debugger::enable($this->parameters['productionMode'], $logDirectory, $email);
	}



	/**
	 * @return RobotLoader
	 */
	public function createRobotLoader()
	{
		if (!($cacheDir = $this->getCacheDirectory())) {
			throw new InvalidStateException("Set path to temporary directory using setTempDirectory().");
		}
		$loader = new RobotLoader;
		$loader->setCacheStorage(new FileStorage($cacheDir));
		$loader->autoRebuild = !$this->parameters['productionMode'];
		return $loader;
	}



	/**
	 * Adds configuration file.
	 * @return Configurator  provides a fluent interface
	 */
	public function addConfig($file, $section = NULL)
	{
		$this->files[] = array($file, $section === NULL ? $this->parameters['environment'] : $section);
		return $this;
	}



	/** @deprecated */
	public function loadConfig($file, $section = NULL)
	{
		trigger_error(__METHOD__ . '() is deprecated; use addConfig(file, [section])->createContainer() instead.', E_USER_WARNING);
		return $this->addConfig($file, $section)->createContainer();
	}



	/**
	 * Returns system DI container.
	 * @return SystemContainer
	 */
	public function createContainer()
	{
		if ($cacheDir = $this->getCacheDirectory()) {
			$cache = new Cache(new PhpFileStorage($cacheDir), 'Nette.Configurator');
			$cacheKey = array($this->parameters, $this->files);
			$cached = $cache->load($cacheKey);
			if (!$cached) {
				$code = $this->buildContainer($dependencies);
				$cache->save($cacheKey, $code, array(
					Cache::FILES => $dependencies,
				));
				$cached = $cache->load($cacheKey);
			}
			LimitedScope::load($cached['file'], TRUE);

		} elseif ($this->files) {
			throw new InvalidStateException("Set path to temporary directory using setTempDirectory().");

		} else {
			LimitedScope::evaluate($this->buildContainer()); // back compatibility with Environment
		}

		$container = new $this->parameters['container']['class'];
		$container->initialize();
		Environment::setContext($container); // back compatibility
		return $container;
	}



	/**
	 * Build system container class.
	 * @return string
	 */
	protected function buildContainer(& $dependencies = NULL)
	{
		$loader = $this->createLoader();
		$config = array();
		$code = "<?php\n";
		foreach ($this->files as $tmp) {
			list($file, $section) = $tmp;
			$config = ConfigHelpers::merge($loader->load($file, $section), $config);
			$code .= "// source: $file $section\n";
		}
		$code .= "\n";

		$this->checkCompatibility($config);

		if (!isset($config['parameters'])) {
			$config['parameters'] = array();
		}
		$config['parameters'] = ConfigHelpers::merge($config['parameters'], $this->parameters);

		$compiler = $this->createCompiler();
		$this->onCompile($this, $compiler);

		$code .= $compiler->compile(
			$config,
			$this->parameters['container']['class'],
			$config['parameters']['container']['parent']
		);
		$dependencies = array_merge($loader->getDependencies(), $this->isDebugMode() ? $compiler->getContainerBuilder()->getDependencies() : array());
		return $code;
	}



	protected function checkCompatibility(array $config)
	{
		foreach (array('service' => 'services', 'variable' => 'parameters', 'variables' => 'parameters', 'mode' => 'parameters', 'const' => 'constants') as $old => $new) {
			if (isset($config[$old])) {
				throw new DeprecatedException("Section '$old' in configuration file is deprecated; use '$new' instead.");
			}
		}
		if (isset($config['services'])) {
			foreach ($config['services'] as $key => $def) {
				foreach (array('option' => 'arguments', 'methods' => 'setup') as $old => $new) {
					if (is_array($def) && isset($def[$old])) {
						throw new DeprecatedException("Section '$old' in service definition is deprecated; refactor it into '$new'.");
					}
				}
			}
		}
	}



	/**
	 * @return ConfigCompiler
	 */
	protected function createCompiler()
	{
		$compiler = new ConfigCompiler;
		$compiler->addExtension('php', new PhpExtension)
			->addExtension('constants', new ConstantsExtension)
			->addExtension('nette', new NetteExtension);
		return $compiler;
	}



	/**
	 * @return ConfigLoader
	 */
	protected function createLoader()
	{
		return new ConfigLoader;
	}



	protected function getCacheDirectory()
	{
		return empty($this->parameters['tempDir']) ? NULL : $this->parameters['tempDir'] . '/cache';
	}



	/********************* tools ****************d*g**/



	/**
	 * Detects debug mode by IP address.
	 * @param  string|array  IP addresses or computer names whitelist detection
	 * @return bool
	 */
	public static function detectDebugMode($list = NULL)
	{
		$list = is_string($list) ? preg_split('#[,\s]+#', $list) : (array) $list;
		if (!isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			$list[] = '127.0.0.1';
			$list[] = '::1';
		}
		return in_array(isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : php_uname('n'), $list, TRUE);
	}



	/** @deprecated */
	public function setProductionMode($value = TRUE)
	{
		return $this->setDebugMode(is_bool($value) ? !$value : $value);
	}



	/** @deprecated */
	public function isProductionMode()
	{
		return !$this->isDebugMode();
	}



	/** @deprecated */
	public static function detectProductionMode($list = NULL)
	{
		return !self::detectDebugMode($list);
	}

}
