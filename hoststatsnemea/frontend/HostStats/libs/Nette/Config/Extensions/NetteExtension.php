<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Config\Extensions
 */



/**
 * Core Nette Framework services.
 *
 * @author     David Grudl
 * @package Nette\Config\Extensions
 */
class NetteExtension extends ConfigCompilerExtension
{
	public $defaults = array(
		'xhtml' => TRUE,
		'session' => array(
			'iAmUsingBadHost' => NULL,
			'autoStart' => 'smart',  // true|false|smart
			'expiration' => NULL,
		),
		'application' => array(
			'debugger' => TRUE,
			'errorPresenter' => NULL,
			'catchExceptions' => '%productionMode%',
		),
		'routing' => array(
			'debugger' => TRUE,
			'routes' => array(), // of [mask => action]
		),
		'security' => array(
			'debugger' => TRUE,
			'frames' => 'SAMEORIGIN', // X-Frame-Options
			'users' => array(), // of [user => password]
			'roles' => array(), // of [role => parents]
			'resources' => array(), // of [resource => parents]
		),
		'mailer' => array(
			'smtp' => FALSE,
		),
		'database' => array(), // of [name => dsn, user, password, debugger, explain, autowired, reflection]
		'forms' => array(
			'messages' => array(),
		),
		'container' => array(
			'debugger' => FALSE,
		),
		'debugger' => array(
			'email' => NULL,
			'editor' => NULL,
			'browser' => NULL,
			'strictMode' => NULL,
			'bar' => array(), // of class name
			'blueScreen' => array(), // of callback
		),
	);

	public $databaseDefaults = array(
		'dsn' => NULL,
		'user' => NULL,
		'password' => NULL,
		'options' => NULL,
		'debugger' => TRUE,
		'explain' => TRUE,
		'reflection' => 'DiscoveredReflection',
	);



	public function loadConfiguration()
	{
		$container = $this->getContainerBuilder();
		$config = $this->getConfig($this->defaults);


		// cache
		$container->addDefinition($this->prefix('cacheJournal'))
			->setClass('FileJournal', array('%tempDir%'));

		$container->addDefinition('cacheStorage') // no namespace for back compatibility
			->setClass('FileStorage', array('%tempDir%/cache'));

		$container->addDefinition($this->prefix('templateCacheStorage'))
			->setClass('PhpFileStorage', array('%tempDir%/cache'))
			->setAutowired(FALSE);

		$container->addDefinition($this->prefix('cache'))
			->setClass('Cache', array(1 => '%namespace%'))
			->setParameters(array('namespace' => NULL));


		// http
		$container->addDefinition($this->prefix('httpRequestFactory'))
			->setClass('HttpRequestFactory')
			->addSetup('setEncoding', array('UTF-8'))
			->setInternal(TRUE);

		$container->addDefinition('httpRequest') // no namespace for back compatibility
			->setClass('HttpRequest')
			->setFactory('@\HttpRequestFactory::createHttpRequest');

		$container->addDefinition('httpResponse') // no namespace for back compatibility
			->setClass('HttpResponse');

		$container->addDefinition($this->prefix('httpContext'))
			->setClass('HttpContext');


		// session
		$session = $container->addDefinition('session') // no namespace for back compatibility
			->setClass('Session');

		if (isset($config['session']['expiration'])) {
			$session->addSetup('setExpiration', array($config['session']['expiration']));
		}
		if (isset($config['session']['iAmUsingBadHost'])) {
			$session->addSetup('Framework::$iAmUsingBadHost = ?;', array((bool) $config['session']['iAmUsingBadHost']));
		}
		unset($config['session']['expiration'], $config['session']['autoStart'], $config['session']['iAmUsingBadHost']);
		if (!empty($config['session'])) {
			$session->addSetup('setOptions', array($config['session']));
		}


		// security
		$container->addDefinition($this->prefix('userStorage'))
			->setClass('UserStorage');

		$user = $container->addDefinition('user') // no namespace for back compatibility
			->setClass('User');

		if (!$container->parameters['productionMode'] && $config['security']['debugger']) {
			$user->addSetup('Debugger::$bar->addPanel(?)', array(
				new DIStatement('UserPanel')
			));
		}

		if ($config['security']['users']) {
			$container->addDefinition($this->prefix('authenticator'))
				->setClass('SimpleAuthenticator', array($config['security']['users']));
		}

		if ($config['security']['roles'] || $config['security']['resources']) {
			$authorizator = $container->addDefinition($this->prefix('authorizator'))
				->setClass('Permission');
			foreach ($config['security']['roles'] as $role => $parents) {
				$authorizator->addSetup('addRole', array($role, $parents));
			}
			foreach ($config['security']['resources'] as $resource => $parents) {
				$authorizator->addSetup('addResource', array($resource, $parents));
			}
		}


		// application
		$application = $container->addDefinition('application') // no namespace for back compatibility
			->setClass('Application')
			->addSetup('$catchExceptions', $config['application']['catchExceptions'])
			->addSetup('$errorPresenter', $config['application']['errorPresenter']);

		if ($config['application']['debugger']) {
			$application->addSetup('RoutingDebugger::initializePanel');
		}

		$container->addDefinition($this->prefix('presenterFactory'))
			->setClass('PresenterFactory', array(
				isset($container->parameters['appDir']) ? $container->parameters['appDir'] : NULL
			));


		// routing
		$router = $container->addDefinition('router') // no namespace for back compatibility
			->setClass('RouteList');

		foreach ($config['routing']['routes'] as $mask => $action) {
			$router->addSetup('$service[] = new Route(?, ?);', array($mask, $action));
		}

		if (!$container->parameters['productionMode'] && $config['routing']['debugger']) {
			$application->addSetup('Debugger::$bar->addPanel(?)', array(
				new DIStatement('RoutingDebugger')
			));
		}


		// mailer
		if (empty($config['mailer']['smtp'])) {
			$container->addDefinition($this->prefix('mailer'))
				->setClass('SendmailMailer');
		} else {
			$container->addDefinition($this->prefix('mailer'))
				->setClass('SmtpMailer', array($config['mailer']));
		}

		$container->addDefinition($this->prefix('mail'))
			->setClass('Mail')
			->addSetup('setMailer')
			->setShared(FALSE);


		// forms
		$container->addDefinition($this->prefix('basicForm'))
			->setClass('Form')
			->setShared(FALSE);


		// templating
		$latte = $container->addDefinition($this->prefix('latte'))
			->setClass('LatteFilter')
			->setShared(FALSE);

		if (empty($config['xhtml'])) {
			$latte->addSetup('$service->getCompiler()->defaultContentType = ?', LatteCompiler::CONTENT_HTML);
		}

		$container->addDefinition($this->prefix('template'))
			->setClass('FileTemplate')
			->addSetup('registerFilter', array($latte))
			->addSetup('registerHelperLoader', array('TemplateHelpers::loader'))
			->setShared(FALSE);


		// database
		$container->addDefinition($this->prefix('database'))
				->setClass('DINestedAccessor', array('@container', $this->prefix('database')));

		if (isset($config['database']['dsn'])) {
			$config['database'] = array('default' => $config['database']);
		}

		$autowired = TRUE;
		foreach ((array) $config['database'] as $name => $info) {
			if (!is_array($info)) {
				continue;
			}
			$info += $this->databaseDefaults + array('autowired' => $autowired);
			$autowired = FALSE;

			foreach ((array) $info['options'] as $key => $value) {
				unset($info['options'][$key]);
				$info['options'][constant($key)] = $value;
			}

			$connection = $container->addDefinition($this->prefix("database.$name"))
				->setClass('Connection', array($info['dsn'], $info['user'], $info['password'], $info['options']))
				->setAutowired($info['autowired'])
				->addSetup('setCacheStorage')
				->addSetup('Debugger::$blueScreen->addPanel(?)', array(
					'DatabasePanel::renderException'
				));

			if ($info['reflection']) {
				$connection->addSetup('setDatabaseReflection', is_string($info['reflection'])
					? array(new DIStatement(preg_match('#^[a-z]+\z#', $info['reflection']) ? 'Nette\Database\Reflection\\' . ucfirst($info['reflection']) . 'Reflection' : $info['reflection']))
					: ConfigCompiler::filterArguments(array($info['reflection']))
				);
			}

			if (!$container->parameters['productionMode'] && $info['debugger']) {
				$panel = $container->addDefinition($this->prefix("database.{$name}ConnectionPanel"))
					->setClass('DatabasePanel')
					->setAutowired(FALSE)
					->addSetup('$explain', !empty($info['explain']))
					->addSetup('Debugger::$bar->addPanel(?)', array('@self'));

				$connection->addSetup('$service->onQuery[] = ?', array(array($panel, 'logQuery')));
			}
		}
	}



	public function afterCompile(PhpClassType $class)
	{
		$initialize = $class->methods['initialize'];
		$container = $this->getContainerBuilder();
		$config = $this->getConfig($this->defaults);

		// debugger
		foreach (array('email', 'editor', 'browser', 'strictMode', 'maxLen', 'maxDepth') as $key) {
			if (isset($config['debugger'][$key])) {
				$initialize->addBody('Debugger::$? = ?;', array($key, $config['debugger'][$key]));
			}
		}

		if (!$container->parameters['productionMode']) {
			if ($config['container']['debugger']) {
				$config['debugger']['bar'][] = 'ContainerPanel';
			}

			foreach ((array) $config['debugger']['bar'] as $item) {
				$initialize->addBody($container->formatPhp(
					'Debugger::$bar->addPanel(?);',
					ConfigCompiler::filterArguments(array(is_string($item) ? new DIStatement($item) : $item))
				));
			}

			foreach ((array) $config['debugger']['blueScreen'] as $item) {
				$initialize->addBody($container->formatPhp(
					'Debugger::$blueScreen->addPanel(?);',
					ConfigCompiler::filterArguments(array($item))
				));
			}
		}

		if (!empty($container->parameters['tempDir'])) {
			$initialize->addBody($this->checkTempDir($container->expand('%tempDir%/cache')));
		}

		foreach ((array) $config['forms']['messages'] as $name => $text) {
			$initialize->addBody('Rules::$defaultMessages[Form::?] = ?;', array($name, $text));
		}

		if ($config['session']['autoStart'] === 'smart') {
			$initialize->addBody('$this->session->exists() && $this->session->start();');
		} elseif ($config['session']['autoStart']) {
			$initialize->addBody('$this->session->start();');
		}

		if (empty($config['xhtml'])) {
			$initialize->addBody('Html::$xhtml = ?;', array((bool) $config['xhtml']));
		}

		if (isset($config['security']['frames']) && $config['security']['frames'] !== TRUE) {
			$frames = $config['security']['frames'];
			if ($frames === FALSE) {
				$frames = 'DENY';
			} elseif (preg_match('#^https?:#', $frames)) {
				$frames = "ALLOW-FROM $frames";
			}
			$initialize->addBody('header(?);', array("X-Frame-Options: $frames"));
		}

		foreach ($container->findByTag('run') as $name => $on) {
			if ($on) {
				$initialize->addBody('$this->getService(?);', array($name));
			}
		}
	}



	private function checkTempDir($dir)
	{
		// checks whether directory is writable
		$uniq = uniqid('_', TRUE);
		if (!@mkdir("$dir/$uniq", 0777)) { // @ - is escalated to exception
			throw new InvalidStateException("Unable to write to directory '$dir'. Make this directory writable.");
		}

		// tests subdirectory mode
		$useDirs = @file_put_contents("$dir/$uniq/_", '') !== FALSE; // @ - error is expected
		@unlink("$dir/$uniq/_");
		@rmdir("$dir/$uniq"); // @ - directory may not already exist

		return 'FileStorage::$useDirectories = ' . ($useDirs ? 'TRUE' : 'FALSE') . ";\n";
	}

}
