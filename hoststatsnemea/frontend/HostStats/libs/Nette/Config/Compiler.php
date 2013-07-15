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
 * DI container compiler.
 *
 * @author     David Grudl
 *
 * @property-read ConfigCompilerExtension[] $extensions
 * @property-read DIContainerBuilder $containerBuilder
 * @property-read array $config
 * @package Nette\Config
 */
class ConfigCompiler extends Object
{
	/** @var ConfigCompilerExtension[] */
	private $extensions = array();

	/** @var DIContainerBuilder */
	private $container;

	/** @var array */
	private $config;

	/** @var array reserved section names */
	private static $reserved = array('services' => 1, 'factories' => 1, 'parameters' => 1);



	/**
	 * Add custom configurator extension.
	 * @return ConfigCompiler  provides a fluent interface
	 */
	public function addExtension($name, ConfigCompilerExtension $extension)
	{
		if (isset(self::$reserved[$name])) {
			throw new InvalidArgumentException("Name '$name' is reserved.");
		}
		$this->extensions[$name] = $extension->setCompiler($this, $name);
		return $this;
	}



	/**
	 * @return array
	 */
	public function getExtensions()
	{
		return $this->extensions;
	}



	/**
	 * @return DIContainerBuilder
	 */
	public function getContainerBuilder()
	{
		return $this->container;
	}



	/**
	 * Returns configuration without expanded parameters.
	 * @return array
	 */
	public function getConfig()
	{
		return $this->config;
	}



	/**
	 * @return string
	 */
	public function compile(array $config, $className, $parentName)
	{
		$this->config = $config;
		$this->container = new DIContainerBuilder;
		$this->processParameters();
		$this->processExtensions();
		$this->processServices();
		return $this->generateCode($className, $parentName);
	}



	public function processParameters()
	{
		if (isset($this->config['parameters'])) {
			$this->container->parameters = $this->config['parameters'];
		}
	}



	public function processExtensions()
	{
		for ($i = 0; $slice = array_slice($this->extensions, $i, 1); $i++) {
			reset($slice)->loadConfiguration();
		}

		if ($extra = array_diff_key($this->config, self::$reserved, $this->extensions)) {
			$extra = implode("', '", array_keys($extra));
			throw new InvalidStateException("Found sections '$extra' in configuration, but corresponding extensions are missing.");
		}
	}



	public function processServices()
	{
		$this->parseServices($this->container, $this->config);

		foreach ($this->extensions as $name => $extension) {
			$this->container->addDefinition($name)
				->setClass('DINestedAccessor', array('@container', $name))
				->setAutowired(FALSE);

			if (isset($this->config[$name])) {
				$this->parseServices($this->container, $this->config[$name], $name);
			}
		}

		foreach ($this->container->getDefinitions() as $name => $def) {
			$factory = $name . 'Factory';
			if (!$def->shared && !$def->internal && !$this->container->hasDefinition($factory)) {
				$this->container->addDefinition($factory)
					->setClass('Callback', array('@container', DIContainer::getMethodName($name, FALSE)))
					->setAutowired(FALSE)
					->tags = $def->tags;
			}
		}
	}



	public function generateCode($className, $parentName)
	{
		foreach ($this->extensions as $extension) {
			$extension->beforeCompile();
			$this->container->addDependency(ClassReflection::from($extension)->getFileName());
		}

		$classes[] = $class = $this->container->generateClass($parentName);
		$class->setName($className)
			->addMethod('initialize');

		foreach ($this->extensions as $extension) {
			$extension->afterCompile($class);
		}

		$defs = $this->container->getDefinitions();
		ksort($defs);
		$list = array_keys($defs);
		foreach (array_reverse($defs, TRUE) as $name => $def) {
			if ($def->class === 'DINestedAccessor' && ($found = preg_grep('#^'.$name.'\.#i', $list))) {
				$list = array_diff($list, $found);
				$def->class = $className . '_' . preg_replace('#\W+#', '_', $name);
				$class->documents = preg_replace("#\\S+(?= \\$$name\\z)#", $def->class, $class->documents);
				$classes[] = $accessor = new PhpClassType($def->class);
				foreach ($found as $item) {
					if ($defs[$item]->internal) {
						continue;
					}
					$short = substr($item, strlen($name)  + 1);
					$accessor->addDocument($defs[$item]->shared
						? "@property {$defs[$item]->class} \$$short"
						: "@method {$defs[$item]->class} create" . ucfirst("$short()"));
				}
			}
		}

		return implode("\n\n\n", $classes);
	}



	/********************* tools ****************d*g**/



	/**
	 * Parses section 'services' from configuration file.
	 * @return void
	 */
	public static function parseServices(DIContainerBuilder $container, array $config, $namespace = NULL)
	{
		$services = isset($config['services']) ? $config['services'] : array();
		$factories = isset($config['factories']) ? $config['factories'] : array();
		$all = array_merge($services, $factories);

		uasort($all, create_function('$a, $b', '
			return strcmp(ConfigHelpers::isInheriting($a), ConfigHelpers::isInheriting($b));
		'));

		foreach ($all as $origName => $def) {
			$shared = array_key_exists($origName, $services);
			if ((string) (int) $origName === (string) $origName) {
				$name = (string) (count($container->getDefinitions()) + 1);
			} elseif ($shared && array_key_exists($origName, $factories)) {
				throw new ServiceCreationException("It is not allowed to use services and factories with the same name: '$origName'.");
			} else {
				$name = ($namespace ? $namespace . '.' : '') . strtr($origName, '\\', '_');
			}

			if (($parent = ConfigHelpers::takeParent($def)) && $parent !== $name) {
				$container->removeDefinition($name);
				$definition = $container->addDefinition($name);
				if ($parent !== ConfigHelpers::OVERWRITE) {
					foreach ($container->getDefinition($parent) as $k => $v) {
						$definition->$k = unserialize(serialize($v)); // deep clone
					}
				}
			} elseif ($container->hasDefinition($name)) {
				$definition = $container->getDefinition($name);
				if ($definition->shared !== $shared) {
					throw new ServiceCreationException("It is not allowed to use service and factory with the same name '$name'.");
				}
			} else {
				$definition = $container->addDefinition($name);
			}
			try {
				self::parseService($definition, $def, $shared);
			} catch (Exception $e) {
				throw new ServiceCreationException("Service '$name': " . $e->getMessage(), NULL, $e);
			}
		}
	}



	/**
	 * Parses single service from configuration file.
	 * @return void
	 */
	public static function parseService(DIServiceDefinition $definition, $config, $shared = TRUE)
	{
		if ($config === NULL) {
			return;
		} elseif (!is_array($config)) {
			$config = array('class' => NULL, 'factory' => $config);
		}

		$known = $shared
			? array('class', 'factory', 'arguments', 'setup', 'autowired', 'run', 'tags')
			: array('class', 'factory', 'arguments', 'setup', 'autowired', 'tags', 'internal', 'parameters');

		if ($error = array_diff(array_keys($config), $known)) {
			throw new InvalidStateException("Unknown key '" . implode("', '", $error) . "' in definition of service.");
		}

		$arguments = array();
		if (array_key_exists('arguments', $config)) {
			Validators::assertField($config, 'arguments', 'array');
			$arguments = self::filterArguments($config['arguments']);
			$definition->setArguments($arguments);
		}

		if (array_key_exists('class', $config) || array_key_exists('factory', $config)) {
			$definition->class = NULL;
			$definition->factory = NULL;
		}

		if (array_key_exists('class', $config)) {
			Validators::assertField($config, 'class', 'string|stdClass|null');
			if ($config['class'] instanceof stdClass) {
				$definition->setClass($config['class']->value, self::filterArguments($config['class']->attributes));
			} else {
				$definition->setClass($config['class'], $arguments);
			}
		}

		if (array_key_exists('factory', $config)) {
			Validators::assertField($config, 'factory', 'callable|stdClass|null');
			if ($config['factory'] instanceof stdClass) {
				$definition->setFactory($config['factory']->value, self::filterArguments($config['factory']->attributes));
			} else {
				$definition->setFactory($config['factory'], $arguments);
			}
		}

		if (isset($config['setup'])) {
			if (ConfigHelpers::takeParent($config['setup'])) {
				$definition->setup = array();
			}
			Validators::assertField($config, 'setup', 'list');
			foreach ($config['setup'] as $id => $setup) {
				Validators::assert($setup, 'callable|stdClass', "setup item #$id");
				if ($setup instanceof stdClass) {
					Validators::assert($setup->value, 'callable', "setup item #$id");
					$definition->addSetup($setup->value, self::filterArguments($setup->attributes));
				} else {
					$definition->addSetup($setup);
				}
			}
		}

		$definition->setShared($shared);
		if (isset($config['parameters'])) {
			Validators::assertField($config, 'parameters', 'array');
			$definition->setParameters($config['parameters']);
		}

		if (isset($config['autowired'])) {
			Validators::assertField($config, 'autowired', 'bool');
			$definition->setAutowired($config['autowired']);
		}

		if (isset($config['internal'])) {
			Validators::assertField($config, 'internal', 'bool');
			$definition->setInternal($config['internal']);
		}

		if (isset($config['run'])) {
			$config['tags']['run'] = (bool) $config['run'];
		}

		if (isset($config['tags'])) {
			Validators::assertField($config, 'tags', 'array');
			if (ConfigHelpers::takeParent($config['tags'])) {
				$definition->tags = array();
			}
			foreach ($config['tags'] as $tag => $attrs) {
				if (is_int($tag) && is_string($attrs)) {
					$definition->addTag($attrs);
				} else {
					$definition->addTag($tag, $attrs);
				}
			}
		}
	}



	/**
	 * Removes ... and replaces entities with DIStatement.
	 * @return array
	 */
	public static function filterArguments(array $args)
	{
		foreach ($args as $k => $v) {
			if ($v === '...') {
				unset($args[$k]);
			} elseif ($v instanceof stdClass && isset($v->value, $v->attributes)) {
				$args[$k] = new DIStatement($v->value, self::filterArguments($v->attributes));
			}
		}
		return $args;
	}

}
