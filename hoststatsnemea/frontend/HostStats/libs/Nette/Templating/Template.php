<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Templating
 */



/**
 * Template.
 *
 * @author     David Grudl
 * @package Nette\Templating
 */
class Template extends Object implements ITemplate
{
	/** @var array of function(Template $sender); Occurs before a template is compiled - implement to customize the filters */
	public $onPrepareFilters = array();

	/** @var string */
	private $source;

	/** @var array */
	private $params = array();

	/** @var array compile-time filters */
	private $filters = array();

	/** @var array run-time helpers */
	private $helpers = array();

	/** @var array */
	private $helperLoaders = array();

	/** @var ICacheStorage */
	private $cacheStorage;



	/**
	 * Sets template source code.
	 * @param  string
	 * @return Template  provides a fluent interface
	 */
	public function setSource($source)
	{
		$this->source = $source;
		return $this;
	}



	/**
	 * Returns template source code.
	 * @return source
	 */
	public function getSource()
	{
		return $this->source;
	}



	/********************* rendering ****************d*g**/



	/**
	 * Renders template to output.
	 * @return void
	 */
	public function render()
	{
		$cache = new Cache($storage = $this->getCacheStorage(), 'Nette.Template');
		$cached = $compiled = $cache->load($this->source);

		if ($compiled === NULL) {
			$compiled = $this->compile();
			$cache->save($this->source, $compiled, array(Cache::CONSTS => 'Framework::REVISION'));
			$cached = $cache->load($this->source);
		}

		if ($cached !== NULL && $storage instanceof PhpFileStorage) {
			LimitedScope::load($cached['file'], $this->getParameters());
		} else {
			LimitedScope::evaluate($compiled, $this->getParameters());
		}
	}



	/**
	 * Renders template to file.
	 * @param  string
	 * @return void
	 */
	public function save($file)
	{
		if (file_put_contents($file, $this->__toString(TRUE)) === FALSE) {
			throw new IOException("Unable to save file '$file'.");
		}
	}



	/**
	 * Renders template to string.
	 * @param  bool  can throw exceptions? (hidden parameter)
	 * @return string
	 */
	public function __toString()
	{
		$args = func_get_args();
		ob_start();
		try {
			$this->render();
			return ob_get_clean();

		} catch (Exception $e) {
			ob_end_clean();
			if ($args && $args[0]) {
				throw $e;
			} else {
				trigger_error("Exception in " . __METHOD__ . "(): {$e->getMessage()} in {$e->getFile()}:{$e->getLine()}", E_USER_ERROR);
			}
		}
	}



	/**
	 * Applies filters on template content.
	 * @return string
	 */
	public function compile()
	{
		if (!$this->filters) {
			$this->onPrepareFilters($this);
		}

		$code = $this->getSource();
		foreach ($this->filters as $filter) {
			$code = self::extractPhp($code, $blocks);
			$code = $filter->invoke($code);
			$code = strtr($code, $blocks); // put PHP code back
		}

		return TemplateHelpers::optimizePhp($code);
	}



	/********************* template filters & helpers ****************d*g**/



	/**
	 * Registers callback as template compile-time filter.
	 * @param  callable
	 * @return Template  provides a fluent interface
	 */
	public function registerFilter($callback)
	{
		$callback = new Callback($callback);
		if (in_array($callback, $this->filters)) {
			throw new InvalidStateException("Filter '$callback' was registered twice.");
		}
		$this->filters[] = $callback;
		return $this;
	}



	/**
	 * Returns all registered compile-time filters.
	 * @return array
	 */
	final public function getFilters()
	{
		return $this->filters;
	}



	/**
	 * Registers callback as template run-time helper.
	 * @param  string
	 * @param  callable
	 * @return Template  provides a fluent interface
	 */
	public function registerHelper($name, $callback)
	{
		$this->helpers[strtolower($name)] = new Callback($callback);
		return $this;
	}



	/**
	 * Registers callback as template run-time helpers loader.
	 * @param  callable
	 * @return Template  provides a fluent interface
	 */
	public function registerHelperLoader($callback)
	{
		$this->helperLoaders[] = new Callback($callback);
		return $this;
	}



	/**
	 * Returns all registered run-time helpers.
	 * @return array
	 */
	final public function getHelpers()
	{
		return $this->helpers;
	}



	/**
	 * Returns all registered template run-time helper loaders.
	 * @return array
	 */
	final public function getHelperLoaders()
	{
		return $this->helperLoaders;
	}



	/**
	 * Call a template run-time helper. Do not call directly.
	 * @param  string  helper name
	 * @param  array   arguments
	 * @return mixed
	 */
	public function __call($name, $args)
	{
		$lname = strtolower($name);
		if (!isset($this->helpers[$lname])) {
			foreach ($this->helperLoaders as $loader) {
				$helper = $loader->invoke($lname);
				if ($helper) {
					$this->registerHelper($lname, $helper);
					return $this->helpers[$lname]->invokeArgs($args);
				}
			}
			return parent::__call($name, $args);
		}

		return $this->helpers[$lname]->invokeArgs($args);
	}



	/**
	 * Sets translate adapter.
	 * @return Template  provides a fluent interface
	 */
	public function setTranslator(ITranslator $translator = NULL)
	{
		$this->registerHelper('translate', $translator === NULL ? NULL : array($translator, 'translate'));
		return $this;
	}



	/********************* template parameters ****************d*g**/



	/**
	 * Adds new template parameter.
	 * @param  string  name
	 * @param  mixed   value
	 * @return Template  provides a fluent interface
	 */
	public function add($name, $value)
	{
		if (array_key_exists($name, $this->params)) {
			throw new InvalidStateException("The variable '$name' already exists.");
		}

		$this->params[$name] = $value;
		return $this;
	}



	/**
	 * Sets all parameters.
	 * @param  array
	 * @return Template  provides a fluent interface
	 */
	public function setParameters(array $params)
	{
		$this->params = $params + $this->params;
		return $this;
	}



	/**
	 * Returns array of all parameters.
	 * @return array
	 */
	public function getParameters()
	{
		$this->params['template'] = $this;
		return $this->params;
	}



	/** @deprecated */
	function setParams(array $params)
	{
		trigger_error(__METHOD__ . '() is deprecated; use setParameters() instead.', E_USER_WARNING);
		return $this->setParameters($params);
	}



	/** @deprecated */
	function getParams()
	{
		trigger_error(__METHOD__ . '() is deprecated; use getParameters() instead.', E_USER_WARNING);
		return $this->getParameters();
	}



	/**
	 * Sets a template parameter. Do not call directly.
	 * @param  string  name
	 * @param  mixed   value
	 * @return void
	 */
	public function __set($name, $value)
	{
		$this->params[$name] = $value;
	}



	/**
	 * Returns a template parameter. Do not call directly.
	 * @param  string  name
	 * @return mixed  value
	 */
	public function &__get($name)
	{
		if (!array_key_exists($name, $this->params)) {
			trigger_error("The variable '$name' does not exist in template.", E_USER_NOTICE);
		}

		return $this->params[$name];
	}



	/**
	 * Determines whether parameter is defined. Do not call directly.
	 * @param  string    name
	 * @return bool
	 */
	public function __isset($name)
	{
		return isset($this->params[$name]);
	}



	/**
	 * Removes a template parameter. Do not call directly.
	 * @param  string    name
	 * @return void
	 */
	public function __unset($name)
	{
		unset($this->params[$name]);
	}



	/********************* caching ****************d*g**/



	/**
	 * Set cache storage.
	 * @return Template  provides a fluent interface
	 */
	public function setCacheStorage(ICacheStorage $storage)
	{
		$this->cacheStorage = $storage;
		return $this;
	}



	/**
	 * @return ICacheStorage
	 */
	public function getCacheStorage()
	{
		if ($this->cacheStorage === NULL) {
			return new DevNullStorage;
		}
		return $this->cacheStorage;
	}



	/********************* tools ****************d*g**/



	/**
	 * Extracts all blocks of PHP code.
	 * @param  string
	 * @param  array
	 * @return string
	 */
	private static function extractPhp($source, & $blocks)
	{
		$res = '';
		$blocks = array();
		$tokens = token_get_all($source);
		foreach ($tokens as $n => $token) {
			if (is_array($token)) {
				if ($token[0] === T_INLINE_HTML) {
					$res .= $token[1];
					continue;

				} elseif ($token[0] === T_CLOSE_TAG) {
					if ($php !== $res) { // not <?xml
						$res .= str_repeat("\n", substr_count($php, "\n"));
					}
					$res .= $token[1];
					continue;

				} elseif ($token[0] === T_OPEN_TAG && $token[1] === '<?' && isset($tokens[$n+1][1]) && $tokens[$n+1][1] === 'xml') {
					$php = & $res;
					$token[1] = '<<?php ?>?';

				} elseif ($token[0] === T_OPEN_TAG || $token[0] === T_OPEN_TAG_WITH_ECHO) {
					$res .= $id = "<?php \x01@php:p" . count($blocks) . "@\x02";
					$php = & $blocks[$id];
				}
				$php .= $token[1];

			} else {
				$php .= $token;
			}
		}
		return $res;
	}

}
