<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 *
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 *
 * For the full copyright and license information, please view
 * the file license.txt that was distributed with this source code.
 * @package Nette\Application\Routers
 */



/**
 * The unidirectional router for CLI. (experimental)
 *
 * @author     David Grudl
 *
 * @property-read array $defaults
 * @package Nette\Application\Routers
 */
class CliRouter extends Object implements IRouter
{
	const PRESENTER_KEY = 'action';

	/** @var array */
	private $defaults;



	/**
	 * @param  array   default values
	 */
	public function __construct($defaults = array())
	{
		$this->defaults = $defaults;
	}



	/**
	 * Maps command line arguments to a Request object.
	 * @return PresenterRequest|NULL
	 */
	public function match(IHttpRequest $httpRequest)
	{
		if (empty($_SERVER['argv']) || !is_array($_SERVER['argv'])) {
			return NULL;
		}

		$names = array(self::PRESENTER_KEY);
		$params = $this->defaults;
		$args = $_SERVER['argv'];
		array_shift($args);
		$args[] = '--';

		foreach ($args as $arg) {
			$opt = preg_replace('#/|-+#A', '', $arg);
			if ($opt === $arg) {
				if (isset($flag) || $flag = array_shift($names)) {
					$params[$flag] = $arg;
				} else {
					$params[] = $arg;
				}
				$flag = NULL;
				continue;
			}

			if (isset($flag)) {
				$params[$flag] = TRUE;
				$flag = NULL;
			}

			if ($opt !== '') {
				$pair = explode('=', $opt, 2);
				if (isset($pair[1])) {
					$params[$pair[0]] = $pair[1];
				} else {
					$flag = $pair[0];
				}
			}
		}

		if (!isset($params[self::PRESENTER_KEY])) {
			throw new InvalidStateException('Missing presenter & action in route definition.');
		}
		$presenter = $params[self::PRESENTER_KEY];
		if ($a = strrpos($presenter, ':')) {
			$params[self::PRESENTER_KEY] = substr($presenter, $a + 1);
			$presenter = substr($presenter, 0, $a);
		}

		return new PresenterRequest(
			$presenter,
			'CLI',
			$params
		);
	}



	/**
	 * This router is only unidirectional.
	 * @return NULL
	 */
	public function constructUrl(PresenterRequest $appRequest, Url $refUrl)
	{
		return NULL;
	}



	/**
	 * Returns default values.
	 * @return array
	 */
	public function getDefaults()
	{
		return $this->defaults;
	}

}
